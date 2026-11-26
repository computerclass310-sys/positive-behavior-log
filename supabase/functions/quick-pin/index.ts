// Quick 4-digit sign-in code, checked only on the server.
// actions:
//   has    {email}        -> {has_pin}            is quick sign-in available for this email
//   login  {email, pin}   -> {token_hash}          client exchanges it with auth.verifyOtp({token_hash,type:"email"})
//   status (signed in)    -> {has_pin}            also unlocks the code: an email sign-in proves the address
//   set    (signed in) {pin} -> {ok}
// The code is stored as PBKDF2-SHA256 with a random salt. 5 wrong attempts lock it until the next email sign-in.
import { createClient } from "npm:@supabase/supabase-js@2.45.4";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
  auth: { persistSession: false, autoRefreshToken: false },
});
const MAX_FAILS = 5;
const ITER = 210000;
const enc = new TextEncoder();
const b64 = (b: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(b)));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const weak = (p: string) => /^(\d)\1{3}$/.test(p) || "0123456789".includes(p) || "9876543210".includes(p);

async function hash(pin: string, salt: Uint8Array) {
  const key = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveBits"]);
  return b64(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: new Uint8Array(salt), iterations: ITER }, key, 256));
}
function same(a: string, b: string) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
const json = (o: unknown, status = 200) =>
  new Response(JSON.stringify(o), { status, headers: { ...cors, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "method" }, 405);
  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return json({ error: "bad_request" }, 400); }
  const action = String(body.action || "");

  if (action === "set" || action === "status") {
    const jwt = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
    const { data: u, error } = await admin.auth.getUser(jwt);
    const user = u?.user;
    if (error || !user?.email) return json({ error: "unauthorized" }, 401);
    if (action === "status") {
      const { data } = await admin.from("teacher_pins").select("user_id").eq("user_id", user.id).maybeSingle();
      if (data) await admin.from("teacher_pins").update({ failed: 0, locked: false }).eq("user_id", user.id);
      return json({ has_pin: !!data });
    }
    const pin = String(body.pin || "");
    if (!/^\d{4}$/.test(pin) || weak(pin)) return json({ error: "weak_pin" }, 400);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const { error: e2 } = await admin.from("teacher_pins").upsert({
      user_id: user.id, email: user.email.toLowerCase(), salt: b64(salt), pin_hash: await hash(pin, salt),
      failed: 0, locked: false, updated_at: new Date().toISOString(),
    });
    if (e2) return json({ error: "save_failed" }, 500);
    return json({ ok: true });
  }

  const email = String(body.email || "").trim().toLowerCase();
  if (!/^\S+@\S+\.\S+$/.test(email)) return json({ error: "bad_email" }, 400);

  if (action === "has") {
    const { data } = await admin.from("teacher_pins").select("locked").eq("email", email).maybeSingle();
    return json({ has_pin: !!data && !data.locked });
  }

  if (action === "login") {
    const pin = String(body.pin || "");
    const { data: row } = await admin.from("teacher_pins").select("*").eq("email", email).maybeSingle();
    if (!row) return json({ error: "no_pin" }, 404);
    if (row.locked) return json({ error: "locked" }, 423);
    const ok = /^\d{4}$/.test(pin) && same(await hash(pin, unb64(row.salt)), row.pin_hash);
    if (!ok) {
      const failed = row.failed + 1;
      await admin.from("teacher_pins").update({ failed, locked: failed >= MAX_FAILS }).eq("user_id", row.user_id);
      return json({ error: failed >= MAX_FAILS ? "locked" : "wrong_pin", remaining: Math.max(0, MAX_FAILS - failed) }, 401);
    }
    await admin.from("teacher_pins").update({ failed: 0 }).eq("user_id", row.user_id);
    const { data: link, error } = await admin.auth.admin.generateLink({ type: "magiclink", email: row.email });
    const token_hash = link?.properties?.hashed_token;
    if (error || !token_hash) return json({ error: "link_failed" }, 500);
    return json({ token_hash });
  }

  return json({ error: "bad_action" }, 400);
});
