-- سجل رصد السلوك الإيجابي: قاعدة بيانات مشتركة لكل معلمات المدرسة
-- شغّلي هذا الملف مرة واحدة في Supabase: SQL Editor > New query > Run

-- المعلمات (ملف لكل حساب)
create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  full_name text not null check (char_length(full_name) between 2 and 120),
  max_points int not null default 20 check (max_points between 5 and 40),
  export_format text not null default 'excel' check (export_format in ('pdf', 'excel', 'word')),
  created_at timestamptz not null default now()
);

-- الصفوف
create table public.classes (
  id bigint generated always as identity primary key,
  name text not null unique check (char_length(name) between 1 and 80),
  created_by uuid default auth.uid() references public.profiles (id) on delete set null,
  created_at timestamptz not null default now()
);

-- الطالبات
create table public.students (
  id bigint generated always as identity primary key,
  full_name text not null check (char_length(full_name) between 3 and 160),
  class_id bigint not null references public.classes (id) on delete restrict,
  created_by uuid not null default auth.uid() references public.profiles (id) on delete restrict,
  created_at timestamptz not null default now()
);
create index students_class_id_idx on public.students (class_id);
create index students_created_by_idx on public.students (created_by);

-- سجلات السلوك الإيجابي
create table public.behavior_records (
  id bigint generated always as identity primary key,
  student_id bigint not null references public.students (id) on delete restrict,
  teacher_id uuid not null default auth.uid() references public.profiles (id) on delete restrict,
  category text check (category is null or char_length(category) between 1 and 60),
  description text not null check (char_length(description) between 1 and 500),
  points smallint not null check (points in (1, 2, 3, 5)),
  signature text check (signature is null or (signature like 'data:image/png;base64,%' and char_length(signature) < 300000)),
  created_at timestamptz not null default now()
);
create index behavior_records_student_id_idx on public.behavior_records (student_id);
create index behavior_records_teacher_id_idx on public.behavior_records (teacher_id);

-- مجموع درجات كل طالبة (يحترم صلاحيات من يستعلم)
create view public.student_scores with (security_invoker = true) as
  select student_id, sum(points)::int as total
  from public.behavior_records
  group by student_id;

-- مجموع درجات كل طالبة عند كل معلمة (تبويب المتابعة يعرض رصد المعلمة الداخلة فقط)
create view public.student_teacher_scores with (security_invoker = true) as
  select student_id, teacher_id, sum(points)::int as total
  from public.behavior_records
  group by student_id, teacher_id;

-- الحماية: لا وصول لغير المسجلات، وكل معلمة تعدّل ما أضافته فقط
alter table public.profiles enable row level security;
alter table public.classes enable row level security;
alter table public.students enable row level security;
alter table public.behavior_records enable row level security;

revoke all on public.profiles, public.classes, public.students, public.behavior_records, public.student_scores from anon;
revoke all on public.student_teacher_scores from anon, authenticated;
grant select on public.student_teacher_scores to authenticated;
revoke all on public.profiles, public.classes, public.students, public.behavior_records, public.student_scores from authenticated;
grant select, insert on public.profiles to authenticated;
grant update (full_name, max_points, export_format) on public.profiles to authenticated;
grant select, insert on public.classes to authenticated;
grant select, insert, delete on public.students to authenticated;
grant select, insert, delete on public.behavior_records to authenticated;
grant select on public.student_scores to authenticated;

create policy "teachers read profiles" on public.profiles for select to authenticated using (true);
create policy "teacher creates own profile" on public.profiles for insert to authenticated
  with check ((select auth.uid()) = id);
create policy "teacher updates own profile" on public.profiles for update to authenticated
  using ((select auth.uid()) = id) with check ((select auth.uid()) = id);

create policy "teachers read classes" on public.classes for select to authenticated using (true);
create policy "teacher adds class" on public.classes for insert to authenticated
  with check ((select auth.uid()) = created_by);

create policy "teachers read students" on public.students for select to authenticated using (true);
create policy "teacher adds student" on public.students for insert to authenticated
  with check ((select auth.uid()) = created_by);
create policy "teacher deletes own student" on public.students for delete to authenticated
  using ((select auth.uid()) = created_by);

create policy "teachers read records" on public.behavior_records for select to authenticated using (true);
create policy "teacher adds own record" on public.behavior_records for insert to authenticated
  with check ((select auth.uid()) = teacher_id);
create policy "teacher deletes own record" on public.behavior_records for delete to authenticated
  using ((select auth.uid()) = teacher_id);

-- صفوف أولية (يمكن تعديلها)
insert into public.classes (name) values
  ('ثاني 1'), ('ثاني 2'), ('ثاني 3'), ('ثاني 4'), ('ثاني 5'), ('ثاني 6'),
  ('ثالث 1'), ('ثالث 2'), ('ثالث 3'), ('ثالث 4'), ('ثالث 5'), ('ثالث 6');

-- ===== إضافات مطابقة تصميم Stitch =====
-- نوع السلوك اختياري (أُزيلت أزراره من الواجهة)
alter table public.behavior_records alter column category drop not null;

-- بيانات المعلمة: المادة واسم المدرسة
alter table public.profiles
  add column subject text check (subject is null or char_length(subject) <= 60),
  add column school_name text check (school_name is null or char_length(school_name) <= 120);
grant update (full_name, max_points, export_format, subject, school_name) on public.profiles to authenticated;

-- رقم هوية الطالبة (اختياري) وتعديل بيانات الطالبة ممن أضافتها فقط
alter table public.students
  add column national_id text check (national_id is null or national_id ~ '^[0-9]{10}$');
grant update (full_name, class_id, national_id) on public.students to authenticated;
create policy "teacher updates own student" on public.students for update to authenticated
  using ((select auth.uid()) = created_by) with check ((select auth.uid()) = created_by);

-- مرفق شواهد الإنجاز لكل رصد (ملفات في Storage)
alter table public.behavior_records
  add column attachment_path text check (attachment_path is null or char_length(attachment_path) <= 300);
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('evidence', 'evidence', false, 10485760, array['application/pdf', 'image/png', 'image/jpeg'])
on conflict (id) do nothing;
create policy "teachers upload own evidence" on storage.objects for insert to authenticated
  with check (bucket_id = 'evidence' and (storage.foldername(name))[1] = (select auth.uid())::text);
create policy "teachers read evidence" on storage.objects for select to authenticated
  using (bucket_id = 'evidence');

-- الصفوف المسندة لكل معلمة، وأحدها هو الصف الرئيسي (الفعّال للعرض السريع)
create table public.teacher_classes (
  teacher_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  class_id bigint not null references public.classes (id) on delete cascade,
  is_primary boolean not null default false,
  created_at timestamptz not null default now(),
  primary key (teacher_id, class_id)
);
create unique index teacher_classes_one_primary on public.teacher_classes (teacher_id) where is_primary;
create index teacher_classes_class_id_idx on public.teacher_classes (class_id);
alter table public.teacher_classes enable row level security;
revoke all on public.teacher_classes from anon, authenticated;
grant select, insert, delete on public.teacher_classes to authenticated;
grant update (class_id, is_primary) on public.teacher_classes to authenticated;
create policy "teacher reads own assignments" on public.teacher_classes for select to authenticated
  using ((select auth.uid()) = teacher_id);
create policy "teacher adds own assignment" on public.teacher_classes for insert to authenticated
  with check ((select auth.uid()) = teacher_id);
create policy "teacher updates own assignment" on public.teacher_classes for update to authenticated
  using ((select auth.uid()) = teacher_id) with check ((select auth.uid()) = teacher_id);
create policy "teacher removes own assignment" on public.teacher_classes for delete to authenticated
  using ((select auth.uid()) = teacher_id);

-- أُزيل رقم هوية الطالبة نهائياً (لا يُطلب ولا يُخزَّن)
alter table public.students drop column national_id;

-- الدرجات حسب النموذج الرسمي: 2 أو 4 أو 6 (القيم القديمة مسموحة مؤقتاً)
alter table public.behavior_records drop constraint behavior_records_points_check;
alter table public.behavior_records add constraint behavior_records_points_check
  check (points in (1, 2, 3, 4, 5, 6));

-- الرمز السريع لكل معلمة: مشفّر (PBKDF2)، لا يصل إليه المتصفح؛ تقرؤه وظيفة الخادم quick-pin فقط
-- (supabase/functions/quick-pin/index.ts، منشورة مع verify_jwt=false لأنها تتحقق بنفسها)
create table public.teacher_pins (
  user_id uuid primary key references auth.users (id) on delete cascade,
  email text not null unique check (email = lower(email)),
  salt text not null,
  pin_hash text not null,
  failed smallint not null default 0,
  locked boolean not null default false,
  updated_at timestamptz not null default now()
);
alter table public.teacher_pins enable row level security;
revoke all on public.teacher_pins from anon, authenticated;

-- عند حذف حساب معلمة تبقى الطالبات اللاتي أضافتهن (بلا مالكة) بدل منع الحذف
alter table public.students alter column created_by drop not null;
alter table public.students drop constraint students_created_by_fkey;
alter table public.students add constraint students_created_by_fkey
  foreign key (created_by) references public.profiles (id) on delete set null;

-- ===== نسخة احتياطية يومية (آخر 30 يوماً) داخل مخطط backups غير المكشوف =====
create extension if not exists pg_cron;
create schema if not exists backups;
revoke all on schema backups from public, anon, authenticated;
create table backups.snapshots (
  id bigint generated always as identity primary key,
  taken_at timestamptz not null default now(),
  data jsonb not null
);
revoke all on backups.snapshots from public, anon, authenticated;
-- التواقيع (صور) لا تُنسخ لتوفير المساحة؛ رموز الدخول لا تُنسخ أبداً
create or replace function backups.take_snapshot() returns bigint
language plpgsql set search_path = '' as $$
declare new_id bigint;
begin
  insert into backups.snapshots (data)
  select jsonb_build_object(
    'teachers', coalesce((select jsonb_agg(jsonb_build_object('id', p.id, 'email', u.email, 'full_name', p.full_name, 'subject', p.subject,
                  'max_points', p.max_points, 'created_at', p.created_at) order by p.full_name)
                from public.profiles p left join auth.users u on u.id = p.id), '[]'),
    'classes', coalesce((select jsonb_agg(to_jsonb(c) order by c.id) from public.classes c), '[]'),
    'teacher_classes', coalesce((select jsonb_agg(to_jsonb(t)) from public.teacher_classes t), '[]'),
    'students', coalesce((select jsonb_agg(to_jsonb(s) order by s.id) from public.students s), '[]'),
    'behavior_records', coalesce((select jsonb_agg(to_jsonb(r) - 'signature' order by r.id) from public.behavior_records r), '[]')
  ) returning id into new_id;
  delete from backups.snapshots where taken_at < now() - interval '30 days';
  return new_id;
end $$;
revoke all on function backups.take_snapshot() from public, anon, authenticated;
-- كل يوم الساعة 11 مساءً بتوقيت الرياض (20:00 UTC)
select cron.schedule('daily-backup', '0 20 * * *', $$select backups.take_snapshot()$$);

-- Trusted devices for quick sign-in: a new device needs the email code once, then the existing quick code.
-- Only the quick-pin Edge Function (service role) reads and writes this table.
create table public.teacher_devices (
  user_id uuid not null references auth.users (id) on delete cascade,
  device_hash text not null,
  created_at timestamptz not null default now(),
  last_used timestamptz not null default now(),
  primary key (user_id, device_hash)
);
alter table public.teacher_devices enable row level security;
revoke all on public.teacher_devices from anon, authenticated;

-- الصف الواحد يُسند لمعلمتين على الأكثر
create or replace function public.enforce_class_teacher_limit()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if tg_op = 'UPDATE' and new.class_id = old.class_id then return new; end if;
  perform 1 from public.classes where id = new.class_id for update;
  if (select count(*) from public.teacher_classes
      where class_id = new.class_id and teacher_id <> new.teacher_id) >= 2 then
    raise exception 'class_full' using errcode = 'P0001', hint = 'A class can be assigned to two teachers at most';
  end if;
  return new;
end $$;
revoke all on function public.enforce_class_teacher_limit() from public, anon, authenticated;
create trigger teacher_classes_max_two
  before insert or update of class_id on public.teacher_classes
  for each row execute function public.enforce_class_teacher_limit();
-- عدد المعلمات لكل صف (أعداد فقط) ليعرض التطبيق الصفوف المكتملة
create or replace function public.class_load()
returns table (class_id bigint, teachers int) language sql stable security definer set search_path = '' as $$
  select class_id, count(*)::int from public.teacher_classes group by class_id
$$;
revoke all on function public.class_load() from public, anon;
grant execute on function public.class_load() to authenticated;

-- البريد المخوّل بمتابعة جميع الصفوف وطباعة تقريرها (يُدار من لوحة Supabase فقط)
create table public.supervisors (
  email text primary key check (email = lower(email)),
  created_at timestamptz not null default now()
);
alter table public.supervisors enable row level security;
revoke all on public.supervisors from anon, authenticated;
-- insert into public.supervisors (email) values ('...');
create or replace function public.is_supervisor()
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.supervisors where email = lower(coalesce((select auth.jwt()) ->> 'email', '')))
$$;
revoke all on function public.is_supervisor() from public, anon;
grant execute on function public.is_supervisor() to authenticated;
-- أسماء المعلمات المسند لهن كل صف: للبريد المخوّل فقط (فارغة لغيره)
create or replace function public.class_teachers()
returns table (class_id bigint, full_name text) language sql stable security definer set search_path = '' as $$
  select tc.class_id, p.full_name
  from public.teacher_classes tc join public.profiles p on p.id = tc.teacher_id
  where public.is_supervisor()
  order by tc.class_id, tc.created_at
$$;
revoke all on function public.class_teachers() from public, anon;
grant execute on function public.class_teachers() to authenticated;

-- اسم المعلمة يُربط ببريد واحد فقط (الأسماء تُقارن بعد توحيد المسافات والهمزات والتاء المربوطة والألف المقصورة)
create or replace function public.norm_name(t text)
returns text language sql immutable set search_path = '' as $$
  select translate(
           regexp_replace(regexp_replace(btrim(coalesce(t, '')), '[ً-ْـ]', '', 'g'), '\s+', ' ', 'g'),
           'أإآٱةى', 'ااااهي')
$$;
create or replace function public.enforce_unique_teacher_name()
returns trigger language plpgsql security definer set search_path = '' as $$
declare n text := public.norm_name(new.full_name);
begin
  if tg_op = 'UPDATE' and public.norm_name(old.full_name) = n then return new; end if;
  perform pg_advisory_xact_lock(hashtext('teacher_name:' || n));
  if exists (select 1 from public.profiles where id <> new.id and public.norm_name(full_name) = n) then
    raise exception 'name_taken' using errcode = 'P0001', hint = 'This teacher name is already linked to another email';
  end if;
  return new;
end $$;
revoke all on function public.enforce_unique_teacher_name() from public, anon, authenticated;
create trigger profiles_unique_name
  before insert or update of full_name on public.profiles
  for each row execute function public.enforce_unique_teacher_name();
