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
