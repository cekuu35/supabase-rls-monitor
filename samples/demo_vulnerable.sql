-- Demo schema exercising the real Supabase RLS failure modes.
-- Generic / anonymized - not any specific project's code.
-- Used to demonstrate what RLS Monitor catches (and what it correctly ignores).

-- 1) Policies defined, RLS NEVER enabled -> policies inert, table wide open.
create table transactions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users,
  amount numeric,
  created_at timestamptz default now()
);
create policy "own txns select" on transactions
  for select using (auth.uid() = user_id);
create policy "own txns insert" on transactions
  for insert with check (auth.uid() = user_id);
-- (no ENABLE ROW LEVEL SECURITY on transactions)

-- 2) Anyone can forge a vote: WITH CHECK (true), no TO clause.
create table product_votes (
  user_id uuid,
  product_id uuid,
  primary key (user_id, product_id)
);
alter table product_votes enable row level security;
create policy "anyone can vote" on product_votes
  for insert with check (true);

-- 3) Anyone can delete the question bank: DELETE USING (true), no TO.
create table questions (
  id uuid primary key default gen_random_uuid(),
  body text,
  answer text
);
alter table questions enable row level security;
create policy "delete questions" on questions
  for delete using (true);

-- 4) "Service role full access" applied to EVERY role (no TO) and OR-combined
--    with the user-scoped policy, cancelling it.
create table resumes (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid references auth.users,
  contact_email text,
  content jsonb
);
alter table resumes enable row level security;
create policy "service role full access" on resumes
  for all using (true);
create policy "owner can manage" on resumes
  for all to authenticated using (auth.uid() = owner_id);

-- 5) Public read of a sensitive table.
create table user_profiles (
  id uuid primary key,
  email text,
  phone text
);
alter table user_profiles enable row level security;
create policy "public profiles" on user_profiles
  for select using (true);

-- 6) SECURITY DEFINER function without a pinned search_path.
create function is_admin() returns boolean
language sql security definer
as $$ select exists(select 1 from admins where id = auth.uid()) $$;

-- 7) CORRECT - must NOT be flagged. UPDATE with USING, no WITH CHECK:
--    Postgres reuses USING for the new row, so ownership holds.
create table notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users,
  text text
);
alter table notes enable row level security;
create policy "own notes update" on notes
  for update to authenticated using (auth.uid() = user_id);

-- 8) RLS on, no policies -> locked down (INFO, not a leak).
create table audit_log (
  id bigint generated always as identity primary key,
  event text,
  at timestamptz default now()
);
alter table audit_log enable row level security;
