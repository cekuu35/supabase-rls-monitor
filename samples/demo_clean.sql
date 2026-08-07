create table notes (id uuid primary key, user_id uuid, text text);
alter table notes enable row level security;
create policy "own select" on notes for select to authenticated using (auth.uid() = user_id);
create policy "own insert" on notes for insert to authenticated with check (auth.uid() = user_id);
create policy "own update" on notes for update to authenticated using (auth.uid() = user_id);
