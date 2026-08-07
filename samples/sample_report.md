# RLS Monitor report

- Schema: `samples/demo_vulnerable.sql`
- Source: `samples/demo_src`
- Findings: 🔴 5 critical  🟠 2 high  🟡 1 medium  🔵 0 low  ⚪ 1 info

> **7 finding(s) can leak or corrupt data right now.** Fix these before your next deploy.

## 1. 🔴 CRITICAL - lib\supabase.ts uses NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY
*rule: `next-public-service-role` | object: `lib\supabase.ts`*

Any env var prefixed NEXT_PUBLIC_ is inlined into the browser bundle at build time. The service_role key bypasses RLS entirely - shipping it to the browser hands every visitor full database access.

**Fix**
```sql
1) Rename to SUPABASE_SERVICE_ROLE_KEY (no NEXT_PUBLIC_).
2) Use it only in server code (route handlers / server actions); import 'server-only'.
3) ROTATE the key in the dashboard - the old one is in every deployed bundle.
   Verify: npm run build && grep -ro "eyJ[A-Za-z0-9_-]\{20,\}" .next/static
```

## 2. 🔴 CRITICAL - `anyone can vote` lets anyone insert rows on `product_votes`
*rule: `anon-write-true` | object: `product_votes`*

The INSERT policy evaluates to TRUE with no `TO` clause restricting it, so the public anon key can write arbitrary rows (forge ownership, delete records, tamper with data). The absence of a UI button is not a control - the anon key is already in your frontend.

**Fix**
```sql
DROP POLICY "anyone can vote" ON product_votes;
CREATE POLICY "anyone can vote" ON product_votes
  FOR INSERT TO authenticated
  WITH CHECK (auth.uid() = user_id);  -- scope to the owner
```

## 3. 🔴 CRITICAL - `delete questions` lets anyone delete rows on `questions`
*rule: `anon-write-true` | object: `questions`*

The DELETE policy evaluates to TRUE with no `TO` clause restricting it, so the public anon key can write arbitrary rows (forge ownership, delete records, tamper with data). The absence of a UI button is not a control - the anon key is already in your frontend.

**Fix**
```sql
DROP POLICY "delete questions" ON questions;
CREATE POLICY "delete questions" ON questions
  FOR DELETE TO authenticated
  USING (auth.uid() = user_id);  -- scope to the owner
```

## 4. 🔴 CRITICAL - `service role full access` lets anyone read & write rows on `resumes`
*rule: `anon-write-true` | object: `resumes`*

The ALL policy evaluates to TRUE with no `TO` clause restricting it, so the public anon key can write arbitrary rows (forge ownership, delete records, tamper with data). The absence of a UI button is not a control - the anon key is already in your frontend.

**Fix**
```sql
DROP POLICY "service role full access" ON resumes;
CREATE POLICY "service role full access" ON resumes
  FOR ALL TO authenticated
  USING (auth.uid() = user_id);  -- scope to the owner
```

## 5. 🔴 CRITICAL - `transactions` has 2 policies but RLS is not enabled
*rule: `rls-off-with-policies` | object: `transactions`*

Policies exist on this table but no `ENABLE ROW LEVEL SECURITY` was found for it, so Postgres does not enforce them. The anon key can read and write every row.

**Fix**
```sql
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
```

## 6. 🟠 HIGH - components\BuyCredits.tsx references the service_role key in a client component
*rule: `service-role-in-client` | object: `components\BuyCredits.tsx`*

This file is a client component ('use client') yet references the service_role key. If it instantiates or imports that client, the key reaches the browser. Verify the import chain.

**Fix**
```sql
Move service_role usage to server-only modules; keep the browser client on the anon key + RLS. Rotate if it ever shipped.
```

## 7. 🟠 HIGH - `public profiles` exposes every row of `user_profiles` to the public
*rule: `anon-read-true` | object: `user_profiles`*

`USING (true)` with no `TO` clause means an unauthenticated request returns the whole table. This table name suggests sensitive data.

**Fix**
```sql
DROP POLICY "public profiles" ON user_profiles;
CREATE POLICY "public profiles" ON user_profiles
  FOR SELECT TO authenticated
  USING (auth.uid() = user_id);  -- or a public subset only
```

## 8. 🟡 MEDIUM - `is_admin()` is SECURITY DEFINER without a pinned search_path
*rule: `definer-search-path` | object: `is_admin`*

A SECURITY DEFINER function without `SET search_path` can be hijacked via a shadowing object in a schema the caller controls, running attacker code with the owner's rights.

**Fix**
```sql
ALTER FUNCTION is_admin SET search_path = '';
```

## 9. ⚪ INFO - `audit_log` has RLS enabled but no policies
*rule: `rls-on-no-policy` | object: `audit_log`*

This table denies all access except the service_role. Safe, but confirm the app doesn't need anon/authenticated reads here (a silent 'no rows' bug looks like this).

**Fix**
```sql
-- Add a policy if legitimate access is expected, else leave locked.
```

---
*Not flagged by design: an UPDATE policy with `USING` but no `WITH CHECK` (Postgres reuses USING for the new row), and the mere presence of `WITH CHECK` on INSERT (the language requires it). Run with `--explain` for details.*