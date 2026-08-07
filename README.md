# RLS Monitor

**Catch the Supabase Row Level Security holes that leak user data — before your next deploy.**

Your Supabase `anon` key is public by design (it ships in your frontend). If one
RLS policy is wrong, anyone with `curl` can read or overwrite your tables. This
is the #1 cause of data leaks in apps built with Lovable, Bolt, Cursor, v0 and
Replit — **83% of Supabase exposures are RLS misconfiguration**, and a single
missing-RLS pattern hit 170+ production apps (CVE-2025-48757).

RLS Monitor reads your schema the way an attacker probes it and reports every
hole, ranked by severity, each with the exact SQL to fix it.

## What it catches

| Rule | Severity | What it means |
|------|----------|---------------|
| `rls-off-with-policies` | CRITICAL | Policies exist but `ENABLE ROW LEVEL SECURITY` is missing — policies are inert, table wide open |
| `anon-write-true` | CRITICAL | An INSERT/UPDATE/DELETE/ALL policy is `true` with no `TO` clause — anyone can forge, tamper, or delete rows |
| `next-public-service-role` | CRITICAL | `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY` inlined into the browser bundle — full DB access for every visitor |
| `service-role-in-client` | HIGH | A `"use client"` component references the service_role key |
| `anon-read-true` | HIGH/MED | `USING (true)` public read (HIGH if the table looks sensitive) |
| `allrole-true` | HIGH | `FOR ALL USING (true)` with no `TO` — cancels adjacent user-scoped policies |
| `definer-search-path` | MEDIUM | `SECURITY DEFINER` function without a pinned `search_path` |
| `rls-on-no-policy` | INFO | RLS on, zero policies — locked down (or a silent "no rows" bug) |

## What it deliberately does NOT flag

Credibility depends on zero false positives. Two patterns that *look* like bugs
but are not:

- An UPDATE policy with `USING` but no `WITH CHECK` — Postgres reuses `USING`
  for the new row, so ownership still holds.
- The mere presence of `WITH CHECK` on an INSERT policy — the language requires
  it; it is not evidence of care.

Run `python rls_monitor.py --explain` for the full reasoning.

## Quickstart

```bash
# 1. Export your schema (read-only, no data leaves your machine)
supabase db dump --schema-only > schema.sql

# 2. Scan
python rls_monitor.py --schema schema.sql

# 3. (optional) Also scan client source for a leaked service_role key
python rls_monitor.py --schema schema.sql --src ./app --out report.md
```

No dependencies beyond Python 3.8+. Nothing is uploaded anywhere.

## Run it on every deploy (the recurring value)

Drop this in `.github/workflows/rls.yml` — the build fails if a CRITICAL hole
lands, so a bad policy never reaches production:

```yaml
name: RLS check
on: [push, pull_request]
jobs:
  rls:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: supabase db dump --schema-only > schema.sql
        env: { SUPABASE_ACCESS_TOKEN: ${{ secrets.SUPABASE_ACCESS_TOKEN }} }
      - run: python rls_monitor.py --schema schema.sql --fail-on CRITICAL
```

`--fail-on` accepts `CRITICAL`, `HIGH`, `MEDIUM`, or `none`.

## Managed service (done for you)

Don't want to wire it up yourself? I run it for you and review every finding by
hand — a scanner flags patterns; a human confirms exploitability and writes the
fix.

| Package | Price | What you get |
|---------|-------|--------------|
| **Audit** | **$99** | Full scan of your schema + a plain-English, severity-ranked report with fix SQL |
| **Audit + Fix** | **$499** | I write, apply and test every fix with you — verified secure at handoff |
| **Audit + Fix + Guard** | **$699** | Everything above + 30 days of re-scans after each deploy |
| **Guard (monthly)** | **$199/mo** | Ongoing: re-scan on every deploy, policy tests, priority support |

My RLS analysis has been confirmed by the Supabase security team. I audit real
production leaks, not lab examples.

See `samples/sample_report.md` for what a report looks like.
