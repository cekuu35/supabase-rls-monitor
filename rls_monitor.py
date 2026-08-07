#!/usr/bin/env python3
"""
RLS Monitor - Supabase Row Level Security auditor.

Feed it a Postgres/Supabase schema dump and it reports the authorization
holes that leak user data in production, ranked by severity, each with the
exact SQL to fix it.

    supabase db dump --schema-only > schema.sql
    python rls_monitor.py --schema schema.sql

Optionally scan client source for a leaked service_role key:

    python rls_monitor.py --schema schema.sql --src ./app

Detection is deliberately conservative. Two patterns that LOOK like bugs but
are not (and would burn credibility if reported) are NOT flagged:
  * An UPDATE policy with USING but no WITH CHECK -> Postgres reuses USING for
    the new row, so ownership is still enforced.
  * The mere presence of WITH CHECK on an INSERT policy -> the language
    requires it; it is not evidence of care.
See --explain for the reasoning.
"""
import argparse
import json
import os
import re
import sys

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_ICON = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1",
            "LOW": "\U0001F535", "INFO": "⚪"}

# Table-name hint: weak signal that a table MIGHT hold sensitive data.
SENSITIVE = re.compile(
    r"(user|account|payment|invoice|patient|medical|health|message|email|"
    r"token|secret|api_key|credential|order|customer|profile|subscription|"
    r"billing|address|ssn|passport|dob|salary|bank)", re.I)

# Column-name hint: strong signal a public-read table actually leaks PII/secrets.
# Deliberately narrower than SENSITIVE - "username"/"display_name" are usually
# meant to be public, so they are not here.
SENSITIVE_COL = re.compile(
    r"(email|phone|mobile|ssn|passport|national_id|dob|birth|address|"
    r"salary|iban|bank|card|payment|token|secret|api_?key|password|"
    r"hash|credential|stripe|latitude|longitude|geo|location)", re.I)

WRITE_CMDS = {"ALL", "INSERT", "UPDATE", "DELETE"}


def strip_comments(sql):
    """Remove -- line comments and /* */ block comments (naive; fine for dumps)."""
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.S)
    sql = re.sub(r"--[^\n]*", " ", sql)
    return sql


def split_statements(sql):
    """Split on top-level semicolons, respecting $$-quoted function bodies and
    single-quoted strings so a ';' inside a function body doesn't split it."""
    stmts, buf = [], []
    i, n = 0, len(sql)
    dollar_tag = None
    in_squote = False
    while i < n:
        c = sql[i]
        if dollar_tag:
            if sql.startswith(dollar_tag, i):
                buf.append(dollar_tag)
                i += len(dollar_tag)
                dollar_tag = None
                continue
            buf.append(c); i += 1; continue
        if in_squote:
            buf.append(c)
            if c == "'":
                in_squote = False
            i += 1; continue
        if c == "'":
            in_squote = True; buf.append(c); i += 1; continue
        m = re.match(r"\$[A-Za-z0-9_]*\$", sql[i:])
        if m:
            dollar_tag = m.group(0)
            buf.append(dollar_tag); i += len(dollar_tag); continue
        if c == ";":
            stmts.append("".join(buf)); buf = []; i += 1; continue
        buf.append(c); i += 1
    if "".join(buf).strip():
        stmts.append("".join(buf))
    return stmts


# Schemas Supabase manages and pre-enables RLS on. Policies here are normal;
# a missing ENABLE in a migration is not a finding (Supabase already enabled it).
MANAGED_SCHEMAS = {"storage", "auth", "realtime", "vault", "graphql",
                   "graphql_public", "extensions", "supabase_functions", "cron"}


def norm_table(raw):
    """Normalize a possibly schema-qualified, quoted table name to (full, bare).
    Unqualified names default to the public schema so `sessions` and
    `public.sessions` resolve to the same table."""
    raw = raw.strip()
    parts = [p.strip().strip('"') for p in raw.split(".")]
    bare = parts[-1].lower()
    if len(parts) == 1:
        full = "public." + bare
    else:
        full = ".".join(p.lower() for p in parts)
    return full, bare


def extract_paren(s, kw_match):
    """Given a regex match ending just before '(', return the balanced group."""
    idx = kw_match.end()
    while idx < len(s) and s[idx] != "(":
        if not s[idx].isspace():
            return None
        idx += 1
    if idx >= len(s):
        return None
    depth, start = 0, idx
    in_q = False
    for j in range(idx, len(s)):
        ch = s[j]
        if in_q:
            if ch == "'":
                in_q = False
            continue
        if ch == "'":
            in_q = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return s[start + 1:j].strip()
    return None


def is_trivially_true(expr):
    if expr is None:
        return False
    e = expr.strip().lower()
    while e.startswith("(") and e.endswith(")"):
        e = e[1:-1].strip()
    return e == "true"


def parse_schema(sql):
    sql = strip_comments(sql)
    rls_enabled, rls_disabled = set(), set()
    # Ordered by (table_full, policy_name) so a later DROP/CREATE supersedes an
    # earlier one - lets the tool read concatenated migrations, not just a dump.
    policy_map = {}
    functions = []
    table_cols = {}

    for stmt in split_statements(sql):
        s = stmt.strip()
        if not s:
            continue
        low = s.lower()

        cm = re.match(r"create\s+table\s+(?:if\s+not\s+exists\s+)?([\w.\"]+)", s, re.I)
        if cm:
            full, _ = norm_table(cm.group(1))
            body = extract_paren(s, cm)
            cols = set()
            if body:
                for part in re.split(r",(?![^()]*\))", body):
                    tok = part.strip().split()
                    if tok and tok[0].upper() not in (
                            "CONSTRAINT", "PRIMARY", "FOREIGN", "UNIQUE",
                            "CHECK", "EXCLUDE", "LIKE"):
                        cols.add(tok[0].strip('"').lower())
            table_cols.setdefault(full, set()).update(cols)
            # fall through: a CREATE TABLE won't match the branches below

        m = re.search(r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?"
                      r"([\w.\"]+)\s+enable\s+row\s+level\s+security", low)
        if m:
            rls_enabled.add(norm_table(m.group(1))[0]); continue
        m = re.search(r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?"
                      r"([\w.\"]+)\s+disable\s+row\s+level\s+security", low)
        if m:
            rls_disabled.add(norm_table(m.group(1))[0]); continue

        m = re.match(r"drop\s+policy\s+(?:if\s+exists\s+)?(\"[^\"]+\"|[\w]+)"
                     r"\s+on\s+([\w.\"]+)", s, re.I)
        if m:
            name = m.group(1).strip('"')
            full, _ = norm_table(m.group(2))
            policy_map.pop((full, name), None)
            continue

        m = re.match(r"create\s+policy\s+(?:if\s+not\s+exists\s+)?"
                     r"(\"[^\"]+\"|[\w]+)\s+on\s+([\w.\"]+)", s, re.I | re.S)
        if m:
            name = m.group(1).strip('"')
            full, bare = norm_table(m.group(2))
            cmd_m = re.search(r"\bfor\s+(all|select|insert|update|delete)\b", s, re.I)
            cmd = (cmd_m.group(1).upper() if cmd_m else "ALL")
            roles = None
            rm = re.search(r"\bto\s+([a-z0-9_\", ]+?)(?=\s+using\b|\s+with\s+check\b|$)",
                           s, re.I | re.S)
            if rm:
                roles = [r.strip().strip('"').lower()
                         for r in rm.group(1).split(",") if r.strip()]
            using = None
            um = re.search(r"\busing\b", s, re.I)
            if um:
                using = extract_paren(s, um)
            check = None
            cm = re.search(r"\bwith\s+check\b", s, re.I)
            if cm:
                check = extract_paren(s, cm)
            policy_map[(full, name)] = dict(
                name=name, table_full=full, table_bare=bare,
                cmd=cmd, roles=roles, using=using, check=check)
            continue

        if re.search(r"create\s+(or\s+replace\s+)?function", low) and \
           re.search(r"security\s+definer", low):
            fn = re.search(r"function\s+([\w.\"]+)\s*\(", s, re.I)
            fname = fn.group(1).strip('"') if fn else "<function>"
            has_sp = bool(re.search(r"set\s+search_path", low))
            functions.append(dict(name=fname, has_search_path=has_sp))

    return dict(rls_enabled=rls_enabled, rls_disabled=rls_disabled,
                policies=list(policy_map.values()), functions=functions,
                table_cols=table_cols)


def anon_reachable(roles):
    """True if the policy applies to unauthenticated (anon/public) traffic."""
    if roles is None:
        return True  # no TO clause -> defaults to PUBLIC, includes anon
    return any(r in ("anon", "public") for r in roles)


def analyze(parsed):
    findings = []
    tables_with_policy = {}
    for p in parsed["policies"]:
        tables_with_policy.setdefault(p["table_full"], []).append(p)

    # 1. Policies defined but RLS never enabled -> policies are inert.
    for tbl, pols in tables_with_policy.items():
        schema = tbl.split(".")[0] if "." in tbl else "public"
        if schema in MANAGED_SCHEMAS:
            continue  # Supabase pre-enables RLS on these; missing ENABLE != hole
        if tbl not in parsed["rls_enabled"] or tbl in parsed["rls_disabled"]:
            findings.append(dict(
                sev="CRITICAL", table=tbl, rule="rls-off-with-policies",
                title=(f"`{tbl}` has {len(pols)} "
                       f"{'policy' if len(pols)==1 else 'policies'} but RLS is not enabled"),
                detail=("Policies exist on this table but no `ENABLE ROW LEVEL "
                        "SECURITY` was found for it, so Postgres does not enforce "
                        "them. The anon key can read and write every row."),
                fix=f"ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY;"))

    # 2/3/4. Per-policy checks.
    table_cols = parsed.get("table_cols", {})
    for p in parsed["policies"]:
        tbl, cmd = p["table_full"], p["cmd"]
        anon = anon_reachable(p["roles"])
        cols = table_cols.get(tbl, set())
        sens_cols = sorted(c for c in cols if SENSITIVE_COL.search(c))
        # Strong signal = an actual PII/secret column; fall back to the table-name
        # hint only when we couldn't see the table's columns.
        if cols:
            sens = bool(sens_cols)
        else:
            sens = bool(SENSITIVE.search(p["table_bare"]))
        write = cmd in WRITE_CMDS

        check_true = is_trivially_true(p["check"])
        using_true = is_trivially_true(p["using"])

        # Trivially-true WRITE permission reachable by anon = anyone can write.
        if write and anon and (check_true or (using_true and cmd in ("ALL", "UPDATE", "DELETE"))):
            verb = {"ALL": "read & write", "INSERT": "insert", "UPDATE": "update",
                    "DELETE": "delete"}.get(cmd, cmd.lower())
            findings.append(dict(
                sev="CRITICAL", table=tbl, rule="anon-write-true",
                title=f"`{p['name']}` lets anyone {verb} rows on `{tbl}`",
                detail=(f"The {cmd} policy evaluates to TRUE with no `TO` clause "
                        f"restricting it, so the public anon key can write "
                        f"arbitrary rows (forge ownership, delete records, tamper "
                        f"with data). The absence of a UI button is not a control "
                        f"- the anon key is already in your frontend."),
                fix=scope_fix(p)))
            continue

        # Public read.
        if cmd == "SELECT" and anon and using_true:
            sev = "HIGH" if sens else "MEDIUM"
            if sens_cols:
                why = ("This table has column(s) that look sensitive: "
                       + ", ".join(f"`{c}`" for c in sens_cols)
                       + " - these are exposed to anyone.")
            elif sens:
                why = "This table name suggests sensitive data."
            else:
                why = ("Confirm this table is meant to be fully public (a "
                       "username/avatar profile often is; verify no PII columns).")
            findings.append(dict(
                sev=sev, table=tbl, rule="anon-read-true",
                title=f"`{p['name']}` exposes every row of `{tbl}` to the public",
                detail=("`USING (true)` with no `TO` clause means an unauthenticated "
                        "request returns the whole table. " + why),
                fix=scope_fix(p)))
            continue

        # using(true) + no TO on a role-restricted intent (broad grant).
        if using_true and p["roles"] is None and cmd == "ALL":
            findings.append(dict(
                sev="HIGH", table=tbl, rule="allrole-true",
                title=f"`{p['name']}` grants ALL on `{tbl}` to every role",
                detail=("A `FOR ALL USING (true)` with no `TO` clause is applied to "
                        "anon as well and, being OR-combined, cancels any "
                        "user-scoped policy next to it."),
                fix=scope_fix(p)))

    # 5. SECURITY DEFINER without pinned search_path.
    for f in parsed["functions"]:
        if not f["has_search_path"]:
            findings.append(dict(
                sev="MEDIUM", table=f["name"], rule="definer-search-path",
                title=f"`{f['name']}()` is SECURITY DEFINER without a pinned search_path",
                detail=("A SECURITY DEFINER function without `SET search_path` can be "
                        "hijacked via a shadowing object in a schema the caller "
                        "controls, running attacker code with the owner's rights."),
                fix=f"ALTER FUNCTION {f['name']} SET search_path = '';"))

    # 6. RLS on but zero policies -> locked (info, not a leak).
    for tbl in parsed["rls_enabled"]:
        if tbl not in tables_with_policy:
            findings.append(dict(
                sev="INFO", table=tbl, rule="rls-on-no-policy",
                title=f"`{tbl}` has RLS enabled but no policies",
                detail=("This table denies all access except the service_role. Safe, "
                        "but confirm the app doesn't need anon/authenticated reads "
                        "here (a silent 'no rows' bug looks like this)."),
                fix="-- Add a policy if legitimate access is expected, else leave locked."))

    findings.sort(key=lambda x: (SEV_ORDER[x["sev"]], x["table"]))
    return findings


def scope_fix(p):
    tbl = p["table_full"]
    if p["cmd"] in ("INSERT",):
        return (f'DROP POLICY "{p["name"]}" ON {tbl};\n'
                f'CREATE POLICY "{p["name"]}" ON {tbl}\n'
                f'  FOR INSERT TO authenticated\n'
                f'  WITH CHECK (auth.uid() = user_id);  -- scope to the owner')
    if p["cmd"] in ("UPDATE", "DELETE", "ALL"):
        return (f'DROP POLICY "{p["name"]}" ON {tbl};\n'
                f'CREATE POLICY "{p["name"]}" ON {tbl}\n'
                f'  FOR {p["cmd"]} TO authenticated\n'
                f'  USING (auth.uid() = user_id);  -- scope to the owner')
    return (f'DROP POLICY "{p["name"]}" ON {tbl};\n'
            f'CREATE POLICY "{p["name"]}" ON {tbl}\n'
            f'  FOR SELECT TO authenticated\n'
            f'  USING (auth.uid() = user_id);  -- or a public subset only')


SR_KEY = re.compile(r"SUPABASE_SERVICE_ROLE_KEY", re.I)
NEXT_PUBLIC_SR = re.compile(r"NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY", re.I)
USE_CLIENT = re.compile(r"^\s*['\"]use client['\"]", re.M)
SERVER_ONLY = re.compile(r"""['\"]server-only['\"]""")


def scan_source(root):
    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in ("node_modules", ".next", ".git", "dist", "build")]
        for fn in filenames:
            if not fn.endswith((".ts", ".tsx", ".js", ".jsx", ".env",
                                ".config.js", ".config.ts")):
                continue
            path = os.path.join(dirpath, fn)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    txt = fh.read()
            except Exception:
                continue
            rel = os.path.relpath(path, root)
            if NEXT_PUBLIC_SR.search(txt):
                # NEXT_PUBLIC_ is inlined into the browser bundle at build time
                # regardless of where it is referenced - always a leak.
                findings.append(dict(
                    sev="CRITICAL", table=rel, rule="next-public-service-role",
                    title=f"{rel} uses NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY",
                    detail=("Any env var prefixed NEXT_PUBLIC_ is inlined into the "
                            "browser bundle at build time. The service_role key "
                            "bypasses RLS entirely - shipping it to the browser hands "
                            "every visitor full database access."),
                    fix=("1) Rename to SUPABASE_SERVICE_ROLE_KEY (no NEXT_PUBLIC_).\n"
                         "2) Use it only in server code (route handlers / server "
                         "actions); import 'server-only'.\n"
                         "3) ROTATE the key in the dashboard - the old one is in "
                         "every deployed bundle.\n"
                         "   Verify: npm run build && grep -ro \"eyJ[A-Za-z0-9_-]"
                         "\\{20,\\}\" .next/static")))
            elif SR_KEY.search(txt) and USE_CLIENT.search(txt) and not SERVER_ONLY.search(txt):
                # Only a client component ("use client") is a reliable browser
                # signal. Files under app/api or with import "server-only" are
                # server-side and must not be flagged.
                findings.append(dict(
                    sev="HIGH", table=rel, rule="service-role-in-client",
                    title=f"{rel} references the service_role key in a client component",
                    detail=("This file is a client component ('use client') yet "
                            "references the service_role key. If it instantiates or "
                            "imports that client, the key reaches the browser. Verify "
                            "the import chain."),
                    fix=("Move service_role usage to server-only modules; keep the "
                         "browser client on the anon key + RLS. Rotate if it ever "
                         "shipped.")))
    findings.sort(key=lambda x: (SEV_ORDER[x["sev"]], x["table"]))
    return findings


def render(findings, schema_path, src_path):
    counts = {}
    for f in findings:
        counts[f["sev"]] = counts.get(f["sev"], 0) + 1
    lines = ["# RLS Monitor report", ""]
    lines.append(f"- Schema: `{schema_path}`")
    if src_path:
        lines.append(f"- Source: `{src_path}`")
    summary = "  ".join(f"{SEV_ICON[s]} {counts.get(s,0)} {s.lower()}"
                        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
    lines += [f"- Findings: {summary}", ""]
    leaks = [f for f in findings if f["sev"] in ("CRITICAL", "HIGH")]
    if leaks:
        lines.append(f"> **{len(leaks)} finding(s) can leak or corrupt data right "
                     f"now.** Fix these before your next deploy.\n")
    else:
        lines.append("> No data-leaking policy found. See lower-severity notes.\n")

    for i, f in enumerate(findings, 1):
        lines.append(f"## {i}. {SEV_ICON[f['sev']]} {f['sev']} - {f['title']}")
        lines.append(f"*rule: `{f['rule']}` | object: `{f['table']}`*\n")
        lines.append(f["detail"] + "\n")
        lines.append("**Fix**")
        lines.append("```sql")
        lines.append(f["fix"])
        lines.append("```\n")
    lines.append("---")
    lines.append("*Not flagged by design: an UPDATE policy with `USING` but no "
                 "`WITH CHECK` (Postgres reuses USING for the new row), and the mere "
                 "presence of `WITH CHECK` on INSERT (the language requires it). "
                 "Run with `--explain` for details.*")
    return "\n".join(lines)


EXPLAIN = """\
Why RLS Monitor does NOT flag two popular "bugs":

1) UPDATE policy with USING but no WITH CHECK.
   create policy p on t for update using (auth.uid() = user_id);
   Postgres docs: for ALL/UPDATE, if WITH CHECK is omitted the USING expression
   is used for BOTH which rows are visible AND which new rows are allowed. An
   attacker rewriting user_id to a victim's UUID fails the check on the NEW row
   ("new row violates row-level security policy"). Not a hole on its own.

2) The presence of WITH CHECK on an INSERT policy.
   Postgres does not allow USING on INSERT; WITH CHECK is the only legal option.
   Its presence is required by the language, not evidence of careful design.

A missing WITH CHECK is only a hole when USING is BROADER than the intended
write predicate - e.g. using (true) with no TO clause (reaches anon), or
using (is_public or auth.uid() = user_id) where writes should be owner-only.
The distinguishing question: "with USING as written, can an attacker move a row
to someone else?" If no, there is no finding.
"""


def main():
    ap = argparse.ArgumentParser(description="Supabase RLS security auditor")
    ap.add_argument("--schema", help="path to a Postgres/Supabase schema .sql dump")
    ap.add_argument("--src", help="optional client source dir to scan for a leaked "
                                  "service_role key")
    ap.add_argument("--out", help="write the markdown report to this file")
    ap.add_argument("--json", action="store_true", help="emit findings as JSON")
    ap.add_argument("--fail-on", default="CRITICAL",
                    help="exit non-zero if a finding at/above this severity exists "
                         "(CRITICAL/HIGH/MEDIUM/none). Use in CI on each deploy.")
    ap.add_argument("--explain", action="store_true",
                    help="print the false-positive reasoning and exit")
    args = ap.parse_args()

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass

    if args.explain:
        print(EXPLAIN); return 0
    if not args.schema:
        ap.error("--schema is required (or use --explain)")

    with open(args.schema, "r", encoding="utf-8", errors="ignore") as fh:
        sql = fh.read()
    findings = analyze(parse_schema(sql))
    if args.src:
        findings += scan_source(args.src)
        findings.sort(key=lambda x: (SEV_ORDER[x["sev"]], x["table"]))

    if args.json:
        print(json.dumps(findings, indent=2));
    else:
        report = render(findings, args.schema, args.src)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(report)
            print(f"Report written to {args.out}")
        else:
            print(report)

    if args.fail_on.upper() != "NONE":
        thr = SEV_ORDER.get(args.fail_on.upper(), 0)
        if any(SEV_ORDER[f["sev"]] <= thr for f in findings):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
