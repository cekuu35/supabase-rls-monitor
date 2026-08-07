/*
 * RLS Guard - detection engine (JavaScript port of rls_monitor.py core).
 * Self-contained: no dependencies. This same function body is embedded in the
 * n8n "Scan" Code node so the workflow needs nothing installed.
 *
 * scanSchema(sql) -> { findings, counts, hasBlocking, report }
 *
 * CLI test:  node scan.js ../samples/demo_vulnerable.sql
 */

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
const MANAGED = new Set(["storage", "auth", "realtime", "vault", "graphql",
  "graphql_public", "extensions", "supabase_functions", "cron"]);
const SENSITIVE = /(user|account|payment|invoice|patient|medical|health|message|email|token|secret|api_key|credential|order|customer|profile|subscription|billing|address|ssn|passport|dob|salary|bank)/i;
const SENSITIVE_COL = /(email|phone|mobile|ssn|passport|national_id|dob|birth|address|salary|iban|bank|card|payment|token|secret|api_?key|password|hash|credential|stripe|latitude|longitude|geo|location)/i;
const WRITE = new Set(["ALL", "INSERT", "UPDATE", "DELETE"]);

function stripComments(sql) {
  return sql.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/--[^\n]*/g, " ");
}

// Split on top-level ';' while respecting $$...$$ blocks and '...' strings.
function splitStatements(sql) {
  const out = [];
  let buf = "", i = 0, tag = null, sq = false;
  while (i < sql.length) {
    const c = sql[i];
    if (tag) {
      if (sql.startsWith(tag, i)) { buf += tag; i += tag.length; tag = null; continue; }
      buf += c; i++; continue;
    }
    if (sq) { buf += c; if (c === "'") sq = false; i++; continue; }
    if (c === "'") { sq = true; buf += c; i++; continue; }
    const m = sql.slice(i).match(/^\$[A-Za-z0-9_]*\$/);
    if (m) { tag = m[0]; buf += tag; i += tag.length; continue; }
    if (c === ";") { out.push(buf); buf = ""; i++; continue; }
    buf += c; i++;
  }
  if (buf.trim()) out.push(buf);
  return out;
}

function normTable(raw) {
  const parts = raw.trim().split(".").map(p => p.trim().replace(/"/g, ""));
  const bare = parts[parts.length - 1].toLowerCase();
  const full = parts.length === 1 ? "public." + bare : parts.map(p => p.toLowerCase()).join(".");
  return { full, bare };
}

// Balanced-paren extraction starting at the first '(' after index `from`.
function extractParen(s, from) {
  let i = from;
  while (i < s.length && s[i] !== "(") { if (!/\s/.test(s[i])) return null; i++; }
  if (i >= s.length) return null;
  let depth = 0, q = false;
  for (let j = i; j < s.length; j++) {
    const ch = s[j];
    if (q) { if (ch === "'") q = false; continue; }
    if (ch === "'") q = true;
    else if (ch === "(") depth++;
    else if (ch === ")") { depth--; if (depth === 0) return s.slice(i + 1, j).trim(); }
  }
  return null;
}

function triviallyTrue(expr) {
  if (expr == null) return false;
  let e = expr.trim().toLowerCase();
  while (e.startsWith("(") && e.endsWith(")")) e = e.slice(1, -1).trim();
  return e === "true";
}

function parseSchema(sql) {
  sql = stripComments(sql);
  const rlsEnabled = new Set(), rlsDisabled = new Set();
  const policyMap = new Map();
  const funcs = [], tableCols = new Map();

  for (const stmt of splitStatements(sql)) {
    const s = stmt.trim(); if (!s) continue;
    const low = s.toLowerCase();

    let m = s.match(/^create\s+table\s+(?:if\s+not\s+exists\s+)?([\w."]+)/i);
    if (m) {
      const { full } = normTable(m[1]);
      const body = extractParen(s, s.indexOf("("));
      const cols = new Set();
      if (body) for (const part of body.split(/,(?![^()]*\))/)) {
        const tok = part.trim().split(/\s+/);
        if (tok[0] && !["CONSTRAINT", "PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "EXCLUDE", "LIKE"].includes(tok[0].toUpperCase()))
          cols.add(tok[0].replace(/"/g, "").toLowerCase());
      }
      tableCols.set(full, cols);
    }

    m = low.match(/alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?([\w."]+)\s+enable\s+row\s+level\s+security/);
    if (m) { rlsEnabled.add(normTable(m[1]).full); continue; }
    m = low.match(/alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?([\w."]+)\s+disable\s+row\s+level\s+security/);
    if (m) { rlsDisabled.add(normTable(m[1]).full); continue; }

    m = s.match(/^drop\s+policy\s+(?:if\s+exists\s+)?("[^"]+"|\w+)\s+on\s+([\w."]+)/i);
    if (m) { policyMap.delete(normTable(m[2]).full + "||" + m[1].replace(/"/g, "")); continue; }

    m = s.match(/^create\s+policy\s+(?:if\s+not\s+exists\s+)?("[^"]+"|\w+)\s+on\s+([\w."]+)/i);
    if (m) {
      const name = m[1].replace(/"/g, "");
      const { full, bare } = normTable(m[2]);
      const cmdM = s.match(/\bfor\s+(all|select|insert|update|delete)\b/i);
      const cmd = cmdM ? cmdM[1].toUpperCase() : "ALL";
      let roles = null;
      const rm = s.match(/\bto\s+([a-z0-9_", ]+?)(?=\s+using\b|\s+with\s+check\b|$)/i);
      if (rm) roles = rm[1].split(",").map(r => r.trim().replace(/"/g, "").toLowerCase()).filter(Boolean);
      const uM = s.match(/\busing\b/i);
      const using = uM ? extractParen(s, uM.index + uM[0].length) : null;
      const cM = s.match(/\bwith\s+check\b/i);
      const check = cM ? extractParen(s, cM.index + cM[0].length) : null;
      policyMap.set(full + "||" + name, { name, full, bare, cmd, roles, using, check });
      continue;
    }

    if (/create\s+(or\s+replace\s+)?function/.test(low) && /security\s+definer/.test(low)) {
      const fn = s.match(/function\s+([\w."]+)\s*\(/i);
      funcs.push({ name: fn ? fn[1].replace(/"/g, "") : "<function>", hasSearchPath: /set\s+search_path/.test(low) });
    }
  }
  return { rlsEnabled, rlsDisabled, policies: [...policyMap.values()], funcs, tableCols };
}

function anonReachable(roles) {
  if (roles == null) return true;
  return roles.some(r => r === "anon" || r === "public");
}

function analyze(p) {
  const findings = [];
  const byTable = new Map();
  for (const pol of p.policies) { if (!byTable.has(pol.full)) byTable.set(pol.full, []); byTable.get(pol.full).push(pol); }

  for (const [tbl, pols] of byTable) {
    const schema = tbl.includes(".") ? tbl.split(".")[0] : "public";
    if (MANAGED.has(schema)) continue;
    if (!p.rlsEnabled.has(tbl) || p.rlsDisabled.has(tbl))
      findings.push({ sev: "CRITICAL", rule: "rls-off-with-policies", object: tbl,
        title: "`" + tbl + "` has " + pols.length + " policy(ies) but RLS is not enabled",
        detail: "Policies exist but no ENABLE ROW LEVEL SECURITY was found, so Postgres does not enforce them. The anon key can read and write every row.",
        fix: "ALTER TABLE " + tbl + " ENABLE ROW LEVEL SECURITY;" });
  }

  for (const pol of p.policies) {
    const anon = anonReachable(pol.roles);
    const cols = p.tableCols.get(pol.full) || new Set();
    const sensCols = [...cols].filter(c => SENSITIVE_COL.test(c));
    const sens = cols.size ? sensCols.length > 0 : SENSITIVE.test(pol.bare);
    const write = WRITE.has(pol.cmd);
    const checkTrue = triviallyTrue(pol.check);
    const usingTrue = triviallyTrue(pol.using);

    if (write && anon && (checkTrue || (usingTrue && ["ALL", "UPDATE", "DELETE"].includes(pol.cmd)))) {
      const verb = { ALL: "read & write", INSERT: "insert", UPDATE: "update", DELETE: "delete" }[pol.cmd] || pol.cmd;
      findings.push({ sev: "CRITICAL", rule: "anon-write-true", object: pol.full,
        title: "`" + pol.name + "` lets anyone " + verb + " rows on `" + pol.full + "`",
        detail: "The " + pol.cmd + " policy evaluates to TRUE with no TO clause, so the public anon key can write arbitrary rows. A missing UI button is not a control.",
        fix: 'DROP POLICY "' + pol.name + '" ON ' + pol.full + ";\n-- recreate scoped: FOR " + pol.cmd + " TO authenticated USING (auth.uid() = user_id)" });
      continue;
    }
    if (pol.cmd === "SELECT" && anon && usingTrue) {
      findings.push({ sev: sens ? "HIGH" : "MEDIUM", rule: "anon-read-true", object: pol.full,
        title: "`" + pol.name + "` exposes every row of `" + pol.full + "` to the public",
        detail: "USING (true) with no TO clause returns the whole table to unauthenticated requests. " +
          (sensCols.length ? "Sensitive column(s) exposed: " + sensCols.join(", ") + "." : sens ? "Table name suggests sensitive data." : "Confirm this table is meant to be fully public."),
        fix: 'DROP POLICY "' + pol.name + '" ON ' + pol.full + ";\n-- recreate: FOR SELECT TO authenticated USING (auth.uid() = user_id) or a public subset" });
    }
  }

  for (const f of p.funcs) if (!f.hasSearchPath)
    findings.push({ sev: "MEDIUM", rule: "definer-search-path", object: f.name,
      title: "`" + f.name + "()` is SECURITY DEFINER without a pinned search_path",
      detail: "Can be hijacked via a shadowing object in a caller-controlled schema, running attacker code with the owner's rights.",
      fix: "ALTER FUNCTION " + f.name + " SET search_path = '';" });

  findings.sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev] || a.object.localeCompare(b.object));
  return findings;
}

function scanSchema(sql) {
  const findings = analyze(parseSchema(sql || ""));
  const counts = {};
  for (const f of findings) counts[f.sev] = (counts[f.sev] || 0) + 1;
  const blocking = findings.filter(f => f.sev === "CRITICAL" || f.sev === "HIGH");
  const hasBlocking = blocking.length > 0;
  const lines = ["RLS Guard report", "================",
    "CRITICAL " + (counts.CRITICAL || 0) + "  HIGH " + (counts.HIGH || 0) +
    "  MEDIUM " + (counts.MEDIUM || 0) + "  INFO " + (counts.INFO || 0), ""];
  if (hasBlocking) lines.push(blocking.length + " finding(s) can leak or corrupt data. Fix before your next deploy.", "");
  findings.forEach((f, i) => {
    lines.push((i + 1) + ". [" + f.sev + "] " + f.title);
    lines.push("   " + f.detail);
    lines.push("   FIX: " + f.fix.replace(/\n/g, "\n        "), "");
  });
  return { findings, counts, hasBlocking, report: lines.join("\n") };
}

// ---- CLI test harness (ignored by n8n) ----
if (typeof require !== "undefined" && require.main === module) {
  const fs = require("fs");
  const path = process.argv[2];
  if (!path) { console.error("usage: node scan.js <schema.sql>"); process.exit(1); }
  const res = scanSchema(fs.readFileSync(path, "utf8"));
  console.log(res.report);
  console.log("\nhasBlocking =", res.hasBlocking, "| counts =", JSON.stringify(res.counts));
}

if (typeof module !== "undefined") module.exports = { scanSchema };
