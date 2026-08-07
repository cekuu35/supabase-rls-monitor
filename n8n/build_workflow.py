#!/usr/bin/env python3
"""Assemble the RLS Guard n8n workflow suite, embedding the validated scan.js
engine into Code nodes. Emits three integrated workflows:

  rls-guard.workflow.json       - core service: deploy webhook -> scan -> alert
  onboarding.workflow.json      - Gumroad sale ping -> welcome email (auto-deliver)
  offboarding.workflow.json     - Gumroad cancel ping -> notify seller to revoke

Run:  python build_workflow.py
"""
import json, os

here = os.path.dirname(os.path.abspath(__file__))
engine = open(os.path.join(here, "scan.js"), encoding="utf-8").read().split(
    "// ---- CLI test harness", 1)[0].rstrip()

# ---------------------------------------------------------------- Guard scan
scan_code = engine + r"""

// ---- n8n entry: authenticate, validate, scan ----
const item = $input.first().json || {};
const headers = item.headers || {};
const query = item.query || {};
const body = item.body !== undefined ? item.body : item;

const EXPECTED = ($env && $env.RLS_GUARD_TOKEN) ? $env.RLS_GUARD_TOKEN : "test-token";
const token = headers["x-rls-token"] || query.token ||
              (body && typeof body === "object" ? body.token : "") || "";
const customer = headers["x-rls-customer"] ||
              (body && typeof body === "object" ? body.customer : "") || "unknown";

if (!token || token !== EXPECTED) {
  return [{ json: { authorized: false, customer, hasBlocking: false, counts: {},
    report: "401 Unauthorized: send a valid 'x-rls-token' header." } }];
}

let sql = "";
if (typeof body === "string") sql = body;
else if (body && typeof body === "object") sql = body.schema || body.sql || body.data || "";
if (!sql && typeof item === "string") sql = item;

if (!sql || !sql.trim()) {
  return [{ json: { authorized: true, customer, hasBlocking: false, counts: {},
    report: "No schema received. POST the output of `supabase db dump --schema-only` as the request body." } }];
}

let res;
try { res = scanSchema(sql); }
catch (e) {
  return [{ json: { authorized: true, customer, hasBlocking: false, counts: {},
    error: String(e && e.message || e),
    report: "Scan error (schema could not be parsed): " + String(e && e.message || e) } }];
}
res.authorized = true;
res.customer = customer;
return [{ json: res }];
"""

gate_code = ("// Alert only on an authorized request that has a CRITICAL/HIGH finding.\n"
             "return $input.all().filter(i => i.json.authorized && i.json.hasBlocking);")

# ---------------------------------------------------------------- Onboarding
onboard_code = r"""
// Gumroad sends a form-encoded "ping" on each sale. Provision the buyer.
const item = $input.first().json || {};
const b = item.body || item;
const email = b.email || b.purchaser_email || "";
const product = b.product_name || b.product_permalink || "";
const recurrence = b.recurrence || "monthly";
const isOurs = /rls guard/i.test(product) || /yvdwv/i.test(String(b.product_permalink || ""));

if (!email || !isOurs) {
  return [{ json: { skip: true, reason: "not our product or no email", product, email } }];
}

const WEBHOOK = ($env && $env.N8N_PUBLIC_URL ? $env.N8N_PUBLIC_URL : "https://YOUR-N8N") + "/webhook/rls-guard";
const TOKEN = ($env && $env.RLS_GUARD_TOKEN) ? $env.RLS_GUARD_TOKEN : "test-token";

const welcome =
"Welcome to RLS Guard — your Supabase security monitor is live.\n\n" +
"Add this one step to your CI/deploy pipeline. After each deploy it scans your\n" +
"schema and flags any RLS hole before it reaches production:\n\n" +
"  supabase db dump --schema-only > schema.sql\n" +
"  curl -sS -X POST \"" + WEBHOOK + "\" \\\n" +
"    -H \"Content-Type: text/plain\" \\\n" +
"    -H \"x-rls-token: " + TOKEN + "\" \\\n" +
"    -H \"x-rls-customer: " + email + "\" \\\n" +
"    --data-binary @schema.sql\n\n" +
"The response is a plain-English report ranked by severity, with the exact SQL to\n" +
"fix each finding. If a CRITICAL or HIGH issue is found, you also get an email alert.\n\n" +
"Tip: make your build fail on a critical finding —\n" +
"  curl ... | grep -q CRITICAL && { echo 'RLS hole - blocking deploy'; exit 1; } || true\n\n" +
"Questions about any finding? Just reply to this email.\n\n" +
"— RLS Guard";

return [{ json: { skip: false, email, product, recurrence, subject: "Your RLS Guard is live — 1-step setup", body: welcome } }];
"""

# ---------------------------------------------------------------- Offboarding
offboard_code = r"""
// Gumroad cancellation / subscription-ended ping -> tell the seller to revoke.
const item = $input.first().json || {};
const b = item.body || item;
const email = b.email || b.purchaser_email || "unknown";
const cancelled = b.cancelled === "true" || b.cancelled === true ||
                  !!b.subscription_cancelled_at || !!b.subscription_ended_at ||
                  /cancel/i.test(String(b.resource_name || ""));
const product = b.product_name || b.product_permalink || "";
return [{ json: {
  email, product, cancelled,
  subject: "[RLS Guard] Cancellation: " + email,
  body: "Customer " + email + " cancelled their RLS Guard subscription (" + product + ").\n" +
        "Action: rotate the shared token or remove their entry from the customer store so their webhook stops working." } }];
"""


def code_node(name, node_id, code, pos):
    return {"parameters": {"jsCode": code}, "id": node_id, "name": name,
            "type": "n8n-nodes-base.code", "typeVersion": 2, "position": pos}


def webhook_node(name, node_id, path, pos, raw=True):
    return {"parameters": {"httpMethod": "POST", "path": path,
            "responseMode": "responseNode" if raw else "onReceived",
            "options": {"rawBody": raw}},
            "id": node_id, "name": name, "type": "n8n-nodes-base.webhook",
            "typeVersion": 2, "position": pos, "webhookId": path}


def email_node(name, node_id, to_expr, pos):
    return {"parameters": {
        "fromEmail": "rls-guard@YOUR-DOMAIN.com", "toEmail": to_expr,
        "subject": "={{ $json.subject }}", "emailFormat": "text",
        "text": "={{ $json.body }}", "options": {}},
        "id": node_id, "name": name, "type": "n8n-nodes-base.emailSend",
        "typeVersion": 2.1, "position": pos}


def respond_node(name, node_id, pos):
    return {"parameters": {"respondWith": "text", "responseBody": "={{ $json.report }}",
            "options": {}}, "id": node_id, "name": name,
            "type": "n8n-nodes-base.respondToWebhook", "typeVersion": 1, "position": pos}


def dump(name, wf):
    wid = name.replace(".workflow.json", "").replace("-", "")
    wf.update({"id": wid, "active": False,
               "settings": {"executionOrder": "v1"}, "tags": []})
    path = os.path.join(here, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(wf, f, indent=2)
    print("wrote", name, "-", len(wf["nodes"]), "nodes")


# ---- 1) Guard
dump("rls-guard.workflow.json", {
    "name": "RLS Guard — deploy scan",
    "nodes": [
        webhook_node("Deploy webhook", "wh-guard", "rls-guard", [240, 300]),
        code_node("Scan RLS", "code-scan", scan_code, [520, 300]),
        respond_node("Respond with report", "resp", [800, 200]),
        code_node("Only if blocking", "code-gate", gate_code, [800, 420]),
        email_node("Email alert", "email-alert",
                   "={{ $env.RLS_ALERT_EMAIL || 'ops@example.com' }}", [1060, 420]),
    ],
    "connections": {
        "Deploy webhook": {"main": [[{"node": "Scan RLS", "type": "main", "index": 0}]]},
        "Scan RLS": {"main": [[
            {"node": "Respond with report", "type": "main", "index": 0},
            {"node": "Only if blocking", "type": "main", "index": 0}]]},
        "Only if blocking": {"main": [[{"node": "Email alert", "type": "main", "index": 0}]]},
    },
})

# ---- 2) Onboarding
dump("onboarding.workflow.json", {
    "name": "RLS Guard — onboarding (Gumroad sale)",
    "nodes": [
        webhook_node("Gumroad sale ping", "wh-onb", "gumroad-sale", [240, 300], raw=False),
        code_node("Build welcome", "code-onb", onboard_code, [520, 300]),
        {"parameters": {"conditions": {"options": {"caseSensitive": True,
            "typeValidation": "loose", "version": 2},
            "conditions": [{"id": "c1", "leftValue": "={{ $json.skip }}",
            "rightValue": True, "operator": {"type": "boolean", "operation": "false",
            "singleValue": True}}], "combinator": "and"}},
         "id": "if-onb", "name": "Our product?", "type": "n8n-nodes-base.if",
         "typeVersion": 2, "position": [800, 300]},
        email_node("Send welcome", "email-onb", "={{ $json.email }}", [1080, 220]),
    ],
    "connections": {
        "Gumroad sale ping": {"main": [[{"node": "Build welcome", "type": "main", "index": 0}]]},
        "Build welcome": {"main": [[{"node": "Our product?", "type": "main", "index": 0}]]},
        "Our product?": {"main": [[{"node": "Send welcome", "type": "main", "index": 0}], []]},
    },
})

# ---- 3) Offboarding
dump("offboarding.workflow.json", {
    "name": "RLS Guard — offboarding (Gumroad cancel)",
    "nodes": [
        webhook_node("Gumroad cancel ping", "wh-off", "gumroad-cancel", [240, 300], raw=False),
        code_node("Build revoke notice", "code-off", offboard_code, [520, 300]),
        email_node("Notify seller", "email-off",
                   "={{ $env.RLS_ALERT_EMAIL || 'ops@example.com' }}", [800, 300]),
    ],
    "connections": {
        "Gumroad cancel ping": {"main": [[{"node": "Build revoke notice", "type": "main", "index": 0}]]},
        "Build revoke notice": {"main": [[{"node": "Notify seller", "type": "main", "index": 0}]]},
    },
})

print("done")
