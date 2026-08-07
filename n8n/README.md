# RLS Guard — n8n workflow (the monthly subscription engine)

A self-contained n8n workflow that re-scans a Supabase schema for RLS data-leak
patterns **on every deploy** and emails an alert the moment a critical hole
lands. This is the engine behind the **$199/mo Guard** tier — the recurring
product, not a one-time audit.

The detection engine is a JavaScript port of `rls_monitor.py`, embedded directly
in a Code node, so the workflow needs **nothing installed** — no Python, no
external service. It imports into n8n Cloud or self-hosted as-is.

## How it works

```
POST schema.sql  ─▶  [Deploy webhook]  ─▶  [Scan RLS]  ─┬─▶ [Respond with report]  (always, 200)
                                                        └─▶ [Only if blocking] ─▶ [Email alert]  (only on CRITICAL/HIGH)
```

1. The customer's CI posts their schema dump to a private webhook URL after each deploy.
2. The Code node scans it (same logic as the CLI, validated to give identical results).
3. The webhook responds with the full report; if there's a CRITICAL/HIGH finding, an email alert fires.

## Customer setup (one line in their CI)

After `supabase db dump`, POST the schema to their webhook:

```bash
supabase db dump --schema-only > schema.sql
curl -sS -X POST "https://YOUR-N8N/webhook/rls-guard" \
  -H "Content-Type: text/plain" --data-binary @schema.sql
```

Or as JSON: `-H "Content-Type: application/json" -d '{"schema":"<sql>"}'`.
The response body is the plain-text report; the CI step can `grep CRITICAL` and fail the build.

## Import + operate (you, the service provider)

1. n8n → **Workflows → Import from File** → `rls-guard.workflow.json`.
2. Open **Email alert** → attach an SMTP credential (or swap this node for a
   Slack / Discord node). Set the recipient — it defaults to the `RLS_ALERT_EMAIL`
   env var, else `client@example.com`.
3. **Activate** the workflow. Copy the production webhook URL and give each
   customer their own (run one workflow per customer, or add a customer id to the path).
4. Bill it monthly (see below).

> ⚠️ Tested: the detection engine is verified with `node scan.js` and via a
> harness that runs the exact embedded Code-node source — identical results to
> the Python CLI. **Not yet tested in a live n8n instance** (no instance here):
> do one import + one test POST before selling. Node types/versions used:
> webhook v2, code v2, respondToWebhook v1, emailSend v2.1.

## The monthly billing

The workflow is the deliverable; the subscription is how it's sold. Options,
easiest first:

- **Gumroad membership** — create a recurring $199/mo membership ("RLS Guard —
  monthly Supabase security monitoring"). Cleanest for a solo seller; Gumroad
  handles recurring charge + cancellation. Buyer pays → you onboard their webhook.
- **Fiverr Subscriptions** — offer the existing RLS gig's Guard tier as a monthly
  subscription (Fiverr supports recurring on eligible gigs).
- **Stripe Payment Link** (recurring price) — if selling off-platform.

Pricing rationale (from the sales knowledge base): a one-time digital file tops
out ~$170, but **a service/subscription is the right product type above that**.
$199/mo clears it and matches the audit ladder ($99 / $499 / $699 one-time).

## Why this workflow (and not a generic n8n automation)

In the broad n8n market you're one of thousands of automation builders with no
proof. Here you're the only one selling *RLS auditing*, your analysis has been
confirmed by the Supabase security team, and the detection engine already exists
and is tested. The moat is the niche — this workflow monetizes it monthly.

## Files
- `rls-guard.workflow.json` — import this into n8n
- `scan.js` — the standalone engine (also runnable: `node scan.js <schema.sql>`)
- `build_workflow.py` — regenerates the workflow from `scan.js` if you edit the engine
