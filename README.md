# supabase-rls-monitor

Open-source monitor that re-runs RLS audit checks against your Supabase project
on a schedule and emails you a diff if a policy drifts.

Built as the engine behind the **Guard** service (50 USD/mo): I run the same checks
on every deploy and ping you before a regression ships.

## Status

Early. Core audit SQL lives in
[supabase-rls-audit](https://github.com/cekuu35/supabase-rls-audit). The
scheduled runner + diff emailer is in progress.

## Want it done for you?

- Free 9-query audit SQL (MIT): https://github.com/cekuu35/supabase-rls-audit
- Full RLS Audit Kit (29 USD): https://cengokurtoglu.gumroad.com/l/supabase-rls-audit-kit
- Guard (50 USD/mo, early access): email cnkkurtoglu@gmail.com
- Done-for-you audit from 99 USD: https://www.upwork.com/services/product/2083862107074689176

## License

MIT (planned).
