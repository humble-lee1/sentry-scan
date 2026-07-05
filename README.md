# Sentry Scan

A free website security scanner. Enter a domain, get a plain-English report
covering SSL/TLS, HTTP security headers, email spoofing protection (SPF/DKIM/DMARC),
exposed files (.env, .git, etc.), and basic CMS/WordPress checks.

No AI API calls in v1 — every check is plain Node.js logic (TLS handshake, DNS
lookups, HTTP requests). This means it costs $0 to run regardless of how many
people use it.

## Running it locally

You need Node.js 18+ installed (you can check with `node --version`).

```bash
npm install
npm run dev
```

Then open http://localhost:3000 in your browser.

## Project structure

```
src/
  app/
    page.tsx              → homepage (the scan input)
    scan/page.tsx          → results page (reads ?domain= from the URL)
    api/scan/route.ts      → API endpoint that runs the actual scan
    layout.tsx             → shared page wrapper
    globals.css            → fonts, base styles, terminal aesthetic
  components/
    ScanForm.tsx           → the input box on the homepage
    ScanningState.tsx       → the "scanning..." loading animation
    ScoreGauge.tsx          → the circular score display
    CategorySection.tsx     → groups findings by category (SSL, headers, etc.)
    FindingCard.tsx         → a single finding/result card
    SeverityBadge.tsx       → the colored CRITICAL/HIGH/MEDIUM/etc. label
  lib/
    types.ts               → shared TypeScript types for findings/reports
    run-scan.ts             → orchestrator that runs all 5 scanners and scores the result
    scanners/
      ssl.ts                → SSL/TLS certificate + protocol check
      headers.ts             → HTTP security header check
      dns-email.ts            → SPF / DKIM / DMARC check
      exposure.ts             → checks for exposed .env, .git, backups, etc.
      cms.ts                  → WordPress detection + version exposure check
```

## How each scan module works (so you can extend it later)

Each file in `src/lib/scanners/` exports one async function that takes a domain
string and returns an array of `Finding` objects (see `types.ts` for the shape).
To add a new check:

1. Either add a new rule to an existing scanner (e.g. a new header in `headers.ts`),
   or create a new file in `scanners/` following the same pattern.
2. If you create a new file, import and call it from `run-scan.ts` inside the
   `Promise.allSettled([...])` array, and add its category to `CATEGORY_LABELS`.

## Deploying for free

This deploys cleanly to **Vercel** (built by the same team as Next.js, free tier
is generous enough for this kind of low-traffic tool):

1. Push this project to a GitHub repository.
2. Go to vercel.com, sign in with GitHub, click "New Project", and select the repo.
3. Leave all settings as default (Vercel auto-detects Next.js) and click Deploy.
4. You'll get a free `yourproject.vercel.app` URL immediately. You can attach a
   custom domain later from the Vercel dashboard once you're ready to buy one.

No environment variables or API keys are required for v1, since there's no
external AI or paid service involved yet.

## Known limitations (by design, for v1)

- The exposure scanner only checks a fixed list of common paths — it is not a
  full vulnerability scanner.
- The DKIM check only tries a handful of common selector names, since DKIM
  selectors are provider-specific and there's no universal way to discover them.
- No database yet — every scan is stateless and nothing is saved. If you want
  a "scan history" or paid monitoring feature later, that's when you'd add
  Supabase (their free tier covers this comfortably).
- No payment integration yet. The "Coming soon" monitoring button is a placeholder
  for when you add Paystack.

## Monthly monitoring (paid: ₦15,000/month via Paystack)

On the results page, anyone can start monthly monitoring for a domain.
This is a paid feature — checkout happens through Paystack, and the first
charge is delayed 30 days (so the first month is effectively a free trial,
without calling it that).

### How it works

1. **Checkout**: `src/app/api/checkout/route.ts` creates a `pending` row in
   the `subscriptions` table, then redirects the person to a Paystack-hosted
   checkout page (via `initializeTransaction`) to collect their card.
2. **Webhook**: `src/app/api/webhooks/paystack/route.ts` listens for
   Paystack's `charge.success` event. It verifies the request is genuinely
   from Paystack (HMAC signature check), then creates a real Paystack
   subscription (billing starts in 30 days) and — only at this point —
   creates the actual `monitored_sites` row. This ordering matters: a
   monitored site is never created without a verified payment behind it.
3. **Scheduled scanning / change detection / email**: unchanged from the
   original free-tier design — see `src/lib/run-scan.ts`,
   `src/lib/compare-scans.ts`, `src/lib/email.ts`, and the cron route at
   `src/app/api/cron/scan/route.ts`.
4. **Cancellation / failed payment**: the same webhook route handles
   `subscription.disable` and `invoice.payment_failed` by marking the
   subscription `cancelled` and setting `monitored_sites.active = false`,
   which stops the cron job from scanning that site (its scan history is
   preserved in case they resubscribe).

### Required environment variables

```
PAYSTACK_SECRET_KEY=sk_test_...      # test key while developing; switch to sk_live_... before charging real people
NEXT_PUBLIC_PAYSTACK_PUBLIC_KEY=pk_test_...
```

(Plus the Supabase, Resend, and CRON_SECRET variables from before.)

### Setting up the Paystack webhook (required once deployed)

Paystack needs a public URL to send webhook events to — this can't be
tested with `localhost` directly. Once deployed to Vercel:

1. Go to Paystack dashboard → Settings → API Keys & Webhooks
2. Set the webhook URL to `https://yourdomain.vercel.app/api/webhooks/paystack`
3. Save

To test locally before deploying, use a tool like `ngrok` to expose your
local dev server temporarily, and point Paystack's webhook URL at the
ngrok URL while testing (switch back to the production URL afterward).

### Going live

The plan code in `src/lib/paystack.ts` (`SENTRY_SCAN_PLAN_CODE`) was created
in Paystack's **Test Mode**. Before accepting real payments:

1. Switch your Paystack dashboard out of Test Mode
2. Recreate the same plan (₦15,000/month) in Live Mode — it will get a
   different plan code
3. Update `SENTRY_SCAN_PLAN_CODE` in `src/lib/paystack.ts` with the new code
4. Replace `PAYSTACK_SECRET_KEY` and `NEXT_PUBLIC_PAYSTACK_PUBLIC_KEY` in
   your environment variables with the `sk_live_...` / `pk_live_...` keys


### Email sending domain

Until a sending domain is verified with Resend, emails can only be delivered
to the address used to sign up for Resend (sandbox mode). This is fine for
development and testing. Once you own a domain and verify it in the Resend
dashboard, update the `from` address in `src/lib/email.ts` to use it
(e.g. `Sentry Scan <alerts@yourdomain.com>`) — no other code changes needed.

### Database schema

Three tables in Supabase, all with Row Level Security enabled and no public
policies (all access goes through server-side API routes using the secret key):

- **`monitored_sites`**: one row per domain being monitored (domain, email,
  tier, frequency_days, next_scan_at, active). Only ever created by the
  Paystack webhook after a verified payment.
- **`scan_history`**: one row per completed scan (site_id, score,
  findings_json, scanned_at) — used to detect what changed between scans
- **`subscriptions`**: tracks Paystack subscription state (pending, active,
  cancelled, failed) and links back to the monitored_sites row it created

