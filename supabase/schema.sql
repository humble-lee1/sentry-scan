-- Run this in the Supabase SQL Editor (left sidebar -> SQL Editor -> New query)
-- This file matches the actual schema created in the project's Supabase instance.

-- Table 1: domains being monitored
create table if not exists monitored_sites (
  id uuid primary key default gen_random_uuid(),
  domain text not null,
  email text not null,
  tier text not null default 'free' check (tier in ('free', 'paid')),
  frequency_days int not null default 30,
  created_at timestamptz not null default now(),
  next_scan_at timestamptz not null default now(),
  active boolean not null default true
);

-- Table 2: history of completed scans, linked to a monitored site.
-- Storing each scan (not just the latest) lets us diff "this month vs last
-- month" to detect what's new or resolved, and gives a full audit trail.
create table if not exists scan_history (
  id uuid primary key default gen_random_uuid(),
  site_id uuid not null references monitored_sites(id) on delete cascade,
  score int not null,
  findings_json jsonb not null,
  scanned_at timestamptz not null default now()
);

-- Speeds up the cron job's query for "which sites are due for a scan right now"
create index if not exists idx_monitored_sites_next_scan
  on monitored_sites (next_scan_at) where active = true;

-- Row Level Security: locked down by default (per the project's security settings).
-- Our Next.js API routes use the SECRET key (server-side only), which bypasses
-- RLS entirely -- that's intentional and safe, since the secret key never
-- reaches the browser. No public policies are added on purpose: this means
-- the anon/publishable key (used in browser code) has zero access to either
-- table. All access goes through server-side API routes using the secret key.
alter table monitored_sites enable row level security;
alter table scan_history enable row level security;

-- Table 3: tracks Paystack subscriptions. Kept separate from monitored_sites
-- because a subscription can exist in a pending/failed state before (or after)
-- a monitored_sites row is created -- we only create the monitored_sites row
-- once Paystack confirms the subscription via webhook, so checkout abandonment
-- never results in a "monitoring" row with no payment behind it.
create table if not exists subscriptions (
  id uuid primary key default gen_random_uuid(),
  site_id uuid references monitored_sites(id) on delete set null,
  email text not null,
  domain text not null,
  paystack_customer_code text,
  paystack_subscription_code text,
  paystack_authorization_code text,
  status text not null default 'pending' check (status in ('pending', 'active', 'cancelled', 'failed')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_subscriptions_email on subscriptions (email);

alter table subscriptions enable row level security;

-- Grant table-level access to the service_role (used by our server-side API
-- routes via the secret key). Without this, queries fail with "permission
-- denied" even though RLS itself would otherwise allow it -- table grants and
-- RLS are separate layers in Postgres.
grant select, insert, update, delete on monitored_sites to service_role;
grant select, insert, update, delete on scan_history to service_role;
grant select, insert, update, delete on subscriptions to service_role;
