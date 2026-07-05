import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';
import { getSupabaseServerClient } from '@/lib/supabase-server';
import { verifyTransaction, createSubscription, SENTRY_SCAN_PLAN_CODE } from '@/lib/paystack';

/**
 * Verifies that a webhook request genuinely came from Paystack by checking
 * the HMAC SHA512 signature against our secret key. Without this check,
 * anyone who discovers this URL could POST a fake "successful payment"
 * event and activate monitoring for free.
 */
function isValidPaystackSignature(rawBody: string, signatureHeader: string | null): boolean {
  if (!signatureHeader) return false;
  const secret = process.env.PAYSTACK_SECRET_KEY;
  if (!secret) return false;

  const expected = crypto.createHmac('sha512', secret).update(rawBody).digest('hex');
  return expected === signatureHeader;
}

export async function POST(req: NextRequest) {
  const rawBody = await req.text();
  const signature = req.headers.get('x-paystack-signature');

  if (!isValidPaystackSignature(rawBody, signature)) {
    console.error('Invalid Paystack webhook signature — rejecting.');
    return NextResponse.json({ error: 'Invalid signature' }, { status: 401 });
  }

  const event = JSON.parse(rawBody);
  const supabase = getSupabaseServerClient();

  // We only act on the events relevant to our flow. Paystack sends many
  // event types; anything else is acknowledged but ignored.
  if (event.event === 'charge.success') {
    await handleChargeSuccess(supabase, event.data);
  } else if (event.event === 'subscription.disable' || event.event === 'invoice.payment_failed') {
    await handleSubscriptionFailureOrCancellation(supabase, event.data);
  }

  // Always return 200 quickly so Paystack doesn't retry unnecessarily;
  // we've already done the work (or intentionally ignored the event) above.
  return NextResponse.json({ received: true });
}

async function handleChargeSuccess(
  supabase: ReturnType<typeof getSupabaseServerClient>,
  data: {
    reference: string;
    customer: { customer_code: string; email: string };
    authorization: { authorization_code: string };
  }
) {
  const { data: pending } = await supabase
    .from('subscriptions')
    .select('id, domain, email')
    .eq('paystack_subscription_code', data.reference)
    .eq('status', 'pending')
    .maybeSingle();

  if (!pending) {
    // Could be a duplicate webhook delivery (Paystack retries) or an event
    // we don't recognize — safe to ignore rather than error.
    return;
  }

  try {
    // Start the real subscription billing 30 days from now, implementing
    // the "free first month, card charged starting next cycle" agreement.
    const startDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

    const subResult = await createSubscription({
      customerCode: data.customer.customer_code,
      planCode: SENTRY_SCAN_PLAN_CODE,
      authorizationCode: data.authorization.authorization_code,
      startDate,
    });

    // Now that payment is verified and the subscription exists, create the
    // actual monitored_sites row -- this is the only place in the codebase
    // that creates one, ensuring monitoring is never active without a
    // backing subscription.
    const { data: site, error: siteError } = await supabase
      .from('monitored_sites')
      .insert({
        domain: pending.domain,
        email: pending.email,
        tier: 'paid',
        frequency_days: 30,
        next_scan_at: new Date().toISOString(),
      })
      .select('id')
      .single();

    if (siteError || !site) {
      console.error('Failed to create monitored_sites row after payment:', siteError);
      return;
    }

    await supabase
      .from('subscriptions')
      .update({
        status: 'active',
        site_id: site.id,
        paystack_customer_code: data.customer.customer_code,
        paystack_subscription_code: subResult.data.subscription_code,
        paystack_authorization_code: data.authorization.authorization_code,
        updated_at: new Date().toISOString(),
      })
      .eq('id', pending.id);
  } catch (err) {
    console.error('Failed to create Paystack subscription after charge:', err);
    await supabase
      .from('subscriptions')
      .update({ status: 'failed', updated_at: new Date().toISOString() })
      .eq('id', pending.id);
  }
}

async function handleSubscriptionFailureOrCancellation(
  supabase: ReturnType<typeof getSupabaseServerClient>,
  data: { subscription_code?: string }
) {
  if (!data.subscription_code) return;

  const { data: sub } = await supabase
    .from('subscriptions')
    .select('id, site_id')
    .eq('paystack_subscription_code', data.subscription_code)
    .maybeSingle();

  if (!sub) return;

  await supabase
    .from('subscriptions')
    .update({ status: 'cancelled', updated_at: new Date().toISOString() })
    .eq('id', sub.id);

  // Pause scanning for this site rather than deleting it, in case they
  // resubscribe later and we want the scan history intact.
  if (sub.site_id) {
    await supabase.from('monitored_sites').update({ active: false }).eq('id', sub.site_id);
  }
}
