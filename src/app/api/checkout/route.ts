import { NextRequest, NextResponse } from 'next/server';
import { getSupabaseServerClient } from '@/lib/supabase-server';
import { initializeTransaction } from '@/lib/paystack';
import { normalizeDomain, isValidDomain } from '@/lib/run-scan';

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export async function POST(req: NextRequest) {
  let body: { domain?: string; email?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Invalid request body.' }, { status: 400 });
  }

  const rawDomain = body.domain?.trim();
  const email = body.email?.trim().toLowerCase();

  if (!rawDomain || !email) {
    return NextResponse.json({ error: 'Domain and email are both required.' }, { status: 400 });
  }
  if (!EMAIL_PATTERN.test(email)) {
    return NextResponse.json({ error: "That email address doesn't look valid." }, { status: 400 });
  }

  const domain = normalizeDomain(rawDomain);
  if (!isValidDomain(domain)) {
    return NextResponse.json({ error: `"${rawDomain}" doesn't look like a valid domain.` }, { status: 400 });
  }

  const supabase = getSupabaseServerClient();

  // Create a pending subscription record up front, so the webhook (which
  // arrives later, out of band) has somewhere to record the outcome even
  // if the person closes the tab mid-checkout.
  const reference = `secaudit_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;

  const { data: subscription, error: insertError } = await supabase
    .from('subscriptions')
    .insert({ email, domain, status: 'pending' })
    .select('id')
    .single();

  if (insertError || !subscription) {
    console.error('Failed to create pending subscription:', insertError);
    return NextResponse.json({ error: 'Could not start checkout. Please try again.' }, { status: 500 });
  }

  const origin = new URL(req.url).origin;

  try {
    const result = await initializeTransaction({
      email,
      reference,
      callbackUrl: `${origin}/scan?domain=${encodeURIComponent(domain)}&checkout=complete`,
      metadata: { subscriptionId: subscription.id, domain },
    });

    // Store the reference so the webhook can match this transaction back
    // to the pending subscription row.
    await supabase
      .from('subscriptions')
      .update({ paystack_subscription_code: reference })
      .eq('id', subscription.id);

    return NextResponse.json({ checkoutUrl: result.data.authorization_url });
  } catch (err) {
    console.error('Paystack initialization failed:', err);
    await supabase.from('subscriptions').update({ status: 'failed' }).eq('id', subscription.id);
    return NextResponse.json({ error: 'Could not start checkout. Please try again.' }, { status: 500 });
  }
}
