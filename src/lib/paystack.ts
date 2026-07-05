/**
 * Minimal wrapper around the Paystack REST API. We use plain fetch rather
 * than an SDK since Paystack's API is small and well-documented, and this
 * avoids pulling in an extra dependency for a handful of endpoints.
 */

const PAYSTACK_BASE_URL = 'https://api.paystack.co';

function getSecretKey(): string {
  const key = process.env.PAYSTACK_SECRET_KEY;
  if (!key) throw new Error('Missing PAYSTACK_SECRET_KEY environment variable.');
  return key;
}

async function paystackFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(`${PAYSTACK_BASE_URL}${path}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${getSecretKey()}`,
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });

  const data = await res.json();
  if (!res.ok || data.status === false) {
    throw new Error(data.message ?? `Paystack request failed: ${res.status}`);
  }
  return data;
}

/**
 * Initializes a Paystack transaction for the purpose of collecting a card
 * on file and starting a subscription. The customer is redirected to the
 * returned authorization_url to enter their card details.
 */
export async function initializeTransaction(params: {
  email: string;
  reference: string;
  callbackUrl: string;
  metadata?: Record<string, unknown>;
}) {
  return paystackFetch<{
    data: { authorization_url: string; access_code: string; reference: string };
  }>('/transaction/initialize', {
    method: 'POST',
    body: JSON.stringify({
      email: params.email,
      // A small verification charge to capture a reusable card authorization.
      // Paystack requires amounts to meet a minimum per payment channel (e.g.
      // bank transfer's minimum is NGN 100 = 10000 kobo); amounts below that
      // can cause "no active channel" errors since no channel can process
      // a sub-minimum amount. NGN 100 is comfortably above every channel's floor.
      amount: 10000,
      reference: params.reference,
      callback_url: params.callbackUrl,
      metadata: params.metadata,
    }),
  });
}

export async function verifyTransaction(reference: string) {
  return paystackFetch<{
    data: {
      status: string;
      customer: { customer_code: string; email: string };
      authorization: { authorization_code: string; reusable: boolean };
    };
  }>(`/transaction/verify/${reference}`);
}

/**
 * Creates a subscription on the given plan for a customer, starting on a
 * future date (used to implement the "first charge after 30 days" trial).
 */
export async function createSubscription(params: {
  customerCode: string;
  planCode: string;
  authorizationCode: string;
  startDate: string; // ISO 8601
}) {
  return paystackFetch<{ data: { subscription_code: string; status: string } }>('/subscription', {
    method: 'POST',
    body: JSON.stringify({
      customer: params.customerCode,
      plan: params.planCode,
      authorization: params.authorizationCode,
      start_date: params.startDate,
    }),
  });
}

export const SENTRY_SCAN_PLAN_CODE = 'PLN_qba8v8iniahn84l';
