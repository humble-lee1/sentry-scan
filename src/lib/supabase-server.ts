import { createClient } from '@supabase/supabase-js';

/**
 * Server-only Supabase client, using the SECRET key.
 *
 * IMPORTANT: never import this file from a Client Component ('use client').
 * The secret key bypasses Row Level Security entirely, so it must only ever
 * run on the server (API routes, server components). Next.js will throw a
 * build error if an env var without the NEXT_PUBLIC_ prefix is referenced
 * from client code, which gives us a safety net here.
 */
export function getSupabaseServerClient() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;

  if (!url || !secretKey) {
    throw new Error(
      'Missing Supabase environment variables. Check that .env.local has NEXT_PUBLIC_SUPABASE_URL and SUPABASE_SECRET_KEY set.'
    );
  }

  return createClient(url, secretKey, {
    auth: {
      persistSession: false, // server-side usage, no browser session to persist
    },
  });
}
