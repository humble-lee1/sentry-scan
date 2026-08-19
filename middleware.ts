/**
 * RATE LIMITING MIDDLEWARE
 * Save this file as: middleware.ts (at the project root, same level as package.json)
 *
 * Limits each IP to 10 scan requests per minute. Uses Next.js Edge Middleware
 * so it runs before any API route, with zero added latency for normal users.
 * In-memory store resets on each Vercel function cold start -- sufficient for
 * abuse prevention without needing Redis or an external store at this scale.
 */

import { NextRequest, NextResponse } from 'next/server';

const WINDOW_MS = 60_000; // 1 minute
const MAX_REQUESTS = 10; // scans per IP per minute

// Simple in-memory store: Map<ip, { count, windowStart }>
// Note: on Vercel this lives in Edge Runtime memory, which is per-region
// and resets on cold starts -- acceptable for our use case.
const store = new Map<string, { count: number; windowStart: number }>();

function getClientIp(req: NextRequest): string {
  return (
    req.headers.get('x-forwarded-for')?.split(',')[0].trim() ??
    req.headers.get('x-real-ip') ??
    'unknown'
  );
}

export function middleware(req: NextRequest) {
  // Only rate-limit the scan endpoint -- other routes are fine unrestricted.
  if (!req.nextUrl.pathname.startsWith('/api/scan')) {
    return NextResponse.next();
  }

  const ip = getClientIp(req);
  const now = Date.now();
  const entry = store.get(ip);

  if (!entry || now - entry.windowStart > WINDOW_MS) {
    // New window
    store.set(ip, { count: 1, windowStart: now });
    return NextResponse.next();
  }

  if (entry.count >= MAX_REQUESTS) {
    return NextResponse.json(
      {
        error: `Too many scans. Please wait a minute before scanning again.`,
      },
      {
        status: 429,
        headers: {
          'Retry-After': String(
            Math.ceil((WINDOW_MS - (now - entry.windowStart)) / 1000)
          ),
        },
      }
    );
  }

  entry.count++;
  return NextResponse.next();
}

export const config = {
  matcher: '/api/scan',
};
