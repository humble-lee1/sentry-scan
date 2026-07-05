import { NextRequest, NextResponse } from 'next/server';
import { runScan, normalizeDomain, isValidDomain } from '@/lib/run-scan';
import { getSupabaseServerClient } from '@/lib/supabase-server';

// Scans involve several outbound network calls (SSL handshake, HTTP fetches,
// DNS lookups) so we give this route more time than the Next.js default.
export const maxDuration = 60;

export async function POST(req: NextRequest) {
  let body: { domain?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Invalid request body.' }, { status: 400 });
  }

  const rawInput = body.domain?.trim();
  if (!rawInput) {
    return NextResponse.json({ error: 'Please enter a domain to scan.' }, { status: 400 });
  }

  const domain = normalizeDomain(rawInput);

  if (!isValidDomain(domain)) {
    return NextResponse.json(
      { error: `"${rawInput}" doesn't look like a valid domain. Try something like example.com.` },
      { status: 400 }
    );
  }

  try {
    const report = await runScan(domain);

    // Record every completed scan in scan_history so the homepage counter
    // reflects genuine usage. site_id is null for manual (non-monitored) scans.
    // We wrap in try/catch and never await — a DB write failure should never
    // block the user from seeing their scan result.
    try {
      const supabase = getSupabaseServerClient();
      await supabase.from('scan_history').insert({
        site_id: null,
        score: report.overallScore,
        findings_json: report,
      });
    } catch (dbErr) {
      console.error('Failed to record scan in history (non-fatal):', dbErr);
    }

    return NextResponse.json(report);
  } catch (err) {
    console.error('Scan failed:', err);
    return NextResponse.json(
      { error: 'The scan could not be completed. Please try again in a moment.' },
      { status: 500 }
    );
  }
}
