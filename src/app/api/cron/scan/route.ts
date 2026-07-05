import { NextRequest, NextResponse } from 'next/server';
import { getSupabaseServerClient } from '@/lib/supabase-server';
import { runScan } from '@/lib/run-scan';
import { compareScans } from '@/lib/compare-scans';
import { sendMonitoringEmail } from '@/lib/email';
import { ScanReport } from '@/lib/types';

// Scanning multiple sites sequentially can take a while; give this route
// the maximum duration available on Vercel's free (Hobby) plan.
export const maxDuration = 60;

interface MonitoredSiteRow {
  id: string;
  domain: string;
  email: string;
  tier: 'free' | 'paid';
  frequency_days: number;
}

export async function GET(req: NextRequest) {
  // Protect this endpoint: only Vercel's cron scheduler (or someone with the
  // secret) should be able to trigger scans. Without this, anyone who finds
  // the URL could spam scans against arbitrary domains using your server.
  const authHeader = req.headers.get('authorization');
  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const supabase = getSupabaseServerClient();

  const { data: dueSites, error: fetchError } = await supabase
    .from('monitored_sites')
    .select('id, domain, email, tier, frequency_days')
    .eq('active', true)
    .lte('next_scan_at', new Date().toISOString())
    .limit(50); // process in batches so one run can't take forever

  if (fetchError) {
    console.error('Failed to fetch due sites:', fetchError);
    return NextResponse.json({ error: 'Database error' }, { status: 500 });
  }

  const results: { domain: string; status: string }[] = [];

  for (const site of (dueSites ?? []) as MonitoredSiteRow[]) {
    try {
      const result = await processSite(supabase, site, req);
      results.push({ domain: site.domain, status: result });
    } catch (err) {
      console.error(`Failed to process ${site.domain}:`, err);
      results.push({ domain: site.domain, status: 'error' });
    }
  }

  return NextResponse.json({ processed: results.length, results });
}

async function processSite(
  supabase: ReturnType<typeof getSupabaseServerClient>,
  site: MonitoredSiteRow,
  req: NextRequest
): Promise<string> {
  // Run the actual scan using the same engine the live site uses.
  const report: ScanReport = await runScan(site.domain);

  // Fetch the most recent prior scan for this site, if any, to compare against.
  const { data: previousScans } = await supabase
    .from('scan_history')
    .select('findings_json, score')
    .eq('site_id', site.id)
    .order('scanned_at', { ascending: false })
    .limit(1);

  const previousReport: ScanReport | null = previousScans?.[0]?.findings_json ?? null;
  const { newFindings, resolvedFindings } = compareScans(previousReport, report);

  // Store this scan in history regardless of whether anything changed,
  // so future comparisons always have an accurate "last scan" to diff against.
  await supabase.from('scan_history').insert({
    site_id: site.id,
    score: report.overallScore,
    findings_json: report,
  });

  // Schedule the next scan based on this site's tier/frequency.
  const nextScanAt = new Date(Date.now() + site.frequency_days * 24 * 60 * 60 * 1000);
  await supabase
    .from('monitored_sites')
    .update({ next_scan_at: nextScanAt.toISOString() })
    .eq('id', site.id);

  // Only send an email if this isn't the very first scan, or if there's
  // something meaningful to report. Sending an email for the initial
  // baseline scan would be noise — the person just saw this result live.
  const isFirstScan = previousReport === null;
  if (isFirstScan) {
    return 'baseline-scan-no-email';
  }

  const origin = new URL(req.url).origin;
  const reportUrl = `${origin}/scan?domain=${encodeURIComponent(site.domain)}`;

  await sendMonitoringEmail({
    to: site.email,
    domain: site.domain,
    score: report.overallScore,
    previousScore: previousScans?.[0]?.score ?? null,
    newIssuesCount: newFindings.length,
    resolvedIssuesCount: resolvedFindings.length,
    reportUrl,
  });

  return 'scanned-and-emailed';
}
