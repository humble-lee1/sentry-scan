'use client';

import { Suspense, useEffect, useState } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { ScanReport } from '@/lib/types';
import ScanningState from '@/components/ScanningState';
import ScoreGauge from '@/components/ScoreGauge';
import CategorySection from '@/components/CategorySection';
import Link from 'next/link';
import MonitorForm from '@/components/MonitorForm';

export default function ScanPage() {
  return (
    <Suspense fallback={<ScanningState domain="" />}>
      <ScanPageInner />
    </Suspense>
  );
}

function ScanPageInner() {
  const params = useSearchParams();
  const router = useRouter();
  const domain = params.get('domain') ?? '';

  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!domain) {
      router.replace('/');
      return;
    }

    let cancelled = false;
    setLoading(true);
    setError(null);
    setReport(null);

    fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain }),
    })
      .then(async (res) => {
        const data = await res.json();
        if (cancelled) return;
        if (!res.ok) {
          setError(data.error ?? 'Something went wrong.');
        } else {
          setReport(data);
        }
      })
      .catch(() => {
        if (!cancelled) setError('Could not reach the scan service. Check your connection and try again.');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [domain, router]);

  if (loading) {
    return <ScanningState domain={domain} />;
  }

  if (error) {
    return (
      <div className="max-w-2xl mx-auto px-6 py-24 text-center">
        <p className="font-mono text-crit text-sm mb-3">SCAN FAILED</p>
        <p className="text-paper mb-8">{error}</p>
        <Link href="/" className="font-mono text-sm text-signal hover:underline">
          ← try another domain
        </Link>
      </div>
    );
  }

  if (!report) return null;

  const issueCount = report.categories.reduce(
    (sum, c) => sum + c.findings.filter((f) => f.severity !== 'pass' && f.severity !== 'info').length,
    0
  );

  return (
    <main className="px-6 py-16 sm:py-20 max-w-3xl mx-auto">
      <Link href="/" className="font-mono text-xs text-muted hover:text-signal transition-colors">
        ← new scan
      </Link>

      <div className="mt-6 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-6 border-b border-line pb-8">
        <div>
          <p className="font-mono text-xs tracking-[0.2em] uppercase text-muted mb-1">Report for</p>
          <h1 className="font-mono text-2xl text-paper text-glow">{report.domain}</h1>
          <p className="text-xs text-muted mt-2">
            {issueCount} issue{issueCount !== 1 ? 's' : ''} found · scanned just now
          </p>
        </div>
        <ScoreGauge score={report.overallScore} />
      </div>

      <div className="mt-10">
        {report.categories.map((cat) => (
          <CategorySection key={cat.category} category={cat} />
        ))}
      </div>

      {report.errors.length > 0 && (
        <p className="text-xs text-muted font-mono mt-4">
          Note: some checks did not complete and were skipped.
        </p>
      )}

      <MonitorForm domain={report.domain} />
    </main>
  );
}
