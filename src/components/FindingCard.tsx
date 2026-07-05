'use client';

import { useState } from 'react';
import { Finding } from '@/lib/types';
import SeverityBadge from './SeverityBadge';

export default function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const isPass = finding.severity === 'pass';

  return (
    <div className={`border rounded-md p-4 sm:p-5 ${isPass ? 'border-line/60' : 'border-line'} bg-panel`}>
      <div className="flex items-start justify-between gap-3">
        <h4 className="text-sm sm:text-base text-paper font-medium leading-snug">{finding.title}</h4>
        <SeverityBadge severity={finding.severity} />
      </div>

      <p className="mt-2 text-sm text-muted leading-relaxed">{finding.summary}</p>

      {!isPass && (
        <p className="mt-3 text-sm leading-relaxed">
          <span className="font-mono text-xs text-signal tracking-wide">FIX → </span>
          <span className="text-paper/90">{finding.recommendation}</span>
        </p>
      )}

      {finding.evidence && (
        <div className="mt-3">
          <button
            onClick={() => setOpen(!open)}
            className="text-xs font-mono text-muted hover:text-signal transition-colors"
            aria-expanded={open}
          >
            {open ? '▾ hide technical detail' : '▸ show technical detail'}
          </button>
          {open && (
            <pre className="mt-2 text-xs font-mono text-muted bg-ink border border-line rounded p-3 overflow-x-auto whitespace-pre-wrap break-all">
              {finding.evidence}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}
