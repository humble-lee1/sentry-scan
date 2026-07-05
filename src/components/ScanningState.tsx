'use client';

import { useEffect, useState } from 'react';

const STEPS = [
  'resolving domain…',
  'checking SSL certificate…',
  'inspecting security headers…',
  'checking SPF / DKIM / DMARC…',
  'probing for exposed files…',
  'fingerprinting CMS…',
  'compiling report…',
];

export default function ScanningState({ domain }: { domain: string }) {
  const [stepIndex, setStepIndex] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setStepIndex((i) => (i < STEPS.length - 1 ? i + 1 : i));
    }, 900);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="max-w-2xl mx-auto px-6 py-24">
      <div className="flex items-center gap-2 text-signal font-mono text-xs tracking-[0.2em] uppercase mb-8">
        <span className="inline-block w-2 h-2 rounded-full bg-signal cursor-blink" />
        scanning {domain}
      </div>
      <div className="space-y-2 font-mono text-sm">
        {STEPS.map((step, i) => (
          <div
            key={step}
            className={`flex items-center gap-3 transition-opacity duration-300 ${
              i <= stepIndex ? 'opacity-100' : 'opacity-30'
            }`}
          >
            <span className="text-signal w-4">{i < stepIndex ? '✓' : i === stepIndex ? '›' : '·'}</span>
            <span className={i < stepIndex ? 'text-muted' : 'text-paper'}>{step}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
