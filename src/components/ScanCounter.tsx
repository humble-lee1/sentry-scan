'use client';

import { useEffect, useState } from 'react';

function useCountUp(target: number, duration = 1200) {
  const [value, setValue] = useState(0);

  useEffect(() => {
    if (target === 0) return;
    const start = Date.now();
    const tick = () => {
      const elapsed = Date.now() - start;
      const progress = Math.min(elapsed / duration, 1);
      // Ease out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      setValue(Math.floor(eased * target));
      if (progress < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, [target, duration]);

  return value;
}

export default function ScanCounter() {
  const [total, setTotal] = useState<number | null>(null);

  useEffect(() => {
    fetch('/api/stats')
      .then((r) => r.json())
      .then((d) => setTotal(d.count ?? 0))
      .catch(() => setTotal(null));
  }, []);

  const displayValue = useCountUp(total ?? 0);

  if (total === null) return null; // don't render until we have real data

  return (
    <div className="mt-10 inline-flex items-center gap-4 border border-line rounded-md px-5 py-3 bg-panel">
      <div className="text-center">
        <p className="font-mono text-2xl text-signal text-glow font-medium">
          {displayValue.toLocaleString()}
        </p>
        <p className="font-mono text-xs text-muted tracking-widest uppercase mt-0.5">
          security reports generated
        </p>
      </div>
      <div className="w-px h-8 bg-line" />
      <div className="flex items-center gap-2">
        <span className="inline-block w-1.5 h-1.5 rounded-full bg-signal animate-pulse" />
        <span className="font-mono text-xs text-muted">live</span>
      </div>
    </div>
  );
}
