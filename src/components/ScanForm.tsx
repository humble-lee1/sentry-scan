'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';

export default function ScanForm() {
  const [domain, setDomain] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    const trimmed = domain.trim();
    if (!trimmed) {
      setError('Enter a domain to scan.');
      return;
    }

    setLoading(true);
    const clean = trimmed.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    router.push(`/scan?domain=${encodeURIComponent(clean)}`);
  }

  return (
    <form onSubmit={handleSubmit} className="w-full max-w-2xl">
      <div className="flex items-stretch border border-line bg-panel rounded-md overflow-hidden focus-within:border-signal transition-colors">
        <span className="flex items-center pl-4 pr-2 text-signal font-mono text-sm select-none">
          scan&gt;
        </span>
        <input
          type="text"
          inputMode="url"
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="yourbusiness.com"
          aria-label="Domain to scan"
          className="flex-1 bg-transparent py-4 pr-2 font-mono text-base text-paper placeholder:text-muted outline-none"
        />
        <button
          type="submit"
          disabled={loading}
          className="px-5 sm:px-7 bg-signal text-ink font-mono font-medium text-sm tracking-wide hover:bg-paper transition-colors disabled:opacity-60"
        >
          {loading ? 'STARTING…' : 'RUN SCAN'}
        </button>
      </div>
      {error && (
        <p role="alert" className="mt-3 text-sm text-crit font-mono">
          {error}
        </p>
      )}
      <p className="mt-3 text-xs text-muted font-mono">
        No signup. No card. Free report in under a minute.
      </p>
    </form>
  );
}
