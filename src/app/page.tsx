import ScanForm from '@/components/ScanForm';
import ScanCounter from '@/components/ScanCounter';

const CHECKS = [
  {
    n: '01',
    title: 'SSL & encryption',
    body: 'Certificate validity, expiry, and protocol strength — the same thing your browser checks before showing the padlock.',
  },
  {
    n: '02',
    title: 'Security headers',
    body: 'The instructions your server gives browsers to prevent clickjacking, script injection, and data leaks.',
  },
  {
    n: '03',
    title: 'Email & domain spoofing risk',
    body: 'SPF, DKIM, and DMARC — without these, anyone can send email that looks like it came from your business.',
  },
  {
    n: '04',
    title: 'Exposed files & paths',
    body: 'Checks for leaked .env files, .git folders, and backups sitting in public view — common, and very costly.',
  },
  {
    n: '05',
    title: 'Outdated software',
    body: 'Flags publicly visible CMS versions and risky defaults like exposed XML-RPC on WordPress sites.',
  },
];

export default function Home() {
  return (
    <main className="relative overflow-hidden">
      {/* Ambient scanline texture */}
      <div className="pointer-events-none absolute inset-0 bg-scan opacity-50" />

      <section className="relative px-6 pt-24 pb-20 sm:pt-32 sm:pb-28 max-w-5xl mx-auto">
        <div className="flex items-center gap-2 text-signal font-mono text-xs tracking-[0.2em] uppercase mb-6">
          <span className="inline-block w-2 h-2 rounded-full bg-signal cursor-blink" />
          Sentry Scan
        </div>

        <h1 className="font-mono text-3xl sm:text-5xl leading-tight text-paper max-w-3xl text-glow">
          Find out what attackers would see
          <span className="text-signal">_</span>
        </h1>

        <p className="mt-5 max-w-xl text-muted text-base sm:text-lg leading-relaxed">
          Most small business websites carry the same handful of preventable
          weaknesses. Enter a domain below and get a plain-English report —
          no security background required.
        </p>

        <div className="mt-10">
          <ScanForm />
          <ScanCounter />
        </div>
      </section>

      <section className="relative px-6 pb-24 max-w-5xl mx-auto">
        <div className="border-t border-line pt-12">
          <p className="font-mono text-xs tracking-[0.2em] uppercase text-muted mb-8">
            What gets checked
          </p>
          <div className="grid gap-px bg-line sm:grid-cols-2">
            {CHECKS.map((c) => (
              <div key={c.n} className="bg-ink p-6 sm:p-7">
                <div className="flex items-baseline gap-3 mb-2">
                  <span className="font-mono text-sm text-signalDim">{c.n}</span>
                  <h3 className="font-mono text-base text-paper">{c.title}</h3>
                </div>
                <p className="text-sm text-muted leading-relaxed">{c.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <footer className="relative px-6 pb-12 max-w-5xl mx-auto">
        <p className="text-xs text-muted font-mono border-t border-line pt-6">
          Sentry Scan checks publicly visible information only — the same way a
          stranger browsing your website could. It does not access private
          data or attempt to log in anywhere.
        </p>
      </footer>
    </main>
  );
}
