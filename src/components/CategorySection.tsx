import { CategoryResult } from '@/lib/types';
import FindingCard from './FindingCard';
import { SEVERITY_ORDER } from '@/lib/types';

export default function CategorySection({ category }: { category: CategoryResult }) {
  if (category.findings.length === 0) return null;

  const sorted = [...category.findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  const worst = sorted[0]?.severity;
  const allPass = sorted.every((f) => f.severity === 'pass' || f.severity === 'info');

  return (
    <section className="mb-8">
      <div className="flex items-center gap-3 mb-4">
        <h3 className="font-mono text-sm tracking-[0.15em] uppercase text-paper">{category.label}</h3>
        <span className={`h-px flex-1 ${allPass ? 'bg-signal/20' : 'bg-line'}`} />
        <span className="text-xs font-mono text-muted">{sorted.length} check{sorted.length !== 1 ? 's' : ''}</span>
      </div>
      <div className="space-y-3">
        {sorted.map((f) => (
          <FindingCard key={f.id} finding={f} />
        ))}
      </div>
    </section>
  );
}
