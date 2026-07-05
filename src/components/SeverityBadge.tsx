import { Severity } from '@/lib/types';

const SEVERITY_STYLES: Record<Severity, { label: string; classes: string }> = {
  critical: { label: 'CRITICAL', classes: 'bg-crit/15 text-crit border-crit/40' },
  high: { label: 'HIGH', classes: 'bg-crit/10 text-crit border-crit/30' },
  medium: { label: 'MEDIUM', classes: 'bg-warn/15 text-warn border-warn/40' },
  low: { label: 'LOW', classes: 'bg-warn/10 text-warn border-warn/25' },
  info: { label: 'INFO', classes: 'bg-muted/15 text-muted border-muted/30' },
  pass: { label: 'PASS', classes: 'bg-signal/10 text-signal border-signal/30' },
};

export default function SeverityBadge({ severity }: { severity: Severity }) {
  const style = SEVERITY_STYLES[severity];
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded border font-mono text-[11px] tracking-wider ${style.classes}`}
    >
      {style.label}
    </span>
  );
}
