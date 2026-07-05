import { ScanReport, Finding } from './types';

export interface ScanComparison {
  newFindings: Finding[];
  resolvedFindings: Finding[];
}

/**
 * Compares two scan reports and identifies which non-passing findings are
 * new (present now, absent before) versus resolved (present before, absent now).
 * Uses Finding.id for matching, since ids are stable per check (e.g. "ssl-expired").
 */
export function compareScans(previous: ScanReport | null, current: ScanReport): ScanComparison {
  if (!previous) {
    // First-ever scan for this site — nothing to compare against, so nothing
    // is "new" in the delta sense (it's all just the baseline).
    return { newFindings: [], resolvedFindings: [] };
  }

  const isActionable = (f: Finding) => f.severity !== 'pass' && f.severity !== 'info';

  const previousIds = new Set(
    previous.categories.flatMap((c) => c.findings.filter(isActionable).map((f) => f.id))
  );
  const currentFindings = current.categories.flatMap((c) => c.findings.filter(isActionable));
  const currentIds = new Set(currentFindings.map((f) => f.id));

  const newFindings = currentFindings.filter((f) => !previousIds.has(f.id));
  const resolvedFindings = previous.categories
    .flatMap((c) => c.findings.filter(isActionable))
    .filter((f) => !currentIds.has(f.id));

  return { newFindings, resolvedFindings };
}
