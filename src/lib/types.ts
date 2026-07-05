export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'pass';

export interface Finding {
  id: string;
  category: 'ssl' | 'headers' | 'dns-email' | 'exposure' | 'cms';
  title: string;
  severity: Severity;
  summary: string;       // plain-English, one or two sentences
  recommendation: string; // what to do about it
  evidence?: string;      // raw technical detail, shown collapsed
}

export interface CategoryResult {
  category: Finding['category'];
  label: string;
  findings: Finding[];
}

export interface ScanReport {
  domain: string;
  scannedAt: string;
  durationMs: number;
  overallScore: number; // 0-100
  categories: CategoryResult[];
  errors: string[]; // non-fatal errors (e.g. a check timed out)
}

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 0,
  pass: 0,
};

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info', 'pass'];
