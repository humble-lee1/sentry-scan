import { CategoryResult, Finding, ScanReport, SEVERITY_WEIGHT } from './types';
import { checkSsl } from './scanners/ssl';
import { checkHeaders } from './scanners/headers';
import { checkDnsEmail } from './scanners/dns-email';
import { checkExposure } from './scanners/exposure';
import { checkCms } from './scanners/cms';
import { detectBaseUrl } from './scanners/detect-protocol';

const CATEGORY_LABELS: Record<Finding['category'], string> = {
  ssl: 'SSL / Encryption',
  headers: 'HTTP Security Headers',
  'dns-email': 'Email & Domain Security',
  exposure: 'Exposed Files & Paths',
  cms: 'CMS & Software',
};

/**
 * Strips protocol, paths, and trailing slashes from user input so
 * "https://example.com/" and "example.com" behave identically.
 */
export function normalizeDomain(input: string): string {
  let d = input.trim().toLowerCase();
  d = d.replace(/^https?:\/\//, '');
  d = d.replace(/\/.*$/, '');
  d = d.replace(/^www\./, '');
  return d;
}

const BLOCKED_HOSTNAMES = new Set([
  'localhost', 'local', 'internal', 'intranet', 'corp', 'metadata', 'instance-data',
]);

const BLOCKED_PATTERNS = [
  /^169\.254\./, /^100\.64\./, /^10\./, /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./, /^127\./, /^0\./, /^::1$/, /^fc00:/i, /^fe80:/i,
];

export function isValidDomain(domain: string): boolean {
  const pattern = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})+$/i;
  if (!pattern.test(domain) || domain.length > 253) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) return false;
  const parts = domain.toLowerCase().split('.');
  for (const part of parts) {
    if (BLOCKED_HOSTNAMES.has(part)) return false;
  }
  if (BLOCKED_PATTERNS.some((p) => p.test(domain))) return false;
  return true;
}

export async function isDomainSafeToScan(domain: string): Promise<boolean> {
  try {
    const { promises: dns } = await import('dns');
    const addresses = await dns.resolve4(domain);
    for (const ip of addresses) {
      if (BLOCKED_PATTERNS.some((p) => p.test(ip))) {
        console.warn(\`SSRF attempt blocked: \${domain} resolved to \${ip}\`);
        return false;
      }
    }
    return true;
  } catch {
    return true;
  }
}

export async function runScan(rawInput: string): Promise<ScanReport> {
  const domain = normalizeDomain(rawInput);
  const startedAt = Date.now();
  const errors: string[] = [];

  // Determine once whether the site responds on HTTPS or only HTTP, so the
  // exposure and CMS checks probe the protocol that actually works instead
  // of silently no-op'ing against a dead https:// endpoint.
  const protocolInfo = await detectBaseUrl(domain);

  const labels: Finding['category'][] = ['ssl', 'headers', 'dns-email', 'exposure', 'cms'];
  const allFindings: Finding[] = [];

  if (!protocolInfo) {
    // The domain is unreachable over both protocols. Running the page-fetching
    // checks (headers, exposure, cms) against it would only produce misleading
    // "PASS" results for checks that never actually executed, so we skip them
    // and report one clear, honest finding instead. DNS-based checks (SPF/DMARC)
    // and the raw SSL socket check still run independently, since they use their
    // own connection methods and may still surface useful information.
    const results = await Promise.allSettled([checkSsl(domain), checkDnsEmail(domain)]);
    const partialLabels: Finding['category'][] = ['ssl', 'dns-email'];
    results.forEach((result, idx) => {
      if (result.status === 'fulfilled') {
        allFindings.push(...result.value);
      } else {
        errors.push(`${partialLabels[idx]} check failed: ${result.reason}`);
      }
    });

    allFindings.push({
      id: 'global-unreachable',
      category: 'exposure',
      title: 'Site could not be reached over HTTP or HTTPS',
      severity: 'critical',
      summary: `Neither https://${domain} nor http://${domain} responded, so the header, exposed-file, and CMS checks could not run. The domain may be down, misspelled, or blocking automated requests.`,
      recommendation: 'Confirm the domain is correct and that the server is online and accessible from the public internet, then re-run the scan.',
    });
  } else {
    const results = await Promise.allSettled([
      checkSsl(domain),
      checkHeaders(domain),
      checkDnsEmail(domain),
      checkExposure(domain, protocolInfo.baseUrl),
      checkCms(domain, protocolInfo.baseUrl),
    ]);

    results.forEach((result, idx) => {
      if (result.status === 'fulfilled') {
        allFindings.push(...result.value);
      } else {
        errors.push(`${labels[idx]} check failed: ${result.reason}`);
      }
    });
  }

  const categories: CategoryResult[] = labels.map((cat) => ({
    category: cat,
    label: CATEGORY_LABELS[cat],
    findings: allFindings.filter((f) => f.category === cat),
  }));

  const overallScore = computeScore(allFindings);

  return {
    domain,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    overallScore,
    categories,
    errors,
  };
}

function computeScore(findings: Finding[]): number {
  let score = 100;
  for (const f of findings) {
    score -= SEVERITY_WEIGHT[f.severity];
  }
  return Math.max(0, Math.min(100, score));
}
