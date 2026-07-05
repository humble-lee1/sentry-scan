import { Finding } from '../types';

interface HeaderRule {
  header: string;
  title: string;
  severity: Finding['severity'];
  summary: string;
  recommendation: string;
  validate?: (value: string) => boolean; // optional: returns true if the value itself is also OK
  invalidSummary?: string;
}

const HEADER_RULES: HeaderRule[] = [
  {
    header: 'strict-transport-security',
    title: 'Missing HSTS header (Strict-Transport-Security)',
    severity: 'high',
    summary:
      'Without this header, browsers may connect to the site over an insecure HTTP connection before being redirected, leaving an opening for attackers on public networks (e.g. shared wifi) to intercept traffic.',
    recommendation:
      'Add a "Strict-Transport-Security" header (e.g. "max-age=31536000; includeSubDomains") so browsers always connect via HTTPS.',
  },
  {
    header: 'content-security-policy',
    title: 'Missing Content-Security-Policy header',
    severity: 'medium',
    summary:
      'Without a content security policy, the site has fewer protections against attackers injecting malicious scripts (cross-site scripting attacks) into pages.',
    recommendation:
      'Define a Content-Security-Policy header that restricts which sources of scripts, styles, and other content the browser is allowed to load.',
  },
  {
    header: 'x-frame-options',
    title: 'Missing X-Frame-Options header',
    severity: 'medium',
    summary:
      "Without this header, other websites can embed this site inside an invisible frame, which can be used to trick visitors into clicking something they didn't intend to (a \"clickjacking\" attack).",
    recommendation:
      'Add an "X-Frame-Options: SAMEORIGIN" header, or use a Content-Security-Policy "frame-ancestors" directive.',
  },
  {
    header: 'x-content-type-options',
    title: 'Missing X-Content-Type-Options header',
    severity: 'low',
    summary:
      'Without this header, some browsers may try to guess the type of a file rather than trusting what the server says it is, which can be abused in certain attacks.',
    recommendation: 'Add an "X-Content-Type-Options: nosniff" header.',
  },
  {
    header: 'referrer-policy',
    title: 'Missing Referrer-Policy header',
    severity: 'low',
    summary:
      'Without this header, the full URL a visitor came from (which may include sensitive query parameters) may be leaked to third-party sites linked from this page.',
    recommendation: 'Add a "Referrer-Policy" header, e.g. "strict-origin-when-cross-origin".',
  },
  {
    header: 'permissions-policy',
    title: 'Missing Permissions-Policy header',
    severity: 'info',
    summary:
      'This header lets a site explicitly control which browser features (camera, microphone, location, etc.) pages are allowed to use. It is missing here.',
    recommendation: 'Add a Permissions-Policy header restricting features the site does not need.',
  },
];

export async function checkHeaders(domain: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  let res: Response;
  let usedProtocol: 'https' | 'http' = 'https';

  try {
    res = await fetchWithTimeout(`https://${domain}/`, 6000, 'follow');
  } catch (httpsErr) {
    // Fall back to HTTP only to still gather header info, but this itself is a finding.
    // Use 'manual' redirect here: if the site redirects HTTP -> HTTPS, but HTTPS is
    // actually broken (the reason we're in this fallback at all), following the
    // redirect would just hang again and we'd lose the chance to inspect headers.
    try {
      res = await fetchWithTimeout(`http://${domain}/`, 8000, 'manual');
      usedProtocol = 'http';
      findings.push({
        id: 'headers-no-https',
        category: 'headers',
        title: 'Site is not reachable over HTTPS',
        severity: 'critical',
        summary: 'The site could only be reached over plain HTTP, not HTTPS. Any data submitted by visitors (including passwords) could be intercepted.',
        recommendation: 'Enable HTTPS and redirect all HTTP traffic to it.',
      });
    } catch (httpErr) {
      findings.push({
        id: 'headers-unreachable',
        category: 'headers',
        title: 'Site did not respond',
        severity: 'info',
        summary: 'The header scan could not reach the site over HTTP or HTTPS.',
        recommendation: 'Confirm the domain is correct and the server is online.',
        evidence: String(httpErr),
      });
      return findings;
    }
  }

  const headers = res.headers;

  for (const rule of HEADER_RULES) {
    const value = headers.get(rule.header);
    if (!value) {
      findings.push({
        id: `headers-missing-${rule.header}`,
        category: 'headers',
        title: rule.title,
        severity: rule.severity,
        summary: rule.summary,
        recommendation: rule.recommendation,
      });
    } else {
      findings.push({
        id: `headers-present-${rule.header}`,
        category: 'headers',
        title: `${prettyHeaderName(rule.header)} header is set`,
        severity: 'pass',
        summary: `This security header is present.`,
        recommendation: 'No action needed.',
        evidence: `${rule.header}: ${value}`,
      });
    }
  }

  // Server header / version disclosure
  const serverHeader = headers.get('server');
  if (serverHeader && /\d/.test(serverHeader)) {
    findings.push({
      id: 'headers-server-version-disclosed',
      category: 'headers',
      title: 'Server software version is exposed',
      severity: 'low',
      summary: `The server is revealing detailed version information ("${serverHeader}"), which can help an attacker target known vulnerabilities for that exact version.`,
      recommendation: 'Configure the web server to suppress or generalize the "Server" response header.',
      evidence: `Server: ${serverHeader}`,
    });
  }

  if (usedProtocol === 'http') {
    // already flagged above
  }

  return findings;
}

function prettyHeaderName(header: string): string {
  return header
    .split('-')
    .map((w) => w[0].toUpperCase() + w.slice(1))
    .join('-');
}

async function fetchWithTimeout(
  url: string,
  timeoutMs: number,
  redirect: 'follow' | 'manual' = 'follow'
): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      redirect,
      headers: {
        'User-Agent': 'SecAuditBot/0.1 (+https://example.com/about-this-scanner)',
      },
    });
    return res;
  } finally {
    clearTimeout(timeout);
  }
}
