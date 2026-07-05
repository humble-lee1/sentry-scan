import { Finding } from '../types';

interface ExposureCheck {
  path: string;
  title: string;
  severity: Finding['severity'];
  summary: string;
  recommendation: string;
  // a function to confirm the response actually looks like the real thing,
  // not just a custom 200-OK catch-all page
  confirm?: (body: string, status: number) => boolean;
}

const EXPOSURE_CHECKS: ExposureCheck[] = [
  {
    path: '/.env',
    title: 'Exposed .env file',
    severity: 'critical',
    summary:
      'A ".env" file is publicly accessible. These files commonly contain database passwords, API keys, and other secrets — this is one of the most damaging misconfigurations a website can have.',
    recommendation: 'Remove the .env file from the public web root immediately and rotate any credentials it contained, since they should be considered compromised.',
    // A real .env file is short, plain-text "KEY=value" lines with no HTML.
    // The previous version of this check only looked for the presence of an
    // "=" character, which any HTML page satisfies via attributes like
    // class="..." — this caused false positives on WAF/firewall block pages
    // (e.g. Cloudflare's "Sorry, you have been blocked"), which are themselves
    // full of "=" signs. Real .env content has no HTML tags at all.
    confirm: (body) => {
      const trimmed = body.trim();
      if (trimmed.length === 0 || trimmed.length > 5000) return false;
      if (/<html|<!doctype|<body|<head/i.test(trimmed)) return false; // looks like a real webpage, not a .env file
      const lines = trimmed.split('\n').filter((l) => l.trim().length > 0);
      if (lines.length === 0) return false;
      // Most lines should look like KEY=VALUE or # comments, the actual shape of a .env file.
      const envLikeLines = lines.filter((l) => /^[A-Za-z_][A-Za-z0-9_]*\s*=/.test(l) || l.trim().startsWith('#'));
      return envLikeLines.length / lines.length > 0.6;
    },
  },
  {
    path: '/.git/config',
    title: 'Exposed .git directory',
    severity: 'critical',
    summary:
      'The site\'s ".git" version control folder is publicly accessible, which can expose the entire source code history, including old credentials or sensitive logic.',
    recommendation: 'Block access to the .git directory at the web server level, and avoid deploying it to the public web root in the first place.',
    confirm: (body) => /\[core\]|\[remote/.test(body),
  },
  {
    path: '/wp-admin/',
    title: 'WordPress admin panel is publicly reachable',
    severity: 'low',
    summary: 'The WordPress login page is reachable at its default location. This is common and not a vulnerability by itself, but it is the first thing attackers try.',
    recommendation: 'Consider IP-restricting /wp-admin/, enabling two-factor authentication, and using a login-attempt limiter plugin.',
    // Require an actual WordPress login page marker, not just a 200/401/403 status —
    // many sites return one of those codes for /wp-admin/ on a custom catch-all page
    // even when they don't run WordPress at all (false positive seen on non-WP sites).
    confirm: (body, status) =>
      (status === 200 || status === 401 || status === 403) &&
      /wp-login|wp-admin|loginform|wordpress/i.test(body),
  },
  {
    path: '/phpinfo.php',
    title: 'Exposed phpinfo() output',
    severity: 'high',
    summary:
      'A phpinfo() page is accessible, which reveals detailed server configuration, file paths, and software versions useful to an attacker planning further attacks.',
    recommendation: 'Delete this file from the server.',
    confirm: (body) => /phpinfo\(\)|PHP Version/i.test(body),
  },
  {
    path: '/.htaccess',
    title: 'Exposed .htaccess file',
    severity: 'medium',
    summary: 'The server\'s .htaccess configuration file is publicly readable, which can reveal internal routing rules and security configuration.',
    recommendation: 'Configure the server to deny access to dotfiles.',
    // Require real Apache directive syntax, not just "any short non-empty
    // response" — that loose check previously matched WAF/firewall block
    // pages (which are HTML and routinely under 20,000 chars).
    confirm: (body) => {
      const trimmed = body.trim();
      if (trimmed.length === 0 || trimmed.length > 10000) return false;
      if (/<html|<!doctype|<body/i.test(trimmed)) return false;
      return /RewriteEngine|RewriteRule|RewriteCond|Options |AuthType|Require |ErrorDocument|<IfModule/i.test(trimmed);
    },
  },
  {
    path: '/backup.zip',
    title: 'Common backup filename is accessible',
    severity: 'high',
    summary: 'A file at a common backup filename is publicly downloadable, which could expose an entire copy of the site including any sensitive data.',
    recommendation: 'Remove backup files from the public web root. Store backups outside of any web-accessible directory.',
    confirm: (_body, status) => status === 200,
  },
];

export async function checkExposure(_domain: string, baseUrl: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  // First, establish what a guaranteed-404 page looks like on this server,
  // so we don't mistake a custom "not found" page (status 200) for a real exposure.
  const baseline = await safeFetch(`${baseUrl}/this-path-should-not-exist-${Date.now()}`);

  for (const check of EXPOSURE_CHECKS) {
    const result = await safeFetch(`${baseUrl}${check.path}`);
    if (!result) continue; // network error on this single check; skip silently

    const { status, body } = result;

    if (status === 404) continue;

    // Skip anything that looks like a WAF/firewall block page (e.g.
    // Cloudflare's "Sorry, you have been blocked"). These are real HTML
    // responses, not 404s, so they survive the baseline-similarity check
    // below if the WAF includes a per-request token in its page (which
    // defeats simple length-based comparison) -- but they're never the
    // actual file we're probing for, so we filter them out by content too.
    if (looksLikeWafBlockPage(body)) continue;

    // If this path returns the same status+body shape as our known-bad baseline,
    // it's almost certainly a custom catch-all, not a real exposure.
    if (baseline && status === baseline.status && bodiesLookSimilar(body, baseline.body)) {
      continue;
    }

    const isConfirmed = check.confirm ? check.confirm(body, status) : status === 200;
    if (!isConfirmed) continue;

    findings.push({
      id: `exposure-${check.path}`,
      category: 'exposure',
      title: check.title,
      severity: check.severity,
      summary: check.summary,
      recommendation: check.recommendation,
      evidence: `GET ${check.path} -> HTTP ${status}`,
    });
  }

  if (findings.length === 0) {
    findings.push({
      id: 'exposure-none-found',
      category: 'exposure',
      title: 'No common exposed files or paths detected',
      severity: 'pass',
      summary: 'None of the commonly probed sensitive paths (e.g. .env, .git, phpinfo) were found exposed.',
      recommendation: 'No action needed. Note this check only covers a known list of common paths, not a full scan.',
    });
  }

  return findings;
}

async function safeFetch(url: string): Promise<{ status: number; body: string } | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);
    const res = await fetch(url, {
      signal: controller.signal,
      redirect: 'manual', // don't follow redirects — a redirect to a login page means "not exposed"
      headers: { 'User-Agent': 'SecAuditBot/0.1 (+https://example.com/about-this-scanner)' },
    });
    clearTimeout(timeout);
    const body = await res.text();
    return { status: res.status, body: body.slice(0, 5000) };
  } catch {
    return null;
  }
}

function bodiesLookSimilar(a: string, b: string): boolean {
  if (a.length === 0 && b.length === 0) return true;
  const lenDiff = Math.abs(a.length - b.length);
  return lenDiff < 20; // crude but effective for catch-all 404 pages
}

/**
 * Detects common WAF/firewall block pages (Cloudflare, Akamai, Sucuri, etc.)
 * by their well-known phrasing, so a blocked automated request never gets
 * mistaken for the actual file being probed for.
 */
function looksLikeWafBlockPage(body: string): boolean {
  return /you have been blocked|access denied|attention required|security check|blocked by network security|request blocked|automated requests? (from your|detected)|cloudflare ray id|sucuri|incapsula|please complete the security check/i.test(
    body
  );
}
