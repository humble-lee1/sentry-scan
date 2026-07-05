import { Finding } from '../types';

export async function checkCms(_domain: string, baseUrl: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  const homepage = await safeFetch(`${baseUrl}/`);
  if (!homepage) {
    return findings; // unreachable — already reported by other scanners
  }

  const isWordPress =
    /wp-content|wp-includes/i.test(homepage.body) ||
    homepage.body.includes('generator" content="WordPress');

  if (!isWordPress) {
    findings.push({
      id: 'cms-not-wordpress',
      category: 'cms',
      title: 'No WordPress installation detected',
      severity: 'info',
      summary: 'This check only currently covers WordPress. No WordPress signatures were found on the homepage.',
      recommendation: 'No action needed for this check.',
    });
    return findings;
  }

  // Try to read the generator meta tag for an exact version
  const generatorMatch = homepage.body.match(/generator"\s+content="WordPress\s+([\d.]+)"/i);
  const version = generatorMatch ? generatorMatch[1] : null;

  if (version) {
    findings.push({
      id: 'cms-wp-version-exposed',
      category: 'cms',
      title: `WordPress version is publicly exposed (${version})`,
      severity: 'medium',
      summary: `The exact WordPress version (${version}) is visible in the page source, making it easier for an attacker to check for known vulnerabilities affecting that version.`,
      recommendation: 'Remove the WordPress version meta tag (most SEO/security plugins offer this option), and keep WordPress core updated regardless.',
      evidence: `<meta name="generator" content="WordPress ${version}">`,
    });
  } else {
    findings.push({
      id: 'cms-wp-detected-version-hidden',
      category: 'cms',
      title: 'WordPress detected, version hidden',
      severity: 'pass',
      summary: 'This site runs WordPress, and the version number is not exposed in the page source — good practice.',
      recommendation: 'No action needed for this check. Still ensure WordPress core, themes, and plugins are kept up to date.',
    });
  }

  // Readme.html often discloses version even when the meta tag is removed
  const readme = await safeFetch(`${baseUrl}/readme.html`);
  if (readme && readme.status === 200 && /WordPress/i.test(readme.body)) {
    const readmeVersionMatch = readme.body.match(/Version\s+([\d.]+)/i);
    findings.push({
      id: 'cms-wp-readme-exposed',
      category: 'cms',
      title: 'WordPress readme.html is publicly accessible',
      severity: 'low',
      summary: `The default WordPress readme.html file is accessible${readmeVersionMatch ? ` and discloses version ${readmeVersionMatch[1]}` : ''}, which can help an attacker confirm the version even if other version indicators are hidden.`,
      recommendation: 'Delete or block public access to readme.html.',
    });
  }

  // xmlrpc.php — commonly abused for brute-force and amplification attacks
  const xmlrpc = await safeFetch(`${baseUrl}/xmlrpc.php`);
  if (xmlrpc && (xmlrpc.status === 200 || xmlrpc.status === 405)) {
    findings.push({
      id: 'cms-xmlrpc-enabled',
      category: 'cms',
      title: 'XML-RPC is enabled (xmlrpc.php)',
      severity: 'medium',
      summary:
        'WordPress\'s XML-RPC interface is enabled. It is frequently abused for brute-force login attempts and in DDoS amplification attacks, and most sites do not need it.',
      recommendation: 'Disable XML-RPC unless a specific plugin or integration (e.g. the Jetpack plugin) requires it.',
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
      headers: { 'User-Agent': 'SecAuditBot/0.1 (+https://example.com/about-this-scanner)' },
    });
    clearTimeout(timeout);
    const body = await res.text();
    return { status: res.status, body: body.slice(0, 20000) };
  } catch {
    return null;
  }
}
