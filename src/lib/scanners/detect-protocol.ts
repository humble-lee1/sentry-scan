/**
 * Determines whether a domain is reachable over HTTPS or only plain HTTP,
 * so every scanner that fetches pages agrees on which base URL to use.
 * Without this, scanners hardcoded to https:// silently fail (return null/empty)
 * for sites that only run on HTTP, producing misleading "no issues found"
 * results instead of an honest "this couldn't be checked".
 */
export async function detectBaseUrl(domain: string): Promise<{ baseUrl: string; isHttps: boolean } | null> {
  // Try HTTPS first
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);
    await fetch(`https://${domain}/`, {
      signal: controller.signal,
      redirect: 'manual',
      headers: { 'User-Agent': 'SecAuditBot/0.1 (+https://example.com/about-this-scanner)' },
    });
    clearTimeout(timeout);
    return { baseUrl: `https://${domain}`, isHttps: true };
  } catch {
    // fall through to HTTP attempt
  }

  // Fall back to HTTP
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);
    await fetch(`http://${domain}/`, {
      signal: controller.signal,
      redirect: 'manual',
      headers: { 'User-Agent': 'SecAuditBot/0.1 (+https://example.com/about-this-scanner)' },
    });
    clearTimeout(timeout);
    return { baseUrl: `http://${domain}`, isHttps: false };
  } catch {
    return null; // domain is not reachable over either protocol
  }
}
