import * as dns from 'dns';
import { promisify } from 'util';
import { Finding } from '../types';

const resolveTxt = promisify(dns.resolveTxt);
const resolveMx = promisify(dns.resolveMx);

export async function checkDnsEmail(domain: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  // --- MX records (does this domain even receive mail?) ---
  let hasMx = false;
  try {
    const mx = await resolveMx(domain);
    hasMx = mx.length > 0;
  } catch {
    hasMx = false;
  }

  // --- SPF (in a TXT record at the root domain) ---
  try {
    const txtRecords = await resolveTxt(domain);
    const flat = txtRecords.map((parts) => parts.join(''));
    const spf = flat.find((r) => r.startsWith('v=spf1'));

    if (spf) {
      const tooPermissive = /[+~?]?all/.test(spf) && /\+all/.test(spf);
      if (tooPermissive) {
        findings.push({
          id: 'dns-spf-permissive',
          category: 'dns-email',
          title: 'SPF record allows any server to send mail',
          severity: 'high',
          summary:
            'The SPF record uses a setting ("+all") that permits any mail server in the world to send email claiming to be from this domain, defeating the purpose of SPF.',
          recommendation: 'Change the SPF policy to "-all" (hard fail) or "~all" (soft fail) once all legitimate senders are listed.',
          evidence: spf,
        });
      } else {
        findings.push({
          id: 'dns-spf-present',
          category: 'dns-email',
          title: 'SPF record is configured',
          severity: 'pass',
          summary: 'An SPF record exists, helping prevent attackers from sending email that appears to come from this domain.',
          recommendation: 'No action needed. Review periodically as mail providers change.',
          evidence: spf,
        });
      }
    } else if (hasMx) {
      findings.push({
        id: 'dns-spf-missing',
        category: 'dns-email',
        title: 'No SPF record found',
        severity: 'high',
        summary:
          'This domain has no SPF record. Without one, it is much easier for attackers to send phishing emails that appear to come from this domain — a common way Nigerian businesses get impersonated in scams targeting their customers or partners.',
        recommendation: 'Add a TXT record starting with "v=spf1" listing your legitimate mail servers, ending in "-all".',
      });
    }
  } catch (err) {
    findings.push({
      id: 'dns-spf-lookup-failed',
      category: 'dns-email',
      title: 'Could not check SPF record',
      severity: 'info',
      summary: 'The DNS lookup for the SPF record failed or timed out.',
      recommendation: 'Re-run the scan, or check DNS configuration manually.',
      evidence: String(err),
    });
  }

  // --- DMARC (at _dmarc.domain) ---
  try {
    const dmarcRecords = await resolveTxt(`_dmarc.${domain}`);
    const flat = dmarcRecords.map((parts) => parts.join(''));
    const dmarc = flat.find((r) => r.startsWith('v=DMARC1'));

    if (dmarc) {
      const policyMatch = dmarc.match(/p=(\w+)/);
      const policy = policyMatch ? policyMatch[1] : 'unknown';
      if (policy === 'none') {
        findings.push({
          id: 'dns-dmarc-none',
          category: 'dns-email',
          title: 'DMARC policy is set to monitor-only ("none")',
          severity: 'medium',
          summary:
            'A DMARC record exists but is set to "none", meaning suspicious emails impersonating this domain are reported but not actually blocked or quarantined by receiving mail servers.',
          recommendation: 'Once SPF/DKIM are confirmed working, move the DMARC policy to "quarantine" or "reject".',
          evidence: dmarc,
        });
      } else {
        findings.push({
          id: 'dns-dmarc-enforced',
          category: 'dns-email',
          title: `DMARC policy is enforced ("${policy}")`,
          severity: 'pass',
          summary: 'A DMARC record is configured and actively enforced, helping block email impersonation.',
          recommendation: 'No action needed.',
          evidence: dmarc,
        });
      }
    } else if (hasMx) {
      findings.push({
        id: 'dns-dmarc-missing',
        category: 'dns-email',
        title: 'No DMARC record found',
        severity: 'high',
        summary:
          'This domain has no DMARC record. DMARC tells receiving mail servers what to do with emails that fail authentication — without it, impersonation attempts are far more likely to reach victims\' inboxes.',
        recommendation: 'Add a TXT record at "_dmarc.yourdomain.com" such as "v=DMARC1; p=quarantine; rua=mailto:you@yourdomain.com".',
      });
    }
  } catch {
    if (hasMx) {
      findings.push({
        id: 'dns-dmarc-missing-2',
        category: 'dns-email',
        title: 'No DMARC record found',
        severity: 'high',
        summary:
          'This domain has no DMARC record. Without one, impersonation attempts using this domain are far more likely to reach victims\' inboxes.',
        recommendation: 'Add a TXT record at "_dmarc.yourdomain.com" defining your DMARC policy.',
      });
    }
  }

  // --- DKIM: best-effort check on common selectors (DKIM truly requires knowing the selector, so this is a soft check) ---
  const commonSelectors = ['default', 'google', 'selector1', 'selector2', 'mail', 'k1'];
  let dkimFound = false;
  for (const selector of commonSelectors) {
    try {
      const records = await resolveTxt(`${selector}._domainkey.${domain}`);
      if (records.length > 0) {
        dkimFound = true;
        findings.push({
          id: `dns-dkim-found-${selector}`,
          category: 'dns-email',
          title: `DKIM record found (selector: ${selector})`,
          severity: 'pass',
          summary: 'A DKIM signing record was found, which helps verify that mail from this domain has not been tampered with.',
          recommendation: 'No action needed.',
        });
        break;
      }
    } catch {
      // expected for most selectors that aren't in use; not an error worth surfacing
    }
  }
  if (!dkimFound && hasMx) {
    findings.push({
      id: 'dns-dkim-not-confirmed',
      category: 'dns-email',
      title: 'Could not confirm a DKIM record',
      severity: 'info',
      summary:
        'No DKIM record was found under common selector names. This check is not conclusive since DKIM selectors are provider-specific, but if DKIM truly is not configured, it weakens email authentication.',
      recommendation: 'Confirm with your email provider (e.g. Google Workspace, Microsoft 365) that DKIM signing is enabled, and verify the exact selector they use.',
    });
  }

  if (!hasMx) {
    findings.push({
      id: 'dns-no-mx',
      category: 'dns-email',
      title: 'No mail servers configured for this domain',
      severity: 'info',
      summary: 'This domain has no MX records, meaning it is not set up to receive email directly. Email-related checks (SPF/DKIM/DMARC) are less critical if this domain never sends mail either.',
      recommendation: 'If this domain does send email (e.g. from a contact form), configure SPF and DMARC regardless, naming your actual sending service.',
    });
  }

  return findings;
}
