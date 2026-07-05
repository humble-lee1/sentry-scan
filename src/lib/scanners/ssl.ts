import * as tls from 'tls';
import { Finding } from '../types';

/**
 * Connects to the domain on port 443 and inspects the TLS certificate
 * and negotiated protocol. Uses Node's built-in tls module — no external
 * dependency, no API cost.
 */
export async function checkSsl(domain: string): Promise<Finding[]> {
  // Try twice with a generous timeout before concluding HTTPS is genuinely down.
  // A single timeout is ambiguous — it could mean "no HTTPS here" or just "slow
  // network right now" — and those deserve very different severities, so we only
  // report the serious one after a second attempt also fails.
  const first = await attemptSslCheck(domain, 6000);
  if (first.kind === 'success' || first.kind === 'error') {
    return first.findings;
  }
  // First attempt timed out — one more try with a slightly longer window.
  const second = await attemptSslCheck(domain, 8000);
  if (second.kind === 'success' || second.kind === 'error') {
    return second.findings;
  }
  // Timed out twice in a row with a generous window each time — genuinely treat
  // this as "HTTPS is not responding", not just network noise.
  return [
    {
      id: 'ssl-timeout',
      category: 'ssl',
      title: 'No response on HTTPS (port 443) — site may not support HTTPS',
      severity: 'critical',
      summary: `The connection to ${domain} on port 443 (HTTPS) did not respond after two attempts. This usually means the site has no HTTPS configured, so any data submitted by visitors (including passwords) could travel unencrypted.`,
      recommendation: 'Enable HTTPS on the server and confirm port 443 is open and responding. This is essential for protecting any data submitted by visitors.',
    },
  ];
}

type SslAttemptResult =
  | { kind: 'success'; findings: Finding[] }
  | { kind: 'error'; findings: Finding[] }
  | { kind: 'timeout'; findings: Finding[] };

async function attemptSslCheck(domain: string, timeoutMs: number): Promise<SslAttemptResult> {
  const findings: Finding[] = [];
  let settled = false;

  return new Promise((resolve) => {
    const finish = (result: SslAttemptResult) => {
      if (settled) return; // ignore any late event firing after we've already resolved
      settled = true;
      resolve(result);
    };

    const socket = tls.connect(
      {
        host: domain,
        port: 443,
        servername: domain, // SNI
        timeout: timeoutMs,
        rejectUnauthorized: false, // we want to inspect even invalid certs, not throw
      },
      () => {
        if (settled) {
          socket.end();
          return;
        }
        try {
          const cert = socket.getPeerCertificate(true);
          const protocol = socket.getProtocol(); // e.g. 'TLSv1.3'
          const authorized = socket.authorized;
          const authError = (socket as any).authorizationError;

          // 1. Certificate validity
          if (!authorized) {
            findings.push({
              id: 'ssl-invalid-cert',
              category: 'ssl',
              title: 'Invalid or untrusted SSL certificate',
              severity: 'critical',
              summary:
                "This website's security certificate is not valid or not trusted by browsers. Visitors will see a security warning before they can access the site.",
              recommendation:
                'Install a valid SSL certificate from a trusted authority (e.g. via Let\'s Encrypt, which is free) and ensure the full certificate chain is configured on the server.',
              evidence: `authorizationError: ${authError ?? 'unknown'}`,
            });
          } else {
            findings.push({
              id: 'ssl-valid-cert',
              category: 'ssl',
              title: 'SSL certificate is valid',
              severity: 'pass',
              summary: 'The site has a valid, trusted SSL certificate installed.',
              recommendation: 'No action needed. Keep monitoring for renewal before expiry.',
            });
          }

          // 2. Expiry check
          if (cert && cert.valid_to) {
            const expiry = new Date(cert.valid_to);
            const daysLeft = Math.floor((expiry.getTime() - Date.now()) / (1000 * 60 * 60 * 24));

            if (daysLeft < 0) {
              findings.push({
                id: 'ssl-expired',
                category: 'ssl',
                title: 'SSL certificate has expired',
                severity: 'critical',
                summary: `The certificate expired ${Math.abs(daysLeft)} day(s) ago. Visitors are currently seeing security warnings.`,
                recommendation: 'Renew the SSL certificate immediately.',
                evidence: `valid_to: ${cert.valid_to}`,
              });
            } else if (daysLeft < 14) {
              findings.push({
                id: 'ssl-expiring-soon',
                category: 'ssl',
                title: 'SSL certificate expiring soon',
                severity: 'high',
                summary: `The certificate expires in ${daysLeft} day(s).`,
                recommendation: 'Renew the certificate now to avoid an outage or browser warning.',
                evidence: `valid_to: ${cert.valid_to}`,
              });
            } else if (daysLeft < 30) {
              findings.push({
                id: 'ssl-expiring-medium',
                category: 'ssl',
                title: 'SSL certificate expires within a month',
                severity: 'medium',
                summary: `The certificate expires in ${daysLeft} day(s).`,
                recommendation: 'Plan renewal soon, especially if renewal is a manual process.',
                evidence: `valid_to: ${cert.valid_to}`,
              });
            }
          }

          // 3. Protocol strength
          if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
            findings.push({
              id: 'ssl-weak-protocol',
              category: 'ssl',
              title: `Outdated TLS protocol in use (${protocol})`,
              severity: 'high',
              summary:
                'The server is using an old, deprecated encryption protocol that is no longer considered secure and is disabled by default in modern browsers.',
              recommendation: 'Disable TLS 1.0 and 1.1 on the server. Support only TLS 1.2 and TLS 1.3.',
              evidence: `negotiated protocol: ${protocol}`,
            });
          } else if (protocol === 'TLSv1.2' || protocol === 'TLSv1.3') {
            findings.push({
              id: 'ssl-strong-protocol',
              category: 'ssl',
              title: `Modern TLS protocol in use (${protocol})`,
              severity: 'pass',
              summary: 'The server negotiates a current, secure encryption protocol.',
              recommendation: 'No action needed.',
            });
          }

          socket.end();
          finish({ kind: 'success', findings });
        } catch (err) {
          socket.end();
          findings.push(buildErrorFinding(domain, err));
          finish({ kind: 'error', findings });
        }
      }
    );

    socket.on('error', (err) => {
      findings.push(buildErrorFinding(domain, err));
      finish({ kind: 'error', findings });
    });

    socket.on('timeout', () => {
      socket.destroy();
      // Don't push a finding yet — the caller decides whether this was the
      // final attempt (and should report critical) or the first attempt
      // (in which case we retry before concluding anything).
      finish({ kind: 'timeout', findings: [] });
    });
  });
}

function buildErrorFinding(domain: string, err: unknown): Finding {
  const message = err instanceof Error ? err.message : String(err);
  const noHttps = /ECONNREFUSED|ENOTFOUND|EAI_AGAIN/.test(message);
  return {
    id: 'ssl-connection-failed',
    category: 'ssl',
    title: 'Could not establish an HTTPS connection',
    severity: noHttps ? 'critical' : 'info',
    summary: noHttps
      ? `No service responded on port 443 (HTTPS) for ${domain}. The site may not support HTTPS at all, which is a serious risk for any site handling user data.`
      : `An error occurred while checking SSL: ${message}`,
    recommendation: noHttps
      ? 'Enable HTTPS on the server. This is essential for protecting any data submitted by visitors.'
      : 'Re-run the scan, or check the domain spelling and that the server is online.',
    evidence: message,
  };
}
