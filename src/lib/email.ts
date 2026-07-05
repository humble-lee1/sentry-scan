import { Resend } from 'resend';

let client: Resend | null = null;

function getResendClient(): Resend {
  if (!client) {
    const apiKey = process.env.RESEND_API_KEY;
    if (!apiKey) {
      throw new Error('Missing RESEND_API_KEY environment variable.');
    }
    client = new Resend(apiKey);
  }
  return client;
}

/**
 * Sends the monthly monitoring email.
 *
 * NOTE on sandbox mode: until a sending domain is verified with Resend,
 * emails can only be delivered to the address you signed up to Resend with.
 * The "from" address below works in both sandbox and verified-domain modes —
 * Resend automatically uses their shared test sender until you configure
 * your own domain, at which point you'd change this to e.g.
 * "Sentry Scan <alerts@yourdomain.com>".
 */
export async function sendMonitoringEmail(params: {
  to: string;
  domain: string;
  score: number;
  previousScore: number | null;
  newIssuesCount: number;
  resolvedIssuesCount: number;
  reportUrl: string;
}) {
  const { to, domain, score, previousScore, newIssuesCount, resolvedIssuesCount, reportUrl } = params;
  const resend = getResendClient();

  const scoreChangeLine =
    previousScore === null
      ? `Current score: ${score}/100`
      : score === previousScore
        ? `Score unchanged at ${score}/100`
        : score > previousScore
          ? `Score improved from ${previousScore} to ${score} ✓`
          : `Score dropped from ${previousScore} to ${score}`;

  const subject =
    previousScore !== null && score < previousScore
      ? `⚠ Security score dropped for ${domain}`
      : `Monthly security report for ${domain}`;

  const html = `
    <div style="font-family: -apple-system, sans-serif; max-width: 480px; margin: 0 auto; color: #111;">
      <h2 style="margin-bottom: 4px;">Sentry Scan report for ${domain}</h2>
      <p style="color: #555; margin-top: 0;">${scoreChangeLine}</p>
      <p>
        ${newIssuesCount > 0 ? `<strong>${newIssuesCount} new issue${newIssuesCount === 1 ? '' : 's'}</strong> found since last scan.<br/>` : ''}
        ${resolvedIssuesCount > 0 ? `<strong>${resolvedIssuesCount} issue${resolvedIssuesCount === 1 ? '' : 's'}</strong> resolved since last scan.<br/>` : ''}
      </p>
      <a href="${reportUrl}" style="display: inline-block; margin-top: 12px; padding: 10px 16px; background: #111; color: #fff; text-decoration: none; border-radius: 4px;">
        View full report
      </a>
      <p style="color: #999; font-size: 12px; margin-top: 32px;">
        You're receiving this because you asked Sentry Scan to monitor ${domain} monthly.
      </p>
    </div>
  `;

  return resend.emails.send({
    from: 'Sentry Scan <onboarding@resend.dev>',
    to,
    subject,
    html,
  });
}
