import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Sentry Scan — Free Website Security Check',
  description:
    'Scan any website for common security weaknesses — SSL, headers, email spoofing risk, exposed files, and outdated software. Plain-English results, free.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="font-sans bg-ink text-paper antialiased min-h-screen">{children}</body>
    </html>
  );
}
