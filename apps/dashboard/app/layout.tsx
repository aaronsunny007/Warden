import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Warden',
  description: 'Validation-gated security for AI agents and their MCP tools',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header
          style={{
            borderBottom: '1px solid var(--border)',
            padding: '14px 24px',
            display: 'flex',
            gap: 16,
            alignItems: 'baseline',
          }}
        >
          <strong style={{ fontSize: 18 }}>Warden</strong>
          <span style={{ color: 'var(--muted)', fontSize: 13 }}>
            validation-gated security for AI agents and their MCP tools
          </span>
        </header>
        <main style={{ padding: 24, maxWidth: 1200, margin: '0 auto' }}>{children}</main>
      </body>
    </html>
  );
}
