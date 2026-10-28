'use client';
import type { CSSProperties, ReactNode } from 'react';

export function Panel({ title, children, right }: { title: string; children: ReactNode; right?: ReactNode }) {
  return (
    <section
      style={{
        background: 'var(--panel)',
        border: '1px solid var(--border)',
        borderRadius: 10,
        padding: 16,
        marginBottom: 16,
      }}
    >
      <div
        style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}
      >
        <h2
          style={{
            fontSize: 14,
            margin: 0,
            color: 'var(--muted)',
            textTransform: 'uppercase',
            letterSpacing: 0.6,
          }}
        >
          {title}
        </h2>
        {right}
      </div>
      {children}
    </section>
  );
}

const DECISION_COLOR: Record<string, string> = {
  allow: 'var(--allow)',
  block: 'var(--block)',
  redact: 'var(--redact)',
  step_up: 'var(--stepup)',
  quarantine_tool: 'var(--block)',
  approved_step_up: 'var(--allow)',
};

export function Badge({ kind, children }: { kind?: string; children: ReactNode }) {
  const color = kind ? (DECISION_COLOR[kind] ?? 'var(--muted)') : 'var(--muted)';
  const style: CSSProperties = {
    display: 'inline-block',
    padding: '1px 8px',
    borderRadius: 999,
    fontSize: 12,
    color,
    border: `1px solid ${color}`,
    whiteSpace: 'nowrap',
  };
  return <span style={style}>{children}</span>;
}

export function Stat({ label, value, tone }: { label: string; value: string | number; tone?: string }) {
  return (
    <div style={{ flex: 1, minWidth: 120 }}>
      <div style={{ fontSize: 26, fontWeight: 600, color: tone ?? 'var(--text)' }}>{value}</div>
      <div style={{ fontSize: 12, color: 'var(--muted)' }}>{label}</div>
    </div>
  );
}
