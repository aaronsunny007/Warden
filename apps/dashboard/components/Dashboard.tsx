'use client';
import { useCallback, useEffect, useRef, useState } from 'react';
import { API_BASE, api, decideApproval } from '@/lib/api';
import type { ApprovalRow, CoverageItem, Control, Status, ToolRow, Verdict } from '@/lib/types';
import { Badge, Panel, Stat } from './ui';

const REFRESH_MS = 4000;

export function Dashboard() {
  const [status, setStatus] = useState<Status | null>(null);
  const [tools, setTools] = useState<ToolRow[]>([]);
  const [verdicts, setVerdicts] = useState<Verdict[]>([]);
  const [coverage, setCoverage] = useState<{ controls: Control[]; items: CoverageItem[] } | null>(null);
  const [approvals, setApprovals] = useState<ApprovalRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const seen = useRef<Set<string>>(new Set());

  const refresh = useCallback(async () => {
    try {
      const [s, t, v, c, a] = await Promise.all([api.status(), api.tools(), api.verdicts(300), api.coverage(), api.approvals()]);
      setStatus(s);
      setTools(t);
      setVerdicts(v);
      setCoverage(c);
      setApprovals(a);
      setError(null);
      for (const row of v) seen.current.add(row.id);
    } catch (e) {
      setError((e as Error).message);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const live = new EventSource(`${API_BASE}/admin/events`);
    live.addEventListener('verdict', (ev) => {
      try {
        const data = JSON.parse((ev as MessageEvent).data).data as Verdict;
        if (seen.current.has(data.id)) return;
        seen.current.add(data.id);
        setVerdicts((prev) => [data, ...prev].slice(0, 300));
      } catch {
        /* ignore malformed frame */
      }
    });
    live.addEventListener('approval', () => void refresh());
    live.addEventListener('pin', () => void refresh());
    live.onerror = () => {
      /* SSE reconnects automatically; polling is the fallback */
    };
    const poll = setInterval(() => void refresh(), REFRESH_MS);
    return () => {
      live.close();
      clearInterval(poll);
    };
  }, [refresh]);

  const blocked = verdicts.filter((v) => v.decision !== 'allow' && v.decision !== 'approved_step_up').length;
  const tainted = verdicts.filter((v) => v.taintedNow).length;

  return (
    <div data-testid="dashboard">
      {error && (
        <div style={{ background: '#2d1012', border: '1px solid var(--block)', borderRadius: 8, padding: 10, marginBottom: 16, color: 'var(--block)' }} data-testid="conn-error">
          Cannot reach Warden: {error}. Showing last known data.
        </div>
      )}

      <Panel title="Overview">
        <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap' }}>
          <Stat label="Policy bundle" value={status?.bundle.id ?? '—'} />
          <Stat label="Active rules" value={status?.bundle.rules ?? 0} />
          <Stat label="Tools approved" value={status?.tools.approved ?? 0} tone="var(--allow)" />
          <Stat label="Tools quarantined" value={status?.tools.quarantined ?? 0} tone="var(--block)" />
          <Stat label="Verdicts (recent)" value={verdicts.length} />
          <Stat label="Blocked / redacted / stepped-up" value={blocked} tone="var(--block)" />
          <Stat label="Sessions tainted (recent)" value={tainted} tone="var(--redact)" />
        </div>
        <div style={{ marginTop: 12, fontSize: 13, color: 'var(--muted)' }}>
          Upstream servers:{' '}
          {(status?.servers ?? []).map((s) => (
            <span key={s.name} style={{ marginRight: 12 }}>
              <Badge kind={s.connected ? 'allow' : 'block'}>{s.name}</Badge> {s.trust}
            </span>
          ))}
        </div>
      </Panel>

      {approvals.filter((a) => a.state === 'pending').length > 0 && (
        <Panel title="Pending step-up approvals">
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <tbody>
              {approvals
                .filter((a) => a.state === 'pending')
                .map((a) => (
                  <tr key={a.id} style={{ borderTop: '1px solid var(--border)' }} data-testid="approval-row">
                    <td style={{ padding: '8px 6px' }}><code>{a.qualifiedTool}</code></td>
                    <td style={{ padding: '8px 6px', color: 'var(--muted)' }}>{a.reason}</td>
                    <td style={{ padding: '8px 6px' }}>{a.ruleIds.join(', ')}</td>
                    <td style={{ padding: '8px 6px', textAlign: 'right' }}>
                      <button onClick={() => void decideApproval(a.id, 'approve').then(refresh)} style={btn('var(--allow)')}>Approve</button>
                      <button onClick={() => void decideApproval(a.id, 'deny').then(refresh)} style={btn('var(--block)')}>Deny</button>
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </Panel>
      )}

      <Panel title="Live attack feed">
        <div style={{ maxHeight: 420, overflowY: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ textAlign: 'left', color: 'var(--muted)' }}>
                <th style={th}>Time</th><th style={th}>Decision</th><th style={th}>Channel</th><th style={th}>Tool</th>
                <th style={th}>Layer</th><th style={th}>Rules</th><th style={th}>OWASP</th><th style={th}>Explanation</th>
              </tr>
            </thead>
            <tbody>
              {verdicts.map((v) => (
                <tr key={v.id} style={{ borderTop: '1px solid var(--border)' }} data-testid="verdict-row">
                  <td style={td}>{new Date(v.ts).toLocaleTimeString()}</td>
                  <td style={td}><Badge kind={v.decision}>{v.decision}</Badge></td>
                  <td style={td}>{v.channel}{v.tainted ? ' 🔶' : ''}</td>
                  <td style={td}><code>{v.server}.{v.tool}</code></td>
                  <td style={td}>{v.layer}{v.score != null ? ` ${v.score.toFixed(2)}` : ''}</td>
                  <td style={td}>{v.ruleIds.join(', ')}</td>
                  <td style={td}>{v.owasp.join(', ')}</td>
                  <td style={{ ...td, color: 'var(--muted)', maxWidth: 360, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v.explanation}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel title="Tool inventory & pins">
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ textAlign: 'left', color: 'var(--muted)' }}>
              <th style={th}>Tool</th><th style={th}>Risk</th><th style={th}>Status</th><th style={th}>Reason / findings</th>
            </tr>
          </thead>
          <tbody>
            {tools.map((t) => (
              <tr key={t.name} style={{ borderTop: '1px solid var(--border)' }} data-testid="tool-row">
                <td style={td}><code>{t.name}</code></td>
                <td style={td}>{t.riskTier}{t.taintsSession ? ' · taints' : ''}</td>
                <td style={td}><Badge kind={t.status === 'approved' ? 'allow' : t.status === 'quarantined' ? 'block' : 'redact'}>{t.status}</Badge></td>
                <td style={{ ...td, color: 'var(--muted)' }}>{t.reason}{t.findings.length ? ` — ${t.findings.join('; ')}` : ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>

      <Panel title="OWASP coverage">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(230px, 1fr))', gap: 10 }}>
          {(coverage?.items ?? []).map((i) => {
            const covered = i.controls.length > 0 || i.rules.length > 0;
            return (
              <div key={i.id} style={{ border: '1px solid var(--border)', borderRadius: 8, padding: 10, opacity: covered ? 1 : 0.5 }} data-testid="owasp-item">
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <strong style={{ fontSize: 13 }}>{i.id}</strong>
                  <Badge kind={covered ? 'allow' : undefined}>{covered ? 'covered' : 'none'}</Badge>
                </div>
                <div style={{ fontSize: 12, margin: '4px 0', color: 'var(--muted)' }}>{i.name}</div>
                <div style={{ fontSize: 11 }}>
                  {i.controls.length > 0 && <div>controls: {i.controls.join(', ')}</div>}
                  {i.rules.length > 0 && <div>rules: {i.rules.length} ({i.enforcedRules} enforcing)</div>}
                </div>
              </div>
            );
          })}
        </div>
      </Panel>
    </div>
  );
}

const th = { padding: '6px 6px', fontWeight: 500 as const, position: 'sticky' as const, top: 0, background: 'var(--panel)' };
const td = { padding: '6px 6px', verticalAlign: 'top' as const };
const btn = (color: string) => ({ marginLeft: 6, padding: '4px 10px', fontSize: 12, borderRadius: 6, border: `1px solid ${color}`, background: 'transparent', color, cursor: 'pointer' });
