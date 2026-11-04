/** Same-origin fetch helpers. /admin -> gateway admin API, /control -> control plane. The server-side
 * proxy.ts adds the operator token to both, so no credential lives in the browser bundle. */
import type { ApprovalRow, CandidateRow, Control, CoverageItem, Status, ToolRow, Verdict } from './types';

/** Base for API calls. Empty = same-origin (/admin, /control via next.config rewrites).
 * The e2e suite points this at its stub server. */
export const API_BASE = process.env.NEXT_PUBLIC_WARDEN_API_BASE ?? '';

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    cache: 'no-store',
  });
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  return res.json() as Promise<T>;
}

export const api = {
  status: () => get<Status>('/admin/status'),
  tools: () => get<ToolRow[]>('/admin/tools'),
  verdicts: (limit = 200) => get<Verdict[]>(`/admin/verdicts?limit=${limit}`),
  coverage: () => get<{ controls: Control[]; items: CoverageItem[] }>('/admin/coverage'),
  approvals: () => get<ApprovalRow[]>('/admin/approvals'),
  candidates: () => get<CandidateRow[]>('/control/candidates').catch(() => []),
};

export async function decideApproval(id: string, decision: 'approve' | 'deny'): Promise<void> {
  await fetch(`${API_BASE}/admin/approvals/${id}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ decision, by: 'dashboard' }),
  });
}
