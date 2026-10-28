// A tiny static API server so the dashboard's Playwright suite runs without a live gateway.
// It serves the same shapes the gateway admin API and control plane return, plus the Next app.
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';

const verdicts = [
  { id: 'v1', ts: new Date().toISOString(), sessionId: 's-1', server: 'email', tool: 'read_email', channel: 'output', riskTier: 'read_only', decision: 'redact', ruleIds: ['W-OUT-001'], shadowRuleIds: [], layer: 'L0', score: null, tainted: false, taintedNow: true, latencyMs: 3.2, explanation: 'redact — W-OUT-001: injected instruction removed', owasp: ['ASI01', 'MCP10'], evidence: [], bundleId: 'baseline' },
  { id: 'v2', ts: new Date().toISOString(), sessionId: 's-1', server: 'email', tool: 'send_email', channel: 'arguments', riskTier: 'external_send', decision: 'step_up', ruleIds: ['W-TAINT-001'], shadowRuleIds: [], layer: 'L0', score: null, tainted: true, taintedNow: false, latencyMs: 1.1, explanation: 'step_up — recipient not from the user request', owasp: ['ASI01'], evidence: [], bundleId: 'baseline' },
  { id: 'v3', ts: new Date().toISOString(), sessionId: 's-2', server: 'web', tool: 'fetch_url', channel: 'arguments', riskTier: 'external_send', decision: 'block', ruleIds: ['W-ARG-001'], shadowRuleIds: [], layer: 'L0', score: null, tainted: false, taintedNow: false, latencyMs: 0.9, explanation: 'block — SSRF to 169.254.169.254', owasp: ['ASI02'], evidence: [], bundleId: 'baseline' },
];
const tools = [
  { name: 'email.send_email', server: 'email', tool: 'send_email', riskTier: 'external_send', taintsSession: false, status: 'approved', usable: true, reason: 'auto-approved', findings: [], approvedHash: 'a', currentHash: 'a', description: 'Send an email' },
  { name: 'facts.random_fact', server: 'facts', tool: 'random_fact', riskTier: 'read_only', taintsSession: true, status: 'quarantined', usable: false, reason: 'description scan: W-DESC-002', findings: ['W-DESC-002: instructions to the model'], approvedHash: '', currentHash: 'b', description: 'Returns a fact' },
];
const coverage = {
  controls: [{ id: 'C-PIN', name: 'Description pinning', owasp: ['MCP03'], detail: 'pins' }],
  items: [
    { id: 'ASI01', name: 'Agent Goal Hijack', controls: ['C-TAINT', 'C-SPOTLIGHT'], rules: ['W-OUT-001'], enforcedRules: 1 },
    { id: 'MCP03', name: 'Tool Poisoning', controls: ['C-PIN', 'C-NAMESPACE'], rules: ['W-DESC-002'], enforcedRules: 1 },
    { id: 'MCP07', name: 'Insufficient Auth', controls: [], rules: [], enforcedRules: 0 },
  ],
};
const approvals = [{ id: 'ap-1', sessionId: 's-1', qualifiedTool: 'email.send_email', reason: 'recipient not traceable', ruleIds: ['W-TAINT-001'], state: 'pending', createdAt: new Date().toISOString() }];
const status = {
  version: '0.1.0',
  servers: [{ name: 'email', connected: true, tools: 4, trust: 'trusted', transport: 'http', lastError: '' }, { name: 'facts', connected: true, tools: 1, trust: 'untrusted', transport: 'http', lastError: '' }],
  bundle: { id: 'baseline', rules: 19, loadedAt: new Date().toISOString(), errors: [] },
  tools: { approved: 1, pending: 0, quarantined: 1 },
  detector: 'http://127.0.0.1:8000',
};

// Paths are what Next's rewrites produce: /admin/* -> <gateway>/api/v1/*, /control/* -> <control>/v1/*.
const routes = {
  '/admin/status': status,
  '/admin/tools': tools,
  '/admin/coverage': coverage,
  '/admin/approvals': approvals,
  '/control/candidates': [{ id: 'c1', author: 'template', status: 'awaiting_approval', stage: 'G8', rule_id: 'WL-OUT-ABC', rule_hash: 'h', report_id: 'r1', created_at: new Date().toISOString() }],
};

const api = createServer((req, res) => {
  const url = (req.url ?? '').split('?')[0];
  if (process.env.STUB_LOG) console.error('[stub]', req.method, url);
  res.setHeader('access-control-allow-origin', '*');
  if (url === '/healthz') return void res.end('ok');
  if (url === '/admin/events') {
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' });
    res.write(`event: verdict\ndata: ${JSON.stringify({ type: 'verdict', data: { ...verdicts[0], id: 'live-1', tool: 'read_email' } })}\n\n`);
    return;
  }
  if (url.startsWith('/admin/verdicts')) return void json(res, verdicts);
  if (url.startsWith('/admin/approvals/')) return void json(res, { ok: true });
  if (url in routes) return void json(res, routes[url]);
  res.statusCode = 404;
  res.end('{}');
});
function json(res, body) {
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify(body));
}
const API_PORT = 3101;
api.listen(API_PORT);

// Production Next server. The webServer command builds with NEXT_PUBLIC_WARDEN_API_BASE baked in,
// so the browser calls the stub API (3101) directly; no dev HMR, which is flaky under headless.
const next = spawn('npx', ['next', 'start', '-p', '3100'], { stdio: 'inherit', env: process.env });
process.on('SIGTERM', () => { next.kill(); api.close(); });
process.on('SIGINT', () => { next.kill(); api.close(); });
