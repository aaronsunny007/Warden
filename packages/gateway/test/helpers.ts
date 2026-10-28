import { readFileSync } from 'node:fs';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { BUNDLE_SCHEMA, compileRule, generateSigningKey, signBundle, type Approval } from '@warden/policy-ir';
import { createLabApp, loadWorld, type LabApp } from '@warden/lab-servers';
import { createGateway, type Gateway } from '../src/app.js';
import { parseConfig } from '../src/config.js';

export const ROOT = resolve(import.meta.dirname, '../../..');

export function baselineRules(): unknown[] {
  return JSON.parse(readFileSync(join(ROOT, 'policies/baseline.rules.json'), 'utf8')) as unknown[];
}

/** A signed bundle with human enforce approvals, as the gate would produce. */
export function signedBundle(rules: unknown[], keyId = 'test'): { path: string; publicKeyPem: string } {
  const key = generateSigningKey(keyId);
  const approvals: Approval[] = rules.map((r) => {
    const c = compileRule(r);
    if (!c.ok) throw new Error(JSON.stringify(c.errors));
    return {
      ruleId: c.compiled.rule.id,
      version: c.compiled.rule.version,
      ruleHash: c.compiled.hash,
      stage: 'enforce',
      gateReport: 'b'.repeat(64),
      approvedBy: 'test',
      human: true,
      approvedAt: new Date().toISOString(),
    };
  });
  const bundle = signBundle(
    { schema: BUNDLE_SCHEMA, id: 'test-bundle', createdAt: new Date().toISOString(), rules, approvals },
    keyId,
    key.privateKeyPem,
  );
  const dir = mkdtempSync(join(tmpdir(), 'warden-'));
  const path = join(dir, 'bundle.json');
  writeFileSync(path, JSON.stringify(bundle));
  return { path, publicKeyPem: key.publicKeyPem };
}

export interface Harness {
  lab: LabApp;
  labUrl: string;
  gw: Gateway;
  gwUrl: string;
  agent(session: string, userRequest?: string): Promise<Client>;
  admin(path: string, init?: RequestInit): Promise<Response>;
  close(): Promise<void>;
}

export async function startHarness(
  opts: { rules?: unknown[]; servers?: string[]; refreshSeconds?: number } = {},
): Promise<Harness> {
  const lab = await createLabApp(loadWorld(join(ROOT, 'data/lab/world.json')));
  const labUrl = await lab.app.listen({ host: '127.0.0.1', port: 0 });
  const bundle = signedBundle(opts.rules ?? baselineRules());
  const servers = opts.servers ?? [
    'email',
    'customers',
    'files',
    'web',
    'tickets',
    'payments',
    'facts',
    'weather',
    'audit',
  ];
  const trusted = new Set(['email', 'customers', 'files', 'tickets', 'payments']);
  const yaml = `
listen: { host: 127.0.0.1, port: 0 }
admin: { token: test-token }
policy:
  bundle: ${bundle.path}
  trustedKeys: { test: ${JSON.stringify(bundle.publicKeyPem)} }
pins: { store: memory, autoApproveClean: true, refreshSeconds: ${opts.refreshSeconds ?? 0} }
servers:
${servers
  .map(
    (s) => `  - name: ${s}
    transport: { type: http, url: ${labUrl}/mcp/${s} }
    trust: ${trusted.has(s) ? 'trusted' : 'untrusted'}
    taintSources: ${s === 'email' ? '["read_email", "search_email"]' : s === 'tickets' ? '["get_ticket"]' : s === 'files' ? '["read_file"]' : '[]'}`,
  )
  .join('\n')}
`;
  const cfg = parseConfig(yaml);
  const gw = await createGateway(cfg, { logger: false });
  const gwUrl = await gw.listen();
  const clients: Client[] = [];
  return {
    lab,
    labUrl,
    gw,
    gwUrl,
    async agent(session, userRequest) {
      const headers: Record<string, string> = { 'x-warden-session': session };
      if (userRequest) headers['x-warden-user-request'] = encodeURIComponent(userRequest);
      const c = new Client({ name: 'test-agent', version: '1.0.0' });
      await c.connect(
        new StreamableHTTPClientTransport(new URL(`${gwUrl}/mcp`), { requestInit: { headers } }),
      );
      clients.push(c);
      return c;
    },
    admin(path, init = {}) {
      return fetch(`${gwUrl}/api/v1${path}`, {
        ...init,
        headers: {
          authorization: 'Bearer test-token',
          'content-type': 'application/json',
          ...(init.headers ?? {}),
        },
      });
    },
    async close() {
      await Promise.all(clients.map((c) => c.close().catch(() => undefined)));
      await gw.close();
      await lab.app.close();
    },
  };
}

export function textOf(r: unknown): string {
  return ((r as { content?: Array<{ text?: string }> }).content ?? []).map((c) => c.text ?? '').join('\n');
}
