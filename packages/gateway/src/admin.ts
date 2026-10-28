/**
 * Admin API for the dashboard, the control plane and the validation gate.
 * Every route except health and metrics needs the admin bearer token.
 */
import { timingSafeEqual } from 'node:crypto';
import {
  compileRule,
  compileRules,
  PolicySet,
  MODES,
  type MessageContext,
  type Mode,
} from '@warden/policy-ir';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { EventBus } from './events/bus.js';
import type { Verdict } from './events/types.js';
import type { Metrics } from './metrics.js';
import { BUILTIN_CONTROLS, coverage } from './owasp.js';
import type { PolicyStore } from './policy-store.js';
import { VERSION, type Catalog, type WardenCore } from './proxy.js';

export interface AdminDeps {
  token: string;
  core: WardenCore;
  catalog: Catalog;
  policies: PolicyStore;
  bus: EventBus;
  metrics: Metrics;
}

function tokenOk(header: string | undefined, token: string): boolean {
  if (!token) return true; // dev mode: no token configured
  const given = header?.startsWith('Bearer ') ? header.slice(7) : '';
  const a = Buffer.from(given);
  const b = Buffer.from(token);
  return a.length === b.length && timingSafeEqual(a, b);
}

export async function registerAdmin(app: FastifyInstance, deps: AdminDeps): Promise<void> {
  const { core, catalog, policies, bus, metrics } = deps;

  app.get('/healthz', async () => ({ ok: true }));
  app.get('/readyz', async (_req, reply) => {
    const servers = core.upstreams.servers();
    const ready = servers.every((s) => s.connected) && policies.lastError.length === 0;
    return reply.code(ready ? 200 : 503).send({ ready, servers, policyErrors: policies.lastError });
  });
  app.get('/metrics', async (_req, reply) =>
    reply.type(metrics.registry.contentType).send(await metrics.registry.metrics()),
  );

  await app.register(
    async (api) => {
      api.addHook('onRequest', async (req: FastifyRequest, reply: FastifyReply) => {
        if (!tokenOk(req.headers.authorization, deps.token))
          return reply.code(401).send({ error: 'unauthorized' });
      });

      api.get('/status', async () => {
        const b = policies.bundle;
        return {
          version: VERSION,
          servers: core.upstreams.servers(),
          bundle: {
            id: b.bundle.id,
            rules: b.compiled.length,
            loadedAt: policies.loadedAt,
            errors: policies.lastError,
          },
          tools: catalog
            .all()
            .reduce<Record<string, number>>(
              (acc, e) => ((acc[e.pin.status] = (acc[e.pin.status] ?? 0) + 1), acc),
              {},
            ),
          sinkErrors: bus.errors,
          detector: core.cfg.detector.url ? core.cfg.detector.url : null,
        };
      });

      api.get('/tools', async () => {
        await catalog.sync();
        return catalog.all().map((e) => ({
          name: e.info.qualified,
          server: e.info.server,
          tool: e.info.tool,
          riskTier: e.info.riskTier,
          taintsSession: e.info.taintsSession,
          status: e.pin.status,
          usable: catalog.isUsable(e),
          reason: e.pin.reason,
          findings: e.pin.findings,
          approvedHash: e.pin.approvedHash,
          currentHash: e.pin.currentHash,
          firstSeen: e.pin.firstSeen,
          approvedBy: e.pin.approvedBy,
          description: e.info.definition.description,
          approvedDescription: e.pin.approved?.description,
        }));
      });

      api.post<{ Params: { name: string }; Body: { by?: string } }>(
        '/tools/:name/approve',
        async (req, reply) => {
          const by = (req.body?.by ?? 'admin').slice(0, 64);
          const updated = await catalog.pins.approve(req.params.name, by);
          if (!updated) return reply.code(404).send({ error: 'unknown tool' });
          bus.emit('pin', { event: 'approved', tool: req.params.name, by });
          await catalog.sync(true);
          return updated;
        },
      );

      api.post<{ Params: { name: string }; Body: { reason?: string } }>(
        '/tools/:name/quarantine',
        async (req, reply) => {
          const updated = await catalog.pins.quarantine(
            req.params.name,
            (req.body?.reason ?? 'quarantined by admin').slice(0, 200),
          );
          if (!updated) return reply.code(404).send({ error: 'unknown tool' });
          bus.emit('pin', { event: 'quarantined', tool: req.params.name });
          await catalog.sync(true);
          return updated;
        },
      );

      api.get<{ Querystring: { limit?: string; decision?: string; channel?: string; session?: string } }>(
        '/verdicts',
        async (req) => {
          const limit = Math.min(Number(req.query.limit ?? 200) || 200, 2000);
          return bus
            .recent('verdict', 5000)
            .map((e) => e.data as Verdict)
            .filter(
              (v) =>
                (!req.query.decision || v.decision === req.query.decision) &&
                (!req.query.channel || v.channel === req.query.channel) &&
                (!req.query.session || v.sessionId === req.query.session),
            )
            .slice(0, limit);
        },
      );

      api.get('/events', async (req, reply) => {
        reply.hijack();
        const res = reply.raw;
        res.writeHead(200, {
          'content-type': 'text/event-stream',
          'cache-control': 'no-cache',
          connection: 'keep-alive',
          'x-accel-buffering': 'no',
        });
        res.write(': warden event stream\n\n');
        const unsub = bus.subscribe((e) => res.write(`event: ${e.type}\ndata: ${JSON.stringify(e)}\n\n`));
        const ping = setInterval(() => res.write(': ping\n\n'), 15000);
        req.raw.on('close', () => {
          clearInterval(ping);
          unsub();
        });
      });

      api.get('/policy', async () => {
        const b = policies.bundle;
        return {
          bundle: b.bundle,
          hashes: b.compiled.map((c) => ({
            id: c.rule.id,
            version: c.rule.version,
            hash: c.hash,
            mode: c.rule.mode,
          })),
          loadedAt: policies.loadedAt,
          errors: policies.lastError,
        };
      });

      api.put('/policy', { bodyLimit: 10 * 1024 * 1024 }, async (req, reply) => {
        const res = policies.install(req.body);
        return res.ok ? { ok: true, bundleId: policies.bundle.bundle.id } : reply.code(422).send(res);
      });

      // G1 static check for candidate rules (no enforcement side effects).
      api.post<{ Body: { rules: unknown[] } }>('/policy/compile', async (req) => {
        const rules = Array.isArray(req.body?.rules) ? req.body.rules : [];
        return rules.map((r, index) => {
          const c = compileRule(r);
          return c.ok
            ? { index, ok: true, id: c.compiled.rule.id, hash: c.compiled.hash, warnings: c.warnings }
            : { index, ok: false, errors: c.errors };
        });
      });

      // G2/G4/G5 replay: evaluate candidate rules over recorded messages.
      api.post<{
        Body: {
          rules: unknown[];
          messages: Array<{ id: string; ctx: MessageContext; label?: string }>;
          forceMode?: Mode;
          includeActive?: boolean;
        };
      }>('/policy/replay', { bodyLimit: 64 * 1024 * 1024 }, async (req, reply) => {
        const { compiled, failures } = compileRules(Array.isArray(req.body?.rules) ? req.body.rules : []);
        if (failures.length) return reply.code(422).send({ failures });
        const forceMode =
          req.body.forceMode && (MODES as readonly string[]).includes(req.body.forceMode)
            ? req.body.forceMode
            : undefined;
        const set = new PolicySet(
          req.body.includeActive ? [...policies.bundle.compiled, ...compiled] : compiled,
        );
        return (req.body.messages ?? []).map((m) => {
          const ev = set.evaluate(m.ctx, forceMode ? { forceMode } : {});
          return {
            id: m.id,
            label: m.label,
            decision: ev.decision,
            enforced: ev.enforced.map((x) => x.ruleId),
            observed: ev.observed.map((x) => x.ruleId),
          };
        });
      });

      api.get('/approvals', async () => core.approvals.list());
      api.post<{ Params: { id: string }; Body: { decision: 'approve' | 'deny'; by?: string } }>(
        '/approvals/:id',
        async (req, reply) => {
          const state =
            req.body?.decision === 'approve' ? 'approved' : req.body?.decision === 'deny' ? 'denied' : null;
          if (!state) return reply.code(400).send({ error: 'decision must be approve or deny' });
          const r = await core.approvals.decide(req.params.id, state, (req.body.by ?? 'admin').slice(0, 64));
          if (!r) return reply.code(404).send({ error: 'unknown approval' });
          bus.emit('approval', { event: state, ...r });
          return r;
        },
      );

      api.get('/sessions', async () => core.taint.list());
      api.get<{ Params: { id: string } }>('/sessions/:id', async (req) => core.taint.get(req.params.id));
      api.post<{ Params: { id: string }; Body: { userRequest?: string } }>('/sessions/:id', async (req) => {
        if (req.body?.userRequest)
          return core.taint.addUserRequest(req.params.id, String(req.body.userRequest));
        return core.taint.get(req.params.id);
      });
      api.delete<{ Params: { id: string } }>('/sessions/:id', async (req) => {
        await core.taint.reset(req.params.id);
        return { ok: true };
      });

      api.get('/coverage', async () => ({
        controls: BUILTIN_CONTROLS,
        items: coverage(
          policies.bundle.compiled.map((c) => ({ id: c.rule.id, mode: c.rule.mode, owasp: c.rule.owasp })),
        ),
      }));
    },
    { prefix: '/api/v1' },
  );
}
