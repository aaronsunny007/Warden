/** Wires the gateway together: state, policy, detector, upstreams, MCP endpoint and admin API. */
import { randomUUID } from 'node:crypto';
import { toNodeHandler } from '@modelcontextprotocol/node';
import { createMcpHandler } from '@modelcontextprotocol/server';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import Fastify, { type FastifyInstance } from 'fastify';
import { registerAdmin } from './admin.js';
import type { GatewayConfig } from './config.js';
import { HttpDetector, NullDetector, type Detector } from './detector.js';
import { EventBus, JsonlSink, type EventSink } from './events/bus.js';
import { Inspector } from './inspector.js';
import { Metrics } from './metrics.js';
import { PolicyStore } from './policy-store.js';
import { buildServer, Catalog, headerSessionResolver, WardenCore } from './proxy.js';
import { ApprovalStore } from './state/approvals.js';
import { createKV, FileKV, type KV } from './state/kv.js';
import { PinStore } from './state/pins.js';
import { TaintStore } from './state/taint.js';
import { UpstreamManager } from './upstream.js';

export interface Gateway {
  cfg: GatewayConfig;
  app: FastifyInstance;
  core: WardenCore;
  catalog: Catalog;
  policies: PolicyStore;
  bus: EventBus;
  metrics: Metrics;
  listen(): Promise<string>;
  serveStdio(sessionId?: string): Promise<void>;
  close(): Promise<void>;
}

export interface GatewayOverrides {
  detector?: Detector;
  kv?: KV;
  logger?: boolean;
}

async function buildSinks(cfg: GatewayConfig): Promise<EventSink[]> {
  const sinks: EventSink[] = [];
  if (cfg.events.jsonl) sinks.push(new JsonlSink(cfg.events.jsonl));
  if (cfg.events.kafka) {
    const { KafkaSink } = await import('./events/kafka.js');
    sinks.push(new KafkaSink(cfg.events.kafka.brokers, cfg.events.kafka.topic, cfg.events.kafka.clientId));
  }
  if (cfg.events.postgres) {
    const { PostgresSink } = await import('./events/postgres.js');
    sinks.push(new PostgresSink(cfg.events.postgres.url));
  }
  return sinks;
}

export async function createGateway(cfg: GatewayConfig, overrides: GatewayOverrides = {}): Promise<Gateway> {
  const metrics = new Metrics();
  const bus = new EventBus(await buildSinks(cfg), cfg.events.ringSize);
  const kv = overrides.kv ?? createKV(cfg.state.redisUrl);
  const pinKv =
    cfg.pins.store === 'file'
      ? await FileKV.open(cfg.pins.path)
      : cfg.pins.store === 'redis'
        ? kv
        : (overrides.kv ?? kv);
  const policies = new PolicyStore(
    {
      path: cfg.policy.bundle,
      trustedKeys: cfg.policy.trustedKeys,
      allowUnsigned: cfg.policy.allowUnsigned,
      watch: cfg.policy.watch,
    },
    bus,
  );
  const detector =
    overrides.detector ??
    (cfg.detector.url
      ? new HttpDetector(cfg.detector.url, cfg.detector.timeoutMs, kv, cfg.detector.cacheTtlSeconds)
      : new NullDetector());
  const taint = new TaintStore(kv);
  const approvals = new ApprovalStore(kv, cfg.stepUp.approvalTtlSeconds);
  const pins = new PinStore(pinKv);
  const upstreams = new UpstreamManager(cfg.servers, metrics);
  const inspector = new Inspector(cfg, policies, detector, taint, bus, metrics);
  const catalog = new Catalog(cfg, upstreams, pins, inspector, bus, metrics);
  const core = new WardenCore(cfg, catalog, upstreams, inspector, taint, approvals, bus);

  const app = Fastify({
    logger: overrides.logger ?? { level: process.env.LOG_LEVEL ?? 'info' },
    bodyLimit: 2 * 1024 * 1024,
  });

  const handler = createMcpHandler(
    (ctx) => buildServer(core, headerSessionResolver(ctx.requestInfo?.headers), ctx.era),
    {
      onerror: (e) => app.log.warn({ err: e.message }, 'mcp handler error'),
    },
  );
  const nodeHandler = toNodeHandler(handler);
  const allowed = new Set(cfg.allowedHosts.map((h) => h.toLowerCase()));

  await app.register(async (mcp) => {
    mcp.removeAllContentTypeParsers();
    mcp.addContentTypeParser('*', (_req, _payload, done) => done(null));
    mcp.all('/mcp', async (req, reply) => {
      if (allowed.size) {
        const host = (req.headers.host ?? '').replace(/:\d+$/, '').toLowerCase();
        if (!allowed.has(host)) return reply.code(403).send({ error: 'host not allowed' });
      }
      reply.hijack();
      await nodeHandler(req.raw, reply.raw);
    });
  });

  if (cfg.admin.enabled)
    await registerAdmin(app, { token: cfg.admin.token, core, catalog, policies, bus, metrics });

  // Push tool-list changes to subscribed agents.
  upstreams.onToolsChanged(() => {
    void catalog.sync(true).then(() => handler.notify.toolsChanged());
  });

  let stdioServer: ReturnType<typeof buildServer> | null = null;

  return {
    cfg,
    app,
    core,
    catalog,
    policies,
    bus,
    metrics,
    async listen() {
      await upstreams.start();
      await catalog
        .sync(true)
        .catch((e: Error) => app.log.warn({ err: e.message }, 'initial tool sync failed'));
      return app.listen({ host: cfg.listen.host, port: cfg.listen.port });
    },
    async serveStdio(sessionId = process.env.WARDEN_SESSION_ID ?? `stdio-${randomUUID()}`) {
      await upstreams.start();
      await catalog.sync(true).catch(() => undefined);
      stdioServer = buildServer(
        core,
        (meta) => ({
          sessionId,
          userRequest:
            typeof meta?.['io.warden/user-request'] === 'string'
              ? (meta['io.warden/user-request'] as string)
              : undefined,
        }),
        'legacy',
      );
      upstreams.onToolsChanged(() => void stdioServer?.sendToolListChanged().catch(() => undefined));
      await stdioServer.connect(new StdioServerTransport());
    },
    async close() {
      await stdioServer?.close().catch(() => undefined);
      await handler.close().catch(() => undefined);
      await app.close();
      await upstreams.close();
      policies.close();
      await bus.close();
      await kv.close();
      if (pinKv !== kv) await pinKv.close();
    },
  };
}
