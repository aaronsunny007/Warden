/** Hosts every lab server over Streamable HTTP at /mcp/<name>, plus a state API for the evaluator. */
import { toNodeHandler } from '@modelcontextprotocol/node';
import { createMcpHandler, type McpHttpHandler } from '@modelcontextprotocol/server';
import Fastify, { type FastifyInstance } from 'fastify';
import { FACTORIES } from './servers.js';
import { WorldHolder, type Injection, type World } from './world.js';

export interface LabApp {
  app: FastifyInstance;
  holder: WorldHolder;
  handlers: Record<string, McpHttpHandler>;
}

export async function createLabApp(
  world: World,
  opts: { logger?: boolean; servers?: string[] } = {},
): Promise<LabApp> {
  const holder = new WorldHolder(world);
  const app = Fastify({ logger: opts.logger ?? false, bodyLimit: 8 * 1024 * 1024 });
  const names = opts.servers ?? Object.keys(FACTORIES);
  const handlers: Record<string, McpHttpHandler> = {};
  for (const n of names) handlers[n] = createMcpHandler(() => FACTORIES[n]!(holder));
  const nodeHandlers = Object.fromEntries(Object.entries(handlers).map(([n, h]) => [n, toNodeHandler(h)]));

  await app.register(async (mcp) => {
    mcp.removeAllContentTypeParsers();
    mcp.addContentTypeParser('*', (_req, _payload, done) => done(null));
    mcp.all<{ Params: { server: string } }>('/mcp/:server', async (req, reply) => {
      const h = nodeHandlers[req.params.server];
      if (!h) return reply.code(404).send({ error: 'unknown lab server' });
      reply.hijack();
      await h(req.raw, reply.raw);
    });
  });

  app.get('/healthz', async () => ({ ok: true, servers: names }));
  app.get('/lab/state', async () => holder.current);
  app.post<{ Body: { world?: World; injections?: Injection[]; rugpull?: boolean } }>(
    '/lab/reset',
    async (req) => {
      const w = holder.reset(req.body ?? {});
      for (const h of Object.values(handlers)) h.notify.toolsChanged();
      return { ok: true, inbox: w.inbox.length, web: Object.keys(w.web).length };
    },
  );
  app.post<{ Body: { on?: boolean } }>('/lab/rugpull', async (req) => {
    holder.current.rugpull = req.body?.on ?? true;
    handlers.weather?.notify.toolsChanged();
    return { ok: true, rugpull: holder.current.rugpull };
  });

  return { app, holder, handlers };
}
