#!/usr/bin/env node
/**
 * warden-lab http  [--port 8790] [--host 127.0.0.1] [--world data/lab/world.json]
 * warden-lab stdio --server email [--world ...]
 */
import { parseArgs } from 'node:util';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { createLabApp } from './http.js';
import { FACTORIES } from './servers.js';
import { loadWorld, WorldHolder } from './world.js';

async function main(): Promise<void> {
  const [cmd = 'http', ...rest] = process.argv.slice(2);
  const { values } = parseArgs({
    args: rest,
    options: {
      port: { type: 'string' },
      host: { type: 'string' },
      world: { type: 'string' },
      server: { type: 'string' },
    },
  });
  const world = loadWorld(values.world);
  if (cmd === 'stdio') {
    const name = values.server ?? '';
    const factory = FACTORIES[name];
    if (!factory) throw new Error(`--server must be one of ${Object.keys(FACTORIES).join(', ')}`);
    await factory(new WorldHolder(world)).connect(new StdioServerTransport());
    return;
  }
  const { app } = await createLabApp(world, { logger: true });
  const addr = await app.listen({
    host: values.host ?? process.env.HOST ?? '127.0.0.1',
    port: Number(values.port ?? process.env.PORT ?? 8790),
  });
  app.log.info({ addr, servers: Object.keys(FACTORIES) }, 'warden lab listening (lab use only)');
  const stop = (): void => void app.close().then(() => process.exit(0));
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

main().catch((e: unknown) => {
  console.error(`warden-lab: ${(e as Error).stack ?? String(e)}`);
  process.exit(1);
});
