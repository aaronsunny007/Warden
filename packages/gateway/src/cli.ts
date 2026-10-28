#!/usr/bin/env node
/**
 * warden-gateway serve --config warden.yaml            HTTP: MCP at /mcp, admin API at /api/v1
 * warden-gateway stdio --config warden.yaml            stdio: run as a local MCP server for one agent
 */
import { parseArgs } from 'node:util';
import { createGateway } from './app.js';
import { loadConfig } from './config.js';
import { initTelemetry } from './telemetry.js';

async function main(): Promise<void> {
  const [cmd = 'serve', ...rest] = process.argv.slice(2);
  const { values } = parseArgs({
    args: rest,
    options: { config: { type: 'string', short: 'c' }, port: { type: 'string' }, host: { type: 'string' } },
  });
  const path = values.config ?? process.env.WARDEN_CONFIG ?? 'warden.yaml';
  const cfg = loadConfig(path);
  if (values.port) cfg.listen.port = Number(values.port);
  if (values.host) cfg.listen.host = values.host;
  const stopTelemetry = await initTelemetry(cfg.telemetry.otlpEndpoint, cfg.telemetry.serviceName);

  if (cmd === 'stdio') {
    // stdout carries the MCP protocol: logs go to stderr, the admin API still listens if enabled.
    const gw = await createGateway(cfg, { logger: false });
    if (cfg.admin.enabled && cfg.listen.port)
      await gw.app
        .listen({ host: cfg.listen.host, port: cfg.listen.port })
        .catch((e: Error) => console.error(`admin API not started: ${e.message}`));
    await gw.serveStdio();
    const stop = async (): Promise<void> => {
      await gw.close();
      await stopTelemetry();
      process.exit(0);
    };
    process.stdin.on('end', () => void stop());
    process.on('SIGTERM', () => void stop());
    return;
  }

  if (cmd !== 'serve') {
    console.error(`unknown command ${cmd}; use serve or stdio`);
    process.exit(64);
  }
  const gw = await createGateway(cfg);
  const addr = await gw.listen();
  gw.app.log.info(
    { addr, servers: cfg.servers.map((s) => s.name), bundle: gw.policies.bundle.bundle.id },
    'warden gateway listening',
  );
  const stop = async (): Promise<void> => {
    gw.app.log.info('shutting down');
    await gw.close();
    await stopTelemetry();
    process.exit(0);
  };
  process.on('SIGINT', () => void stop());
  process.on('SIGTERM', () => void stop());
}

main().catch((e: unknown) => {
  console.error(`warden-gateway: ${(e as Error).stack ?? String(e)}`);
  process.exit(1);
});
