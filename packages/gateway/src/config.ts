/** Gateway configuration (YAML), with ${ENV} and ${ENV:-default} interpolation. */
import { readFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { RISK_TIERS } from '@warden/policy-ir';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';

const ToolGlob = z.string().min(1).max(128);

const StdioTransport = z
  .object({
    type: z.literal('stdio'),
    command: z.string().min(1),
    args: z.array(z.string()).default([]),
    env: z.record(z.string(), z.string()).default({}),
    cwd: z.string().optional(),
  })
  .strict();

const HttpTransport = z
  .object({
    type: z.literal('http'),
    url: z.string().url(),
    headers: z.record(z.string(), z.string()).default({}),
  })
  .strict();

const ToolOverride = z
  .object({
    risk: z.enum(RISK_TIERS).optional(),
    taintsSession: z.boolean().optional(),
  })
  .strict();

export const ServerConfig = z
  .object({
    name: z.string().regex(/^[a-z][a-z0-9_-]{0,31}$/, 'server names are lower-case identifiers'),
    transport: z.discriminatedUnion('type', [StdioTransport, HttpTransport]),
    /** Outputs of an untrusted server always taint the session. */
    trust: z.enum(['trusted', 'untrusted']).default('untrusted'),
    /** Tools on a trusted server whose outputs carry outside content (email bodies, web pages, tickets). */
    taintSources: z.array(ToolGlob).default([]),
    tools: z.record(z.string(), ToolOverride).default({}),
    enabled: z.boolean().default(true),
  })
  .strict();
export type ServerConfig = z.infer<typeof ServerConfig>;

export const GatewayConfig = z
  .object({
    listen: z
      .object({
        host: z.string().default('127.0.0.1'),
        port: z.number().int().min(0).max(65535).default(8787),
      })
      .strict()
      .default({ host: '127.0.0.1', port: 8787 }),
    /** Host names the MCP endpoint answers to (DNS rebinding protection). Empty = any. */
    allowedHosts: z.array(z.string()).default([]),
    admin: z
      .object({ token: z.string().default(''), enabled: z.boolean().default(true) })
      .strict()
      .default({ token: '', enabled: true }),
    servers: z.array(ServerConfig).default([]),
    detector: z
      .object({
        url: z.string().default(''),
        timeoutMs: z.number().int().min(10).max(30000).default(250),
        /** Channels sent to the detection cascade. */
        channels: z.array(z.enum(['description', 'arguments', 'output'])).default(['description', 'output']),
        cacheTtlSeconds: z.number().int().min(0).default(600),
      })
      .strict()
      .default({ url: '', timeoutMs: 250, channels: ['description', 'output'], cacheTtlSeconds: 600 }),
    policy: z
      .object({
        bundle: z.string().default(''),
        trustedKeys: z.record(z.string(), z.string()).default({}),
        allowUnsigned: z.boolean().default(false),
        /** Enforcement needs a human approval (G8). Only lab and CI configs should turn this off. */
        requireHumanApproval: z.boolean().default(true),
        watch: z.boolean().default(true),
      })
      .strict()
      .default({
        bundle: '',
        trustedKeys: {},
        allowUnsigned: false,
        requireHumanApproval: true,
        watch: true,
      }),
    pins: z
      .object({
        /** Pinning and description scanning. Off only for the B0-B2 evaluation baselines. */
        enabled: z.boolean().default(true),
        store: z.enum(['memory', 'file', 'redis']).default('memory'),
        path: z.string().default('var/pins.json'),
        /** Approve a first-seen tool automatically when its description scan is clean. */
        autoApproveClean: z.boolean().default(true),
        /** Re-list upstream tools at most this often to catch silent rug pulls. */
        refreshSeconds: z.number().int().min(0).default(30),
      })
      .strict()
      .default({
        enabled: true,
        store: 'memory',
        path: 'var/pins.json',
        autoApproveClean: true,
        refreshSeconds: 30,
      }),
    state: z
      .object({ redisUrl: z.string().default('') })
      .strict()
      .default({ redisUrl: '' }),
    events: z
      .object({
        jsonl: z.string().default(''),
        kafka: z
          .object({
            brokers: z.array(z.string()).min(1),
            topic: z.string().default('warden.verdicts'),
            clientId: z.string().default('warden-gateway'),
          })
          .strict()
          .optional(),
        postgres: z.object({ url: z.string() }).strict().optional(),
        ringSize: z.number().int().min(10).max(200000).default(2000),
        /** Lab only: also emit the exact message context each verdict was computed on (feeds the G2 benign corpus). */
        recordMessages: z.boolean().default(false),
      })
      .strict()
      .default({ jsonl: '', ringSize: 2000, recordMessages: false }),
    spotlight: z
      .object({ enabled: z.boolean().default(true) })
      .strict()
      .default({ enabled: true }),
    failure: z
      .object({
        /** What happens when a detection layer is unavailable or times out. */
        highRisk: z.enum(['closed', 'open']).default('closed'),
        readOnly: z.enum(['closed', 'open']).default('open'),
      })
      .strict()
      .default({ highRisk: 'closed', readOnly: 'open' }),
    stepUp: z
      .object({
        /** Try MCP elicitation (or input_required) before falling back to the approval queue. */
        elicitation: z.boolean().default(true),
        approvalTtlSeconds: z.number().int().min(10).default(900),
      })
      .strict()
      .default({ elicitation: true, approvalTtlSeconds: 900 }),
    telemetry: z
      .object({ otlpEndpoint: z.string().default(''), serviceName: z.string().default('warden-gateway') })
      .strict()
      .default({ otlpEndpoint: '', serviceName: 'warden-gateway' }),
  })
  .strict();
export type GatewayConfig = z.infer<typeof GatewayConfig>;

export function interpolateEnv(text: string, env: NodeJS.ProcessEnv = process.env): string {
  return text.replace(
    /\$\{([A-Z0-9_]+)(?::-([^}]*))?\}/g,
    (_m, name: string, def?: string) => env[name] ?? def ?? '',
  );
}

export function parseConfig(
  yamlText: string,
  baseDir = process.cwd(),
  env: NodeJS.ProcessEnv = process.env,
): GatewayConfig {
  const raw = parseYaml(interpolateEnv(yamlText, env)) ?? {};
  const cfg = GatewayConfig.parse(raw);
  const abs = (p: string): string => (p && !isAbsolute(p) ? resolve(baseDir, p) : p);
  cfg.policy.bundle = abs(cfg.policy.bundle);
  cfg.pins.path = abs(cfg.pins.path);
  cfg.events.jsonl = abs(cfg.events.jsonl);
  // Trusted keys may be inline PEM or a path to a PEM file.
  for (const [id, v] of Object.entries(cfg.policy.trustedKeys)) {
    if (!v.includes('BEGIN PUBLIC KEY')) cfg.policy.trustedKeys[id] = readFileSync(abs(v), 'utf8');
  }
  for (const s of cfg.servers)
    if (s.transport.type === 'stdio' && s.transport.cwd) s.transport.cwd = abs(s.transport.cwd);
  return cfg;
}

export function loadConfig(path: string, env: NodeJS.ProcessEnv = process.env): GatewayConfig {
  return parseConfig(readFileSync(path, 'utf8'), dirname(resolve(path)), env);
}
