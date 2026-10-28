/**
 * Connections to the real MCP servers. Warden is an MCP client to each of them,
 * over stdio or Streamable HTTP, and re-lists their tools (bypassing the SDK's
 * cache) so a description changed after approval is always seen.
 */
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { StdioClientTransport, getDefaultEnvironment } from '@modelcontextprotocol/client/stdio';
import type { ServerConfig } from './config.js';
import type { ToolResult } from './inspector.js';
import type { Metrics } from './metrics.js';
import type { ToolDefinition } from './state/pins.js';

export interface UpstreamTool {
  server: string;
  definition: ToolDefinition;
}

interface Conn {
  cfg: ServerConfig;
  client: Client | null;
  connecting: Promise<Client> | null;
  tools: ToolDefinition[];
  listedAt: number;
  lastError: string;
}

const VERSION = '0.1.0';

export class UpstreamManager {
  private conns = new Map<string, Conn>();
  private changeListeners = new Set<(server: string) => void>();

  constructor(
    servers: ServerConfig[],
    private metrics: Metrics,
    private callTimeoutMs = 60_000,
  ) {
    for (const s of servers.filter((x) => x.enabled)) {
      this.conns.set(s.name, {
        cfg: s,
        client: null,
        connecting: null,
        tools: [],
        listedAt: 0,
        lastError: '',
      });
    }
  }

  onToolsChanged(fn: (server: string) => void): void {
    this.changeListeners.add(fn);
  }

  serverConfig(name: string): ServerConfig | undefined {
    return this.conns.get(name)?.cfg;
  }

  servers(): Array<{
    name: string;
    connected: boolean;
    tools: number;
    lastError: string;
    trust: string;
    transport: string;
  }> {
    return [...this.conns.values()].map((c) => ({
      name: c.cfg.name,
      connected: c.client !== null,
      tools: c.tools.length,
      lastError: c.lastError,
      trust: c.cfg.trust,
      transport: c.cfg.transport.type,
    }));
  }

  private async connect(conn: Conn): Promise<Client> {
    if (conn.client) return conn.client;
    if (conn.connecting) return conn.connecting;
    conn.connecting = (async () => {
      const t = conn.cfg.transport;
      const transport =
        t.type === 'stdio'
          ? new StdioClientTransport({
              command: t.command,
              args: t.args,
              env: { ...getDefaultEnvironment(), ...t.env },
              cwd: t.cwd,
              stderr: 'inherit',
            })
          : new StreamableHTTPClientTransport(new URL(t.url), { requestInit: { headers: t.headers } });
      const client = new Client(
        { name: 'warden-gateway', version: VERSION },
        {
          listChanged: {
            tools: {
              onChanged: () => {
                conn.listedAt = 0;
                for (const l of this.changeListeners) l(conn.cfg.name);
              },
            },
          },
        },
      );
      client.onclose = () => {
        conn.client = null;
        this.metrics.upstreamUp.set({ server: conn.cfg.name }, 0);
      };
      await client.connect(transport);
      conn.client = client;
      conn.lastError = '';
      this.metrics.upstreamUp.set({ server: conn.cfg.name }, 1);
      return client;
    })();
    try {
      return await conn.connecting;
    } catch (e) {
      conn.lastError = (e as Error).message;
      this.metrics.upstreamUp.set({ server: conn.cfg.name }, 0);
      throw e;
    } finally {
      conn.connecting = null;
    }
  }

  async start(): Promise<void> {
    await Promise.all([...this.conns.values()].map((c) => this.connect(c).catch(() => undefined)));
  }

  /** Fresh tool lists from every server whose list is older than maxAgeMs. */
  async listAll(maxAgeMs: number): Promise<UpstreamTool[]> {
    const out: UpstreamTool[] = [];
    await Promise.all(
      [...this.conns.values()].map(async (c) => {
        if (Date.now() - c.listedAt > maxAgeMs) {
          try {
            const client = await this.connect(c);
            const res = await client.listTools(undefined, { cacheMode: 'bypass' });
            c.tools = res.tools.map((t) => ({
              name: t.name,
              title: t.title,
              description: t.description,
              inputSchema: t.inputSchema,
              outputSchema: t.outputSchema,
              annotations: t.annotations as Record<string, unknown> | undefined,
            }));
            c.listedAt = Date.now();
          } catch (e) {
            c.lastError = (e as Error).message;
          }
        }
        for (const d of c.tools) out.push({ server: c.cfg.name, definition: d });
      }),
    );
    return out;
  }

  async call(server: string, tool: string, args: Record<string, unknown>): Promise<ToolResult> {
    const conn = this.conns.get(server);
    if (!conn) throw new Error(`unknown server ${server}`);
    const client = await this.connect(conn);
    const end = this.metrics.upstream.startTimer({ server });
    try {
      const res = (await client.callTool(
        { name: tool, arguments: args },
        { timeout: this.callTimeoutMs },
      )) as ToolResult;
      return res;
    } finally {
      end();
    }
  }

  async close(): Promise<void> {
    await Promise.all([...this.conns.values()].map((c) => c.client?.close().catch(() => undefined)));
  }
}
