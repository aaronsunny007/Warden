/**
 * Session taint tracking.
 *
 * Once an agent reads untrusted content (web, email, tickets, an untrusted server),
 * its session is tainted and later high-risk tool calls face stricter policy. Values
 * from the user's own request and from trusted outputs are kept as provenance, so a
 * tainted session can still send to a recipient the user actually named.
 */
import type { KV } from './kv.js';

export interface TaintSource {
  tool: string;
  at: string;
  reason: string;
}

export interface SessionState {
  sessionId: string;
  tainted: boolean;
  sources: TaintSource[];
  /** The user's own request(s), as declared by the host. */
  userRequests: string[];
  /** Short excerpts of trusted, pre-taint outputs. */
  trustedOutputs: string[];
  calls: number;
  blocked: number;
  createdAt: string;
  updatedAt: string;
}

const MAX_TRUSTED = 50;
const MAX_EXCERPT = 4096;
const TTL = 60 * 60 * 24;

export class TaintStore {
  constructor(private kv: KV) {}

  private key(id: string): string {
    return `warden:session:${id}`;
  }

  /** Taint lives in its own set-only key: a concurrent read-modify-write can never clear it. */
  private taintKey(id: string): string {
    return `warden:taint:${id}`;
  }

  async get(sessionId: string): Promise<SessionState> {
    const [raw, flag] = await Promise.all([
      this.kv.get(this.key(sessionId)),
      this.kv.get(this.taintKey(sessionId)),
    ]);
    const now = new Date().toISOString();
    const s: SessionState = raw
      ? (JSON.parse(raw) as SessionState)
      : {
          sessionId,
          tainted: false,
          sources: [],
          userRequests: [],
          trustedOutputs: [],
          calls: 0,
          blocked: 0,
          createdAt: now,
          updatedAt: now,
        };
    if (flag) s.tainted = true;
    return s;
  }

  private async put(s: SessionState): Promise<SessionState> {
    s.updatedAt = new Date().toISOString();
    await this.kv.set(this.key(s.sessionId), JSON.stringify(s), TTL);
    return s;
  }

  async update(sessionId: string, fn: (s: SessionState) => void): Promise<SessionState> {
    const s = await this.get(sessionId);
    fn(s);
    return this.put(s);
  }

  async taint(sessionId: string, source: TaintSource): Promise<SessionState> {
    await this.kv.set(this.taintKey(sessionId), JSON.stringify(source), TTL);
    return this.update(sessionId, (s) => {
      s.tainted = true;
      if (s.sources.length < 100) s.sources.push(source);
    });
  }

  async addUserRequest(sessionId: string, text: string): Promise<SessionState> {
    return this.update(sessionId, (s) => {
      if (text && !s.userRequests.includes(text)) s.userRequests.push(text.slice(0, MAX_EXCERPT));
    });
  }

  async addTrustedOutput(sessionId: string, text: string): Promise<void> {
    if (!text) return;
    await this.update(sessionId, (s) => {
      s.trustedOutputs.push(text.slice(0, MAX_EXCERPT));
      if (s.trustedOutputs.length > MAX_TRUSTED)
        s.trustedOutputs.splice(0, s.trustedOutputs.length - MAX_TRUSTED);
    });
  }

  provenance(s: SessionState): string[] {
    return [...s.userRequests, ...s.trustedOutputs];
  }

  async list(): Promise<SessionState[]> {
    const keys = await this.kv.keys('warden:session:');
    const out: SessionState[] = [];
    for (const k of keys.slice(0, 500)) {
      const raw = await this.kv.get(k);
      if (raw) out.push(JSON.parse(raw) as SessionState);
    }
    return out.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  }

  async reset(sessionId: string): Promise<void> {
    await Promise.all([this.kv.del(this.key(sessionId)), this.kv.del(this.taintKey(sessionId))]);
  }
}
