/**
 * Step-up approvals: a high-risk call that cannot be traced to the user's request waits
 * for a person. The agent gets a safe error naming the approval; once approved, the same
 * call (same session, tool and arguments) is allowed for a limited time.
 */
import { randomUUID } from 'node:crypto';
import { canonicalJson, sha256Hex } from '@warden/policy-ir';
import type { KV } from './kv.js';

export type ApprovalState = 'pending' | 'approved' | 'denied';

export interface StepUpRequest {
  id: string;
  sessionId: string;
  qualifiedTool: string;
  argsHash: string;
  args: unknown;
  reason: string;
  ruleIds: string[];
  state: ApprovalState;
  createdAt: string;
  decidedAt?: string;
  decidedBy?: string;
}

export function argsHash(args: unknown): string {
  return sha256Hex(canonicalJson(args ?? {}));
}

export class ApprovalStore {
  constructor(
    private kv: KV,
    private ttlSeconds: number,
  ) {}

  private key(id: string): string {
    return `warden:approval:${id}`;
  }
  private callKey(sessionId: string, tool: string, hash: string): string {
    return `warden:approval-call:${sessionId}:${tool}:${hash}`;
  }

  async request(
    sessionId: string,
    qualifiedTool: string,
    args: unknown,
    reason: string,
    ruleIds: string[],
  ): Promise<StepUpRequest> {
    const hash = argsHash(args);
    const existing = await this.kv.get(this.callKey(sessionId, qualifiedTool, hash));
    if (existing) {
      const prev = await this.get(existing);
      if (prev && prev.state === 'pending') return prev;
    }
    const req: StepUpRequest = {
      id: randomUUID(),
      sessionId,
      qualifiedTool,
      argsHash: hash,
      args,
      reason,
      ruleIds,
      state: 'pending',
      createdAt: new Date().toISOString(),
    };
    await this.kv.set(this.key(req.id), JSON.stringify(req), this.ttlSeconds);
    await this.kv.set(this.callKey(sessionId, qualifiedTool, hash), req.id, this.ttlSeconds);
    return req;
  }

  async get(id: string): Promise<StepUpRequest | null> {
    const raw = await this.kv.get(this.key(id));
    return raw ? (JSON.parse(raw) as StepUpRequest) : null;
  }

  /** Approved for exactly this call? */
  async isApproved(sessionId: string, qualifiedTool: string, args: unknown): Promise<boolean> {
    const id = await this.kv.get(this.callKey(sessionId, qualifiedTool, argsHash(args)));
    if (!id) return false;
    const req = await this.get(id);
    return req?.state === 'approved';
  }

  async decide(id: string, state: 'approved' | 'denied', by: string): Promise<StepUpRequest | null> {
    const req = await this.get(id);
    if (!req) return null;
    req.state = state;
    req.decidedAt = new Date().toISOString();
    req.decidedBy = by;
    await this.kv.set(this.key(id), JSON.stringify(req), this.ttlSeconds);
    return req;
  }

  async list(): Promise<StepUpRequest[]> {
    const out: StepUpRequest[] = [];
    for (const k of await this.kv.keys('warden:approval:')) {
      const raw = await this.kv.get(k);
      if (raw) out.push(JSON.parse(raw) as StepUpRequest);
    }
    return out.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }
}
