/**
 * Tool description pinning.
 *
 * At approval Warden pins a SHA-256 of the tool's name, description and schemas. Any
 * later change (a "rug pull") quarantines the tool until a person approves the new
 * definition. Quarantined and pending tools are hidden from the agent and cannot be called.
 */
import { canonicalJson, sha256Hex } from '@warden/policy-ir';
import type { KV } from './kv.js';

export interface ToolDefinition {
  name: string;
  title?: string;
  description?: string;
  inputSchema?: unknown;
  outputSchema?: unknown;
  annotations?: Record<string, unknown>;
}

export type PinStatus = 'approved' | 'pending' | 'quarantined';

export interface PinRecord {
  qualifiedName: string;
  server: string;
  tool: string;
  status: PinStatus;
  /** Hash of the approved definition (empty until first approval). */
  approvedHash: string;
  /** Hash of the definition most recently seen upstream. */
  currentHash: string;
  reason: string;
  findings: string[];
  firstSeen: string;
  lastSeen: string;
  approvedAt?: string;
  approvedBy?: string;
  current: ToolDefinition;
  approved?: ToolDefinition;
}

export function definitionHash(def: ToolDefinition): string {
  return sha256Hex(
    canonicalJson({
      name: def.name,
      title: def.title ?? null,
      description: def.description ?? '',
      inputSchema: def.inputSchema ?? null,
      outputSchema: def.outputSchema ?? null,
      annotations: def.annotations ?? null,
    }),
  );
}

export class PinStore {
  constructor(private kv: KV) {}

  private key(q: string): string {
    return `warden:pin:${q}`;
  }

  async get(qualifiedName: string): Promise<PinRecord | null> {
    const raw = await this.kv.get(this.key(qualifiedName));
    return raw ? (JSON.parse(raw) as PinRecord) : null;
  }

  async put(rec: PinRecord): Promise<void> {
    await this.kv.set(this.key(rec.qualifiedName), JSON.stringify(rec));
  }

  async list(): Promise<PinRecord[]> {
    const keys = await this.kv.keys('warden:pin:');
    const out: PinRecord[] = [];
    for (const k of keys) {
      const raw = await this.kv.get(k);
      if (raw) out.push(JSON.parse(raw) as PinRecord);
    }
    return out.sort((a, b) => a.qualifiedName.localeCompare(b.qualifiedName));
  }

  async approve(qualifiedName: string, by: string): Promise<PinRecord | null> {
    const rec = await this.get(qualifiedName);
    if (!rec) return null;
    rec.status = 'approved';
    rec.approvedHash = rec.currentHash;
    rec.approved = rec.current;
    rec.approvedAt = new Date().toISOString();
    rec.approvedBy = by;
    rec.reason = `approved by ${by}`;
    await this.put(rec);
    return rec;
  }

  async quarantine(qualifiedName: string, reason: string): Promise<PinRecord | null> {
    const rec = await this.get(qualifiedName);
    if (!rec) return null;
    rec.status = 'quarantined';
    rec.reason = reason;
    await this.put(rec);
    return rec;
  }
}
