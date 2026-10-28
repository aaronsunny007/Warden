import { createHash } from 'node:crypto';

/**
 * Canonical JSON: object keys sorted, no whitespace, undefined dropped.
 * Hashes and signatures are computed over this form only, and only by this package,
 * so there is exactly one implementation to trust.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortValue);
  if (v && typeof v === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v as Record<string, unknown>).sort()) {
      const val = (v as Record<string, unknown>)[k];
      if (val !== undefined) out[k] = sortValue(val);
    }
    return out;
  }
  if (typeof v === 'number' && !Number.isFinite(v)) throw new Error('non-finite number in canonical JSON');
  return v;
}

export function sha256Hex(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}
