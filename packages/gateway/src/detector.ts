/**
 * Client for the Python detection service (L1 embeddings, L2 classifier, L3 LLM judge).
 * The service decides how far to escalate; the gateway passes the sink's risk tier
 * and enforces a hard timeout. Results are cached by content hash.
 */
import { sha256Hex, type Channel, type RiskTier } from '@warden/policy-ir';
import type { KV } from './state/kv.js';

export interface LayerScore {
  layer: 'L1' | 'L2' | 'L3';
  score: number;
  latencyMs: number;
  label?: string;
  detail?: string;
}

export interface DetectorResult {
  verdict: 'benign' | 'malicious' | 'uncertain';
  score: number;
  layers: LayerScore[];
  /** True when the service could not be reached or timed out. */
  unavailable: boolean;
  cached: boolean;
  latencyMs: number;
}

export interface DetectRequest {
  text: string;
  channel: Channel;
  riskTier: RiskTier;
  sessionId: string;
  tool: string;
}

export interface Detector {
  detect(req: DetectRequest): Promise<DetectorResult>;
}

export const UNAVAILABLE: DetectorResult = {
  verdict: 'uncertain',
  score: 0,
  layers: [],
  unavailable: true,
  cached: false,
  latencyMs: 0,
};

export class HttpDetector implements Detector {
  constructor(
    private url: string,
    private timeoutMs: number,
    private cache: KV | null,
    private cacheTtl: number,
  ) {}

  async detect(req: DetectRequest): Promise<DetectorResult> {
    const started = performance.now();
    const key = `warden:detect:${sha256Hex(`${req.channel}|${req.riskTier}|${req.text}`)}`;
    if (this.cache) {
      const hit = await this.cache.get(key);
      if (hit)
        return {
          ...(JSON.parse(hit) as DetectorResult),
          cached: true,
          latencyMs: performance.now() - started,
        };
    }
    try {
      const res = await fetch(`${this.url.replace(/\/$/, '')}/v1/detect`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          text: req.text.slice(0, 32768),
          channel: req.channel,
          risk_tier: req.riskTier,
          session_id: req.sessionId,
          tool: req.tool,
        }),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      if (!res.ok) return { ...UNAVAILABLE, latencyMs: performance.now() - started };
      const body = (await res.json()) as {
        verdict: DetectorResult['verdict'];
        score: number;
        layers: Array<{
          layer: LayerScore['layer'];
          score: number;
          latency_ms: number;
          label?: string;
          detail?: string;
        }>;
      };
      const result: DetectorResult = {
        verdict: body.verdict,
        score: body.score,
        layers: body.layers.map((l) => ({
          layer: l.layer,
          score: l.score,
          latencyMs: l.latency_ms,
          label: l.label,
          detail: l.detail,
        })),
        unavailable: false,
        cached: false,
        latencyMs: performance.now() - started,
      };
      if (this.cache && this.cacheTtl > 0) await this.cache.set(key, JSON.stringify(result), this.cacheTtl);
      return result;
    } catch {
      return { ...UNAVAILABLE, latencyMs: performance.now() - started };
    }
  }
}

/** Used when no detection service is configured: rules-only (L0) operation. */
export class NullDetector implements Detector {
  async detect(): Promise<DetectorResult> {
    return { ...UNAVAILABLE };
  }
}

export function scoresOf(r: DetectorResult): Partial<Record<'L1' | 'L2' | 'L3', number>> {
  const out: Partial<Record<'L1' | 'L2' | 'L3', number>> = {};
  for (const l of r.layers) out[l.layer] = l.score;
  return out;
}
