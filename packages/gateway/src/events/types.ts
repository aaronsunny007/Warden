import type { Channel, RiskTier } from '@warden/policy-ir';

export type VerdictDecision =
  'allow' | 'block' | 'redact' | 'step_up' | 'quarantine_tool' | 'approved_step_up';

/** One explained, logged decision. Covers OWASP MCP08 (audit and telemetry). */
export interface Verdict {
  id: string;
  ts: string;
  sessionId: string;
  server: string;
  tool: string;
  channel: Channel | 'pin';
  riskTier: RiskTier;
  decision: VerdictDecision;
  /** Rules that were enforced. */
  ruleIds: string[];
  /** Rules that matched in shadow (or outside their canary bucket). */
  shadowRuleIds: string[];
  /** Highest detection layer consulted, and its score. */
  layer: 'L0' | 'L1' | 'L2' | 'L3' | 'pin' | 'taint' | 'failsafe';
  score: number | null;
  detector: Partial<Record<'L1' | 'L2' | 'L3', number>>;
  tainted: boolean;
  taintedNow: boolean;
  latencyMs: number;
  explanation: string;
  owasp: string[];
  evidence: Array<{ kind: string; field: string; detail?: string; text?: string }>;
  /** Policy bundle in force. */
  bundleId: string;
}

export interface WardenEvent {
  type: 'verdict' | 'pin' | 'approval' | 'policy' | 'session';
  ts: string;
  data: unknown;
}
