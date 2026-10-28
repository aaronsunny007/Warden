/** Mirrors the gateway's verdict/admin shapes and the control plane's records. */
export type Decision = 'allow' | 'block' | 'redact' | 'step_up' | 'quarantine_tool' | 'approved_step_up';

export interface Verdict {
  id: string;
  ts: string;
  sessionId: string;
  server: string;
  tool: string;
  channel: string;
  riskTier: string;
  decision: Decision;
  ruleIds: string[];
  shadowRuleIds: string[];
  layer: string;
  score: number | null;
  tainted: boolean;
  taintedNow: boolean;
  latencyMs: number;
  explanation: string;
  owasp: string[];
  evidence: Array<{ kind: string; field: string; detail?: string; text?: string }>;
  bundleId: string;
}

export interface ToolRow {
  name: string;
  server: string;
  tool: string;
  riskTier: string;
  taintsSession: boolean;
  status: 'approved' | 'pending' | 'quarantined';
  usable: boolean;
  reason: string;
  findings: string[];
  approvedHash: string;
  currentHash: string;
  description?: string;
}

export interface CoverageItem {
  id: string;
  name: string;
  controls: string[];
  rules: string[];
  enforcedRules: number;
}

export interface Control {
  id: string;
  name: string;
  owasp: string[];
  detail: string;
}

export interface ApprovalRow {
  id: string;
  sessionId: string;
  qualifiedTool: string;
  reason: string;
  ruleIds: string[];
  state: 'pending' | 'approved' | 'denied';
  createdAt: string;
}

export interface Status {
  version: string;
  servers: Array<{
    name: string;
    connected: boolean;
    tools: number;
    trust: string;
    transport: string;
    lastError: string;
  }>;
  bundle: { id: string; rules: number; loadedAt: string; errors: unknown[] };
  tools: Record<string, number>;
  detector: string | null;
}

export interface CandidateRow {
  id: string;
  author: string;
  status: string;
  stage: string;
  rule_id: string;
  rule_hash: string;
  report_id: string | null;
  created_at: string;
}
