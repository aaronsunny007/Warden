/** Risk tiers for tools: config override, then MCP annotations, then the tool name. */
import type { RiskTier } from '@warden/policy-ir';

export interface ToolAnnotations {
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

const FINANCIAL_DESTRUCTIVE =
  /(^|_|-)(pay|payment|refund|transfer|charge|purchase|withdraw|delete|remove|drop|destroy|wipe|purge|revoke|exec|execute|shell|run_command|deploy|truncate)(_|-|$)/i;
const EXTERNAL_SEND =
  /(^|_|-)(send|email|mail|post|publish|share|forward|upload|webhook|notify|message|sms|tweet|reply|invite|fetch|browse|http|request|download|open_url|pull_request|create_pr)(_|-|$)/i;
const INTERNAL_WRITE =
  /(^|_|-)(write|update|create|set|add|edit|insert|save|move|rename|close|assign|label|comment|append|patch|upsert)(_|-|$)/i;
const READ_ONLY =
  /(^|_|-)(get|list|read|search|find|lookup|query|describe|show|view|count|check|status)(_|-|$)/i;

export const RISK_RANK: Record<RiskTier, number> = {
  read_only: 0,
  internal_write: 1,
  external_send: 2,
  financial_destructive: 3,
};

export function isHighRisk(t: RiskTier): boolean {
  return RISK_RANK[t] >= RISK_RANK.external_send;
}

export function classifyRisk(name: string, annotations?: ToolAnnotations, override?: RiskTier): RiskTier {
  if (override) return override;
  // Name signals for money and destruction outrank a read-only hint the server may have set itself.
  if (FINANCIAL_DESTRUCTIVE.test(name)) return 'financial_destructive';
  if (annotations?.destructiveHint === true && annotations.readOnlyHint !== true)
    return 'financial_destructive';
  if (EXTERNAL_SEND.test(name)) return 'external_send';
  if (annotations?.openWorldHint === true && annotations.readOnlyHint !== true) return 'external_send';
  if (INTERNAL_WRITE.test(name)) return 'internal_write';
  if (annotations?.readOnlyHint === true || READ_ONLY.test(name)) return 'read_only';
  return 'internal_write';
}
