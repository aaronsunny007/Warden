/** Evaluates compiled rules against a message: modes, canary bucketing and action precedence. */
import { createHash } from 'node:crypto';
import type { CompiledRule, Evidence } from './compiler.js';
import type { ActionType, Channel, MessageContext, Mode, RiskTier } from './schema.js';

export type Decision = ActionType | 'allow';

/** Higher wins when several enforcing rules match. */
export const ACTION_PRECEDENCE: Record<Decision, number> = {
  allow: 0,
  taint_session: 1,
  redact: 2,
  step_up: 3,
  block: 4,
  quarantine_tool: 5,
};

export interface RuleMatch {
  ruleId: string;
  version: number;
  hash: string;
  mode: Mode;
  action: ActionType;
  severity: string;
  message?: string;
  owasp: string[];
  evidence: Evidence[];
}

export interface Evaluation {
  decision: Decision;
  /** Matches that were enforced (mode enforce, or canary inside the bucket). */
  enforced: RuleMatch[];
  /** Matches that were only logged (shadow, or canary outside the bucket). */
  observed: RuleMatch[];
  /** Whether any enforced or observed rule asked to taint the session. */
  taint: boolean;
}

/** Deterministic bucket in [0, 100): the same session always lands in the same bucket for a rule. */
export function canaryBucket(sessionId: string, ruleId: string): number {
  const h = createHash('sha256').update(`${sessionId}\u0000${ruleId}`).digest();
  return (h.readUInt32BE(0) % 10000) / 100;
}

export interface EvaluateOptions {
  /** Override every rule's mode, e.g. 'enforce' when the gate replays a candidate. */
  forceMode?: Mode;
}

export class PolicySet {
  readonly rules: readonly CompiledRule[];

  constructor(rules: readonly CompiledRule[]) {
    this.rules = rules;
  }

  /** Rules in scope for a message, ignoring mode 'off'. */
  scoped(
    ctx: Pick<MessageContext, 'channel' | 'server' | 'tool' | 'riskTier' | 'tainted'>,
    opts: EvaluateOptions = {},
  ): CompiledRule[] {
    return this.rules.filter((r) => (opts.forceMode ?? r.rule.mode) !== 'off' && r.inScope(ctx));
  }

  needsDetector(ctx: {
    channel: Channel;
    server: string;
    tool: string;
    riskTier: RiskTier;
    tainted: boolean;
  }): boolean {
    return this.scoped(ctx).some((r) => r.needsDetector);
  }

  evaluate(ctx: MessageContext, opts: EvaluateOptions = {}): Evaluation {
    const enforced: RuleMatch[] = [];
    const observed: RuleMatch[] = [];
    let taint = false;
    for (const r of this.scoped(ctx, opts)) {
      const ev = r.match(ctx);
      if (!ev) continue;
      const mode = opts.forceMode ?? r.rule.mode;
      const m: RuleMatch = {
        ruleId: r.rule.id,
        version: r.rule.version,
        hash: r.hash,
        mode,
        action: r.rule.action.type,
        severity: r.rule.severity,
        message: r.rule.action.message,
        owasp: r.rule.owasp,
        evidence: ev,
      };
      const enforce =
        mode === 'enforce' ||
        (mode === 'canary' && canaryBucket(ctx.sessionId, r.rule.id) < r.rule.canaryPercent);
      if (enforce) enforced.push(m);
      else observed.push(m);
      if (r.rule.action.type === 'taint_session' && enforce) taint = true;
    }
    let decision: Decision = 'allow';
    for (const m of enforced)
      if (ACTION_PRECEDENCE[m.action] > ACTION_PRECEDENCE[decision]) decision = m.action;
    if (decision === 'taint_session') decision = 'allow';
    return { decision, enforced, observed, taint };
  }
}
