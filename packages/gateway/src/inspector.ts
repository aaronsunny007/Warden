/**
 * The inspector: Warden's three interception points.
 *
 *   descriptions (tools/list)  -> pin, scan, quarantine
 *   arguments    (tools/call)  -> L0 rules, taint-aware sink policy, step-up
 *   outputs      (results)     -> detection cascade, redact/block, spotlight, taint
 *
 * Cheap checks run first; the detection service is consulted only when a rule in
 * scope needs its scores, and a missing verdict falls back by risk tier.
 */
import { randomUUID } from 'node:crypto';
import { trace, SpanStatusCode } from '@opentelemetry/api';
import {
  normalize,
  type Channel,
  type Evaluation,
  type MessageContext,
  type RiskTier,
  type RuleMatch,
} from '@warden/policy-ir';
import type { GatewayConfig } from './config.js';
import { scoresOf, type Detector, type DetectorResult } from './detector.js';
import type { EventBus } from './events/bus.js';
import type { Verdict, VerdictDecision } from './events/types.js';
import type { Metrics } from './metrics.js';
import type { PolicyStore } from './policy-store.js';
import { isHighRisk } from './risk.js';
import { spotlight } from './spotlight.js';
import type { ToolDefinition } from './state/pins.js';
import type { TaintStore } from './state/taint.js';

const tracer = trace.getTracer('warden-gateway');

export interface ToolInfo {
  server: string;
  tool: string;
  qualified: string;
  riskTier: RiskTier;
  /** Outputs carry outside content: reading them taints the session. */
  taintsSession: boolean;
  definition: ToolDefinition;
}

export interface ContentBlock {
  type: string;
  text?: string;
  [k: string]: unknown;
}

export interface ToolResult {
  content: ContentBlock[];
  structuredContent?: unknown;
  isError?: boolean;
  [k: string]: unknown;
}

export interface Inspection {
  decision: VerdictDecision;
  verdict: Verdict;
  evaluation: Evaluation;
}

function explain(decision: VerdictDecision, ev: Evaluation, extra: string[]): string {
  const parts = ev.enforced.map(
    (m) => `${m.ruleId}${m.message ? ` (${m.message})` : ''}: ${summariseEvidence(m)}`,
  );
  const shadow = ev.observed.length ? ` [shadow: ${ev.observed.map((m) => m.ruleId).join(', ')}]` : '';
  const body = [...parts, ...extra].join('; ');
  return `${decision}${body ? ` — ${body}` : ''}${shadow}`;
}

function summariseEvidence(m: RuleMatch): string {
  return m.evidence
    .slice(0, 3)
    .map((e) => `${e.kind}${e.detail ? `=${e.detail}` : e.span ? `="${e.span.text.slice(0, 60)}"` : ''}`)
    .join(', ');
}

export function resultText(result: ToolResult): string {
  const parts: string[] = [];
  for (const block of result.content ?? []) {
    if (typeof block.text === 'string') parts.push(block.text);
    else if (
      block.type === 'resource' &&
      block.resource &&
      typeof (block.resource as { text?: unknown }).text === 'string'
    ) {
      parts.push((block.resource as { text: string }).text);
    }
  }
  if (result.structuredContent !== undefined) parts.push(JSON.stringify(result.structuredContent));
  return parts.join('\n');
}

function deepReplace(v: unknown, fn: (s: string) => string): unknown {
  if (typeof v === 'string') return fn(v);
  if (Array.isArray(v)) return v.map((x) => deepReplace(x, fn));
  if (v && typeof v === 'object')
    return Object.fromEntries(
      Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, deepReplace(x, fn)]),
    );
  return v;
}

const MAX_PARAGRAPH = 1200;
/** Stage-2 sanitising scores each paragraph; beyond this many, withhold instead. */
const LOCALISE_MAX_UNITS = 16;
/** A paragraph is removed only if the detector alone scores it at least this high (the W-OUT-006 bar). */
const LOCALISE_BAR = 0.92;

// Tool outputs are often JSON text, where a paragraph break inside a string value is the two
// characters `\n` rather than a real newline. Treat both as breaks so an injected paragraph is
// removed on its own and the legitimate text around it survives.
const PARA_BREAK = /(\n\s*\n|(?:\\n){2,})/;
const LINE_BREAK = /(\n|\\n)/;
const JSON_PREFIX = /^\s*"[^"\\]{1,64}":\s*"/;
const JSON_SUFFIX = /["',\]}\s]+$/;
// Pretty-printed JSON puts one value per line, so a "paragraph" of it is not one idea.
const looksStructured = (t: string): boolean => /\n\s*["}\]]/.test(t) || /^\s*[[{]/.test(t);

/** The units redactResult operates on: paragraphs, or lines for long or JSON-structured text. */
export function splitUnits(text: string): string[] {
  const out: string[] = [];
  for (const para of text.split(PARA_BREAK)) {
    if (PARA_BREAK.test(para) && !para.trim().replace(/\\n/g, '')) continue;
    const units = para.length > MAX_PARAGRAPH || looksStructured(para) ? para.split(LINE_BREAK) : [para];
    for (const u of units) if (u !== '\n' && u !== '\\n' && u.trim().length >= 3) out.push(u);
  }
  return out;
}

/**
 * Redact the paragraph (or line, for long paragraphs) that contains each match, comparing on
 * normalised text so zero-width and look-alike tricks cannot hide a match. Hidden characters are
 * stripped. JSON structure around a redacted string value is preserved. Returns null if any match
 * cannot be located, so the caller can withhold the output.
 */
export function redactResult(result: ToolResult, matches: RuleMatch[]): ToolResult | null {
  const ids = [...new Set(matches.map((m) => m.ruleId))].join(',');
  const marker = `[REDACTED by Warden ${ids}: suspected injected instruction or secret]`;
  const needles = new Set<string>();
  const hidden = new Set<string>();
  for (const m of matches)
    for (const e of m.evidence) {
      if (!e.span?.text) continue;
      if (e.kind === 'hiddenUnicode') hidden.add(e.span.text);
      else if (e.span.text.trim().length >= 3) needles.add(normalize(e.span.text).toLowerCase());
    }
  const found = new Set<string>();
  const redactString = (text: string): string => {
    let t = text;
    for (const h of hidden) t = t.split(h).join('');
    if (!needles.size) return t;
    const paragraphs = t.split(PARA_BREAK);
    return paragraphs
      .map((para) => {
        if (PARA_BREAK.test(para) && !para.trim().replace(/\\n/g, '')) return para;
        const units = para.length > MAX_PARAGRAPH || looksStructured(para) ? para.split(LINE_BREAK) : [para];
        return units
          .map((u) => {
            if (u === '\n' || u === '\\n') return u;
            const n = normalize(u).toLowerCase();
            let hit = false;
            for (const needle of needles)
              if (n.includes(needle)) {
                found.add(needle);
                hit = true;
              }
            if (!hit) return u;
            const prefix = JSON_PREFIX.exec(u)?.[0] ?? '';
            const suffix = JSON_SUFFIX.exec(u.slice(prefix.length))?.[0] ?? '';
            return `${prefix}${marker}${suffix}`;
          })
          .join('');
      })
      .join('');
  };
  const content = (result.content ?? []).map((b) =>
    typeof b.text === 'string' ? { ...b, text: redactString(b.text) } : b,
  );
  const structured =
    result.structuredContent !== undefined ? deepReplace(result.structuredContent, redactString) : undefined;
  for (const n of needles) if (!found.has(n)) return null;
  return { ...result, content, ...(structured !== undefined ? { structuredContent: structured } : {}) };
}

export class Inspector {
  constructor(
    private cfg: GatewayConfig,
    private policies: PolicyStore,
    private detector: Detector,
    private taint: TaintStore,
    private bus: EventBus,
    private metrics: Metrics,
  ) {}

  private detectorWanted(channel: Channel): boolean {
    return Boolean(this.cfg.detector.url) && this.cfg.detector.channels.includes(channel);
  }

  /** Run the cascade if a rule in scope needs it. Returns scores and whether the fail-safe tripped. */
  private async cascade(ctx: MessageContext): Promise<{ result: DetectorResult | null; failsafe: boolean }> {
    const policy = this.policies.policy;
    if (!policy.needsDetector(ctx)) return { result: null, failsafe: false };
    if (!this.detectorWanted(ctx.channel)) {
      // Rules want scores but no detector is configured for this channel: rules-only mode, no fail-safe.
      return { result: null, failsafe: false };
    }
    const r = await this.detector.detect({
      text: ctx.text,
      channel: ctx.channel,
      riskTier: ctx.riskTier,
      sessionId: ctx.sessionId,
      tool: `${ctx.server}.${ctx.tool}`,
    });
    if (r.unavailable) {
      this.metrics.detectorFailures.inc({ channel: ctx.channel });
      const mode = isHighRisk(ctx.riskTier) ? this.cfg.failure.highRisk : this.cfg.failure.readOnly;
      return { result: r, failsafe: mode === 'closed' };
    }
    ctx.detector = scoresOf(r);
    return { result: r, failsafe: false };
  }

  /**
   * Try to turn a would-be block into a verified redaction, so legitimate content around an
   * injection is not lost with it. Two stages, each followed by a full re-check:
   *   1. remove the spans the rules located;
   *   2. if the detector still objects, score each paragraph and remove those that would trip the
   *      detector bar on their own.
   * The result is released only when the exact text to be delivered passes the whole policy and
   * detector cascade. A detector outage, an unlocatable span, too many paragraphs to score, or any
   * residual objection leaves the output withheld.
   */
  private async sanitise(
    ctx: MessageContext,
    result: ToolResult,
    ev: Evaluation,
  ): Promise<ToolResult | null> {
    const clean = async (r: ToolResult): Promise<boolean | null> => {
      const ctx2: MessageContext = { ...ctx, text: resultText(r) };
      const { result: det, failsafe } = await this.cascade(ctx2);
      if (failsafe || det?.unavailable) return null;
      const after = this.policies.policy.evaluate(ctx2);
      return after.decision === 'allow' || after.decision === 'taint_session';
    };

    let current = result;
    const located = ev.enforced.filter((m) => m.evidence.some((e) => e.span?.text));
    if (located.length) {
      const cleaned = redactResult(result, located);
      if (!cleaned) return null;
      if (resultText(cleaned) !== ctx.text) {
        current = cleaned;
        const ok = await clean(current);
        if (ok === null) return null;
        if (ok) return current;
      }
    }

    // Stage 2: detector-guided localisation.
    if (!this.detectorWanted('output')) return null;
    const units = splitUnits(resultText(current));
    if (!units.length || units.length > LOCALISE_MAX_UNITS) return null;
    const scored = await Promise.all(
      units.map((text) =>
        this.detector.detect({
          text,
          channel: 'output',
          riskTier: ctx.riskTier,
          sessionId: ctx.sessionId,
          tool: `${ctx.server}.${ctx.tool}`,
        }),
      ),
    );
    if (scored.some((r) => r.unavailable)) return null;
    const flagged = units.filter(
      (_, i) => Math.max(0, ...scored[i]!.layers.map((l) => l.score)) >= LOCALISE_BAR,
    );
    if (!flagged.length) return null;
    const synthetic: RuleMatch = {
      ruleId: 'W-OUT-006',
      version: 1,
      hash: 'localised',
      mode: 'enforce',
      action: 'redact',
      severity: 'high',
      owasp: [],
      evidence: flagged.map((text) => ({
        kind: 'detector',
        field: 'text',
        span: { start: 0, end: text.length, text },
      })),
    };
    const localised = redactResult(current, [synthetic]);
    if (!localised || resultText(localised) === resultText(current)) return null;
    return (await clean(localised)) ? localised : null;
  }

  private record(
    ctx: MessageContext,
    decision: VerdictDecision,
    ev: Evaluation,
    started: number,
    det: DetectorResult | null,
    opts: { layer?: Verdict['layer']; taintedNow?: boolean; extra?: string[] } = {},
  ): Verdict {
    const layers = det?.layers ?? [];
    const top = layers[layers.length - 1];
    const enforcedEvidence = ev.enforced.flatMap((m) =>
      m.evidence.map((e) => ({
        kind: e.kind,
        field: e.field,
        detail: e.detail,
        text: e.span?.text.slice(0, 200),
      })),
    );
    const latency = performance.now() - started;
    const v: Verdict = {
      id: randomUUID(),
      ts: new Date().toISOString(),
      sessionId: ctx.sessionId,
      server: ctx.server,
      tool: ctx.tool,
      channel: ctx.channel,
      riskTier: ctx.riskTier,
      decision,
      ruleIds: ev.enforced.map((m) => m.ruleId),
      shadowRuleIds: ev.observed.map((m) => m.ruleId),
      layer: opts.layer ?? (top ? top.layer : 'L0'),
      score: top ? top.score : null,
      detector: ctx.detector ?? {},
      tainted: ctx.tainted,
      taintedNow: opts.taintedNow ?? false,
      latencyMs: Math.round(latency * 1000) / 1000,
      explanation: explain(decision, ev, opts.extra ?? []),
      owasp: [...new Set(ev.enforced.flatMap((m) => m.owasp))],
      evidence: enforcedEvidence.slice(0, 20),
      bundleId: this.policies.bundle.bundle.id,
    };
    this.metrics.overhead.observe({ channel: ctx.channel, layer: v.layer }, latency / 1000);
    this.metrics.verdicts.inc({ channel: ctx.channel, decision, risk_tier: ctx.riskTier });
    for (const m of ev.enforced) this.metrics.ruleHits.inc({ rule_id: m.ruleId, mode: m.mode });
    for (const m of ev.observed) this.metrics.ruleHits.inc({ rule_id: m.ruleId, mode: m.mode });
    this.bus.verdict(v);
    if (this.cfg.events.recordMessages)
      this.bus.emit('message', {
        verdictId: v.id,
        sessionId: ctx.sessionId,
        decision,
        ruleIds: v.ruleIds,
        layer: v.layer,
        latencyMs: v.latencyMs,
        ctx,
      });
    return v;
  }

  /* -------------------------------------------------------------- descriptions */

  async inspectDescription(tool: ToolInfo, knownTools: string[]): Promise<Inspection> {
    return tracer.startActiveSpan('warden.inspect.description', async (span) => {
      const started = performance.now();
      const d = tool.definition;
      const text = [d.title, d.description, d.inputSchema ? JSON.stringify(d.inputSchema) : '']
        .filter(Boolean)
        .join('\n');
      const ctx: MessageContext = {
        channel: 'description',
        sessionId: 'tools/list',
        server: tool.server,
        tool: tool.tool,
        riskTier: tool.riskTier,
        tainted: false,
        text,
        description: d.description ?? '',
        knownTools,
      };
      const { result } = await this.cascade(ctx);
      const ev = this.policies.policy.evaluate(ctx);
      const decision: VerdictDecision =
        ev.decision === 'allow' || ev.decision === 'redact' ? 'allow' : 'quarantine_tool';
      const verdict = this.record(ctx, decision, ev, started, result);
      span.setAttribute('warden.decision', decision);
      span.end();
      return { decision, verdict, evaluation: ev };
    });
  }

  /* -------------------------------------------------------------- arguments */

  async inspectArguments(
    sessionId: string,
    tool: ToolInfo,
    args: Record<string, unknown>,
  ): Promise<Inspection> {
    return tracer.startActiveSpan('warden.inspect.arguments', async (span) => {
      const started = performance.now();
      const session = await this.taint.update(sessionId, (s) => {
        s.calls++;
      });
      const ctx: MessageContext = {
        channel: 'arguments',
        sessionId,
        server: tool.server,
        tool: tool.tool,
        riskTier: tool.riskTier,
        tainted: session.tainted,
        text: JSON.stringify(args ?? {}),
        args: args ?? {},
        description: tool.definition.description ?? '',
        provenance: this.taint.provenance(session),
      };
      const { result, failsafe } = await this.cascade(ctx);
      const ev = this.policies.policy.evaluate(ctx);
      let decision: VerdictDecision =
        ev.decision === 'redact' || ev.decision === 'taint_session'
          ? 'allow'
          : (ev.decision as VerdictDecision);
      const extra: string[] = [];
      let layer: Verdict['layer'] | undefined;
      if (failsafe && decision === 'allow') {
        decision = 'block';
        layer = 'failsafe';
        extra.push('detection unavailable; high-risk call failed closed');
      }
      if (decision === 'block' || decision === 'quarantine_tool') {
        decision = 'block';
        await this.taint.update(sessionId, (s) => {
          s.blocked++;
        });
      }
      const verdict = this.record(ctx, decision, ev, started, result, { layer, extra });
      span.setAttribute('warden.decision', decision);
      span.end();
      return { decision, verdict, evaluation: ev };
    });
  }

  /** Record that a step-up was approved by a person (or the user via elicitation). */
  recordApprovedStepUp(inspection: Inspection, by: string): void {
    this.bus.verdict({
      ...inspection.verdict,
      id: randomUUID(),
      ts: new Date().toISOString(),
      decision: 'approved_step_up',
      explanation: `step-up approved by ${by}; ${inspection.verdict.explanation}`,
    });
  }

  /* -------------------------------------------------------------- outputs */

  async inspectOutput(
    sessionId: string,
    tool: ToolInfo,
    result: ToolResult,
  ): Promise<{ result: ToolResult; inspection: Inspection }> {
    return tracer.startActiveSpan('warden.inspect.output', async (span) => {
      const started = performance.now();
      const session = await this.taint.get(sessionId);
      const text = resultText(result);
      const ctx: MessageContext = {
        channel: 'output',
        sessionId,
        server: tool.server,
        tool: tool.tool,
        riskTier: tool.riskTier,
        tainted: session.tainted,
        text,
        description: tool.definition.description ?? '',
        provenance: this.taint.provenance(session),
      };
      const { result: det, failsafe } = await this.cascade(ctx);
      const ev = this.policies.policy.evaluate(ctx);
      let decision: VerdictDecision =
        ev.decision === 'taint_session' ? 'allow' : (ev.decision as VerdictDecision);
      if (decision === 'step_up' || decision === 'quarantine_tool') decision = 'block';
      const extra: string[] = [];
      let layer: Verdict['layer'] | undefined;
      // The call already ran, so withholding its output on a detector outage buys nothing.
      // Instead the session is tainted: later high-risk calls face the strict sink policy.
      const unchecked = failsafe || (det?.unavailable ?? false);
      if (unchecked) {
        layer = 'failsafe';
        extra.push('detection unavailable; output passed unchecked and session tainted');
      }

      // A block driven partly by locatable spans need not cost the legitimate content: redact the
      // spans, then re-run the whole policy and detector on what would be delivered. Only a
      // residual that passes everything is released; anything else stays withheld.
      let sanitised: ToolResult | null = null;
      if (decision === 'block' && !unchecked) {
        sanitised = await this.sanitise(ctx, result, ev);
        if (sanitised) {
          decision = 'redact';
          extra.push('blocked output sanitised and re-verified clean; released with injected spans removed');
        }
      }

      let out: ToolResult = result;
      if (decision === 'redact' && sanitised) {
        out = sanitised;
      } else if (decision === 'block') {
        const ids = ev.enforced.map((m) => m.ruleId).join(', ') || 'failsafe';
        out = {
          content: [
            {
              type: 'text',
              text: `Warden withheld this tool output because it looked like an attack on the agent (${ids}). Continue the user's task without it.`,
            },
          ],
          isError: true,
        };
      } else if (decision === 'redact') {
        const redacted = redactResult(
          result,
          ev.enforced.filter((m) => m.action === 'redact'),
        );
        if (redacted) out = redacted;
        else {
          // A match could not be located in the original text: withhold rather than pass it through.
          decision = 'block';
          extra.push('redaction could not locate the match; output withheld');
          out = {
            content: [
              {
                type: 'text',
                text: `Warden withheld this tool output because part of it looked like an attack on the agent and could not be safely removed. Continue the user's task without it.`,
              },
            ],
            isError: true,
          };
        }
      }

      // Taint: untrusted source, a configured taint source, or a rule that asked for it.
      let taintedNow = false;
      const shouldTaint = tool.taintsSession || ev.taint || decision !== 'allow' || unchecked;
      if (shouldTaint && !session.tainted) {
        await this.taint.taint(sessionId, {
          tool: tool.qualified,
          at: new Date().toISOString(),
          reason: ev.taint
            ? 'rule'
            : decision !== 'allow'
              ? decision
              : unchecked
                ? 'unchecked output'
                : 'untrusted source',
        });
        this.metrics.taintedSessions.inc();
        taintedNow = true;
      } else if (!shouldTaint && decision === 'allow') {
        // Values from a trusted source are provenance whenever they are read, before or after taint:
        // the attacker does not control them. Outputs that were redacted or flagged never count.
        await this.taint.addTrustedOutput(sessionId, text);
      }

      if (this.cfg.spotlight.enabled && decision !== 'block') {
        out = {
          ...out,
          content: (out.content ?? []).map((b) =>
            b.type === 'text' && typeof b.text === 'string'
              ? { ...b, text: spotlight(b.text, tool.qualified, session.tainted || taintedNow) }
              : b,
          ),
        };
      }

      const verdict = this.record(ctx, decision, ev, started, det, { layer, taintedNow, extra });
      span.setAttribute('warden.decision', decision);
      if (decision === 'block') span.setStatus({ code: SpanStatusCode.ERROR, message: 'blocked' });
      span.end();
      return { result: out, inspection: { decision, verdict, evaluation: ev } };
    });
  }
}
