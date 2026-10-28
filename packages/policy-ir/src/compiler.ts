/**
 * The trusted compiler: Policy IR -> pure matcher functions.
 *
 * Nothing here evaluates code from a rule. Every leaf maps to a fixed, reviewed
 * implementation, and regular expressions are checked for catastrophic backtracking
 * before they are compiled.
 */
import safeRegex from 'safe-regex2';
import { canonicalJson, sha256Hex } from './canonical.js';
import { extractEmails, extractUrls, hostMatches, isPrivateHost } from './net.js';
import {
  CHANNELS,
  LIMITS,
  Predicate as PredicateSchema,
  Rule,
  type Channel,
  type Leaf,
  type MessageContext,
  type Predicate,
  type RiskTier,
} from './schema.js';
import { findSecrets } from './secrets.js';
import { decodeFragments, findHiddenUnicode, normalize, type Span } from './text.js';

export interface Evidence {
  kind: Leaf['kind'];
  field: string;
  span?: Span;
  detail?: string;
}

export interface CompileIssue {
  path: string;
  message: string;
}

export interface CompiledRule {
  rule: Rule;
  /** sha256 of the canonical, defaults-applied rule. Approvals bind to this. */
  hash: string;
  needsDetector: boolean;
  needsProvenance: boolean;
  inScope(ctx: Pick<MessageContext, 'channel' | 'server' | 'tool' | 'riskTier' | 'tainted'>): boolean;
  /** Evidence when the rule's predicate matches (scope is not checked here), else null. */
  match(ctx: MessageContext): Evidence[] | null;
}

export type CompileResult =
  | { ok: true; compiled: CompiledRule; warnings: CompileIssue[] }
  | { ok: false; errors: CompileIssue[]; warnings: CompileIssue[] };

type Matcher = (ctx: MessageContext) => Evidence[] | null;

/* ------------------------------------------------------------------ fields */

function collectStrings(v: unknown, out: string[], depth = 0): void {
  if (depth > 12 || out.length > 512) return;
  if (v === null || v === undefined) return;
  if (typeof v === 'string') out.push(v);
  else if (typeof v === 'number' || typeof v === 'boolean') out.push(String(v));
  else if (Array.isArray(v)) for (const x of v) collectStrings(x, out, depth + 1);
  else if (typeof v === 'object')
    for (const x of Object.values(v as Record<string, unknown>)) collectStrings(x, out, depth + 1);
}

function descendants(v: unknown, out: unknown[], depth = 0): void {
  if (depth > 12 || out.length > 1024) return;
  out.push(v);
  if (Array.isArray(v)) for (const x of v) descendants(x, out, depth + 1);
  else if (v && typeof v === 'object')
    for (const x of Object.values(v as Record<string, unknown>)) descendants(x, out, depth + 1);
}

export function resolveField(ctx: MessageContext, field: string): string[] {
  switch (field) {
    case 'text':
      return [ctx.text];
    case 'tool':
      return [ctx.tool];
    case 'server':
      return [ctx.server];
    case 'qualifiedTool':
      return [`${ctx.server}.${ctx.tool}`];
    case 'description':
      return ctx.description !== undefined ? [ctx.description] : [];
    default:
      break;
  }
  const segs = field.split('.').slice(1);
  let cur: unknown[] = [ctx.args ?? {}];
  for (const seg of segs) {
    const next: unknown[] = [];
    for (const v of cur) {
      if (seg === '**') descendants(v, next);
      else if (seg === '*') {
        if (Array.isArray(v)) next.push(...v);
        else if (v && typeof v === 'object') next.push(...Object.values(v as Record<string, unknown>));
      } else if (Array.isArray(v)) {
        for (const item of v)
          if (item && typeof item === 'object' && seg in item)
            next.push((item as Record<string, unknown>)[seg]);
      } else if (v && typeof v === 'object' && Object.prototype.hasOwnProperty.call(v, seg)) {
        next.push((v as Record<string, unknown>)[seg]);
      }
    }
    cur = next;
  }
  const out: string[] = [];
  for (const v of cur) collectStrings(v, out);
  return [...new Set(out)];
}

function rawValues(ctx: MessageContext, field: string): unknown[] {
  if (!field.startsWith('args.')) return resolveField(ctx, field);
  const segs = field.split('.').slice(1);
  let cur: unknown[] = [ctx.args ?? {}];
  for (const seg of segs) {
    const next: unknown[] = [];
    for (const v of cur) {
      if (seg === '*' || seg === '**') {
        if (seg === '**') descendants(v, next);
        else if (Array.isArray(v)) next.push(...v);
        else if (v && typeof v === 'object') next.push(...Object.values(v as Record<string, unknown>));
      } else if (
        v &&
        typeof v === 'object' &&
        !Array.isArray(v) &&
        Object.prototype.hasOwnProperty.call(v, seg)
      ) {
        next.push((v as Record<string, unknown>)[seg]);
      }
    }
    cur = next;
  }
  return cur;
}

/* ------------------------------------------------------------------ regex safety */

export function checkRegex(pattern: string): string | null {
  if (pattern.length > LIMITS.maxRegexLength) return `regex longer than ${LIMITS.maxRegexLength} characters`;
  if (/\\[1-9]|\\k</.test(pattern)) return 'backreferences are not allowed';
  if (/\(\?<[=!]/.test(pattern)) return 'lookbehind is not allowed';
  try {
    new RegExp(pattern, 'u');
  } catch (e) {
    return `invalid regex: ${(e as Error).message}`;
  }
  if (!safeRegex(pattern)) return 'regex may backtrack catastrophically (star height > 1)';
  if (/^(\^)?(\.\*|\.\+)?(\$)?$/.test(pattern)) return 'regex matches everything';
  return null;
}

/* ------------------------------------------------------------------ leaves */

function compileLeaf(leaf: Leaf, path: string, issues: CompileIssue[]): Matcher {
  switch (leaf.kind) {
    case 'text': {
      const values = Array.isArray(leaf.value) ? leaf.value : [leaf.value];
      const prep = (s: string): string => {
        let t = leaf.normalize ? normalize(s) : s;
        if (leaf.caseInsensitive) t = t.toLowerCase();
        return t;
      };
      if (leaf.op === 'regex') {
        const regs: RegExp[] = [];
        values.forEach((v, i) => {
          const err = checkRegex(v);
          if (err) issues.push({ path: `${path}.value${values.length > 1 ? `[${i}]` : ''}`, message: err });
          else regs.push(new RegExp(v, leaf.caseInsensitive ? 'giu' : 'gu'));
        });
        return (ctx) => {
          const ev: Evidence[] = [];
          for (const raw of resolveField(ctx, leaf.field)) {
            const s = (leaf.normalize ? normalize(raw) : raw).slice(0, 65536);
            for (const re of regs) {
              re.lastIndex = 0;
              const m = re.exec(s);
              if (m)
                ev.push({
                  kind: 'text',
                  field: leaf.field,
                  span: { start: m.index, end: m.index + m[0].length, text: m[0] },
                });
            }
          }
          return ev.length ? ev : null;
        };
      }
      const needles = values.map(prep).filter((v) => v.length > 0);
      if (needles.length === 0)
        issues.push({ path: `${path}.value`, message: 'value is empty after normalisation' });
      return (ctx) => {
        const ev: Evidence[] = [];
        for (const raw of resolveField(ctx, leaf.field)) {
          const s = prep(raw);
          for (const n of needles) {
            let hit = -1;
            if (leaf.op === 'contains' || leaf.op === 'anyOf') hit = s.indexOf(n);
            else if (leaf.op === 'equals') hit = s === n ? 0 : -1;
            else if (leaf.op === 'startsWith') hit = s.startsWith(n) ? 0 : -1;
            else if (leaf.op === 'endsWith') hit = s.endsWith(n) ? s.length - n.length : -1;
            if (hit >= 0)
              ev.push({
                kind: 'text',
                field: leaf.field,
                span: { start: hit, end: hit + n.length, text: s.slice(hit, hit + n.length) },
              });
          }
        }
        return ev.length ? ev : null;
      };
    }
    case 'decoded': {
      const phrases = leaf.anyOf.map((p) => normalize(p).toLowerCase());
      return (ctx) => {
        const ev: Evidence[] = [];
        for (const raw of resolveField(ctx, leaf.field)) {
          for (const frag of decodeFragments(raw, leaf.encodings)) {
            const f = normalize(frag).toLowerCase();
            for (const p of phrases)
              if (f.includes(p)) ev.push({ kind: 'decoded', field: leaf.field, detail: p });
          }
        }
        return ev.length ? ev : null;
      };
    }
    case 'url': {
      const constraints = [
        'hostIn',
        'hostNotIn',
        'privateAddress',
        'schemeNotIn',
        'queryLengthGt',
        'markdownImage',
      ] as const;
      if (!constraints.some((c) => leaf[c] !== undefined))
        issues.push({ path, message: 'url predicate needs at least one constraint' });
      return (ctx) => {
        const ev: Evidence[] = [];
        for (const raw of resolveField(ctx, leaf.field)) {
          for (const u of extractUrls(raw)) {
            const host = u.url?.hostname ?? '';
            const scheme = u.url ? u.url.protocol.replace(/:$/, '') : '';
            if (leaf.markdownImage !== undefined && u.markdownImage !== leaf.markdownImage) continue;
            if (leaf.hostIn && !(u.url && leaf.hostIn.some((p) => hostMatches(host, p)))) continue;
            if (leaf.hostNotIn && (!u.url || leaf.hostNotIn.some((p) => hostMatches(host, p)))) continue;
            if (leaf.privateAddress !== undefined && (!u.url || isPrivateHost(host) !== leaf.privateAddress))
              continue;
            if (leaf.schemeNotIn && (!u.url || leaf.schemeNotIn.includes(scheme))) continue;
            if (
              leaf.queryLengthGt !== undefined &&
              (!u.url || u.url.search.length + u.url.hash.length <= leaf.queryLengthGt)
            )
              continue;
            ev.push({ kind: 'url', field: leaf.field, span: u.span, detail: host });
          }
        }
        return ev.length ? ev : null;
      };
    }
    case 'secret':
      return (ctx) => {
        const ev: Evidence[] = [];
        const seen = new Set<string>();
        for (const raw of resolveField(ctx, leaf.field)) {
          for (const s of [raw, normalize(raw)]) {
            for (const h of findSecrets(s, leaf.types)) {
              if (seen.has(h.text)) continue;
              seen.add(h.text);
              ev.push({
                kind: 'secret',
                field: leaf.field,
                span: { start: h.start, end: h.end, text: h.text },
                detail: h.type,
              });
            }
          }
        }
        return ev.length ? ev : null;
      };
    case 'hiddenUnicode':
      return (ctx) => {
        const ev: Evidence[] = [];
        for (const raw of resolveField(ctx, leaf.field))
          for (const span of findHiddenUnicode(raw))
            ev.push({ kind: 'hiddenUnicode', field: leaf.field, span });
        return ev.length ? ev : null;
      };
    case 'detector':
      return (ctx) => {
        const d = ctx.detector ?? {};
        const score =
          leaf.layer === 'max'
            ? Math.max(-1, ...Object.values(d).filter((x): x is number => typeof x === 'number'))
            : d[leaf.layer];
        return score !== undefined && score >= leaf.gte
          ? [{ kind: 'detector', field: leaf.layer, detail: score.toFixed(3) }]
          : null;
      };
    case 'email':
      return (ctx) => {
        const ev: Evidence[] = [];
        for (const raw of resolveField(ctx, leaf.field)) {
          for (const e of extractEmails(normalize(raw))) {
            if (!leaf.domainNotIn.some((p) => hostMatches(e.domain, p)))
              ev.push({ kind: 'email', field: leaf.field, span: e.span, detail: e.domain });
          }
        }
        return ev.length ? ev : null;
      };
    case 'untraceable':
      return (ctx) => {
        const known = (ctx.provenance ?? []).map((k) => normalize(k).toLowerCase());
        const ev: Evidence[] = [];
        for (const raw of resolveField(ctx, leaf.field)) {
          const v = normalize(raw).toLowerCase();
          if (!v) continue;
          if (!known.some((k) => k.includes(v)))
            ev.push({ kind: 'untraceable', field: leaf.field, detail: raw.slice(0, 120) });
        }
        return ev.length ? ev : null;
      };
    case 'length':
      if (leaf.gt === undefined && leaf.lt === undefined)
        issues.push({ path, message: 'length predicate needs gt or lt' });
      return (ctx) => {
        const ev: Evidence[] = [];
        for (const raw of resolveField(ctx, leaf.field)) {
          if (
            (leaf.gt === undefined || raw.length > leaf.gt) &&
            (leaf.lt === undefined || raw.length < leaf.lt)
          ) {
            ev.push({ kind: 'length', field: leaf.field, detail: String(raw.length) });
          }
        }
        return ev.length ? ev : null;
      };
    case 'numeric':
      if (leaf.gt === undefined && leaf.lt === undefined)
        issues.push({ path, message: 'numeric predicate needs gt or lt' });
      return (ctx) => {
        const ev: Evidence[] = [];
        for (const v of rawValues(ctx, leaf.field)) {
          const n =
            typeof v === 'number'
              ? v
              : typeof v === 'string' && v.trim() !== ''
                ? Number(v.replace(/[£$€,\s]/g, ''))
                : NaN;
          if (!Number.isFinite(n)) continue;
          if ((leaf.gt === undefined || n > leaf.gt) && (leaf.lt === undefined || n < leaf.lt))
            ev.push({ kind: 'numeric', field: leaf.field, detail: String(n) });
        }
        return ev.length ? ev : null;
      };
    case 'toolRef':
      return (ctx) => {
        const self = new Set([ctx.tool.toLowerCase(), `${ctx.server}.${ctx.tool}`.toLowerCase()]);
        const names = (ctx.knownTools ?? []).map((t) => t.toLowerCase()).filter((t) => !self.has(t));
        const ev: Evidence[] = [];
        for (const raw of resolveField(ctx, leaf.field)) {
          const s = normalize(raw).toLowerCase();
          for (const n of names) {
            const bare = n.includes('.') ? n.slice(n.indexOf('.') + 1) : n;
            for (const cand of new Set([n, bare])) {
              if (cand.length < 4 || self.has(cand)) continue;
              const re = new RegExp(
                `(^|[^a-z0-9_])${cand.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([^a-z0-9_]|$)`,
              );
              if (re.test(s)) ev.push({ kind: 'toolRef', field: leaf.field, detail: cand });
            }
          }
        }
        return ev.length ? ev : null;
      };
  }
}

/* ------------------------------------------------------------------ predicates */

interface Stats {
  leaves: number;
  maxDepth: number;
  detector: boolean;
  provenance: boolean;
}

function compilePredicate(
  p: Predicate,
  path: string,
  depth: number,
  stats: Stats,
  issues: CompileIssue[],
): Matcher {
  stats.maxDepth = Math.max(stats.maxDepth, depth);
  if ('all' in p) {
    const parts = p.all.map((q, i) => compilePredicate(q, `${path}.all[${i}]`, depth + 1, stats, issues));
    return (ctx) => {
      const ev: Evidence[] = [];
      for (const m of parts) {
        const r = m(ctx);
        if (!r) return null;
        ev.push(...r);
      }
      return ev;
    };
  }
  if ('any' in p) {
    const parts = p.any.map((q, i) => compilePredicate(q, `${path}.any[${i}]`, depth + 1, stats, issues));
    return (ctx) => {
      // Track "matched" separately: a matching `not` branch carries no evidence but still matches.
      const ev: Evidence[] = [];
      let matched = false;
      for (const m of parts) {
        const r = m(ctx);
        if (r) {
          matched = true;
          ev.push(...r);
        }
      }
      return matched ? ev : null;
    };
  }
  if ('not' in p) {
    const inner = compilePredicate(p.not, `${path}.not`, depth + 1, stats, issues);
    return (ctx) => (inner(ctx) ? null : []);
  }
  stats.leaves++;
  if (p.kind === 'detector') stats.detector = true;
  if (p.kind === 'untraceable') stats.provenance = true;
  return compileLeaf(p, path, issues);
}

/* ------------------------------------------------------------------ scope */

function globToRegex(glob: string): RegExp {
  return new RegExp(
    `^${glob
      .split('*')
      .map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&'))
      .join('.*')}$`,
    'i',
  );
}

/* ------------------------------------------------------------------ probes for G1 */

const NEUTRAL_TEXT: Record<Channel, string[]> = {
  description: [
    '',
    'Returns the current weather for a city.',
    'Look up a customer record by id and return name and plan.',
  ],
  arguments: ['{}', '{"customer_id":"1042"}', '{"query":"latest invoice for customer 1042"}'],
  output: ['', 'OK', 'Customer 1042: Jane Doe, plan Pro, renewed 2026-03-01.', 'No results found.'],
};
const NEUTRAL_ARGS: Array<Record<string, unknown>> = [
  {},
  { customer_id: '1042' },
  { query: 'latest invoice for customer 1042' },
];

function probeContexts(channel: Channel): MessageContext[] {
  return NEUTRAL_TEXT[channel].map((text, i) => ({
    channel,
    sessionId: 'probe',
    server: 'probe',
    tool: 'probe_tool',
    riskTier: 'read_only' as RiskTier,
    tainted: false,
    text,
    description: channel === 'description' ? text : 'Probe tool.',
    args: channel === 'arguments' ? (NEUTRAL_ARGS[i] ?? {}) : undefined,
    provenance: [],
    knownTools: [],
  }));
}

/* ------------------------------------------------------------------ compile */

export function ruleHash(rule: Rule): string {
  return sha256Hex(canonicalJson(rule));
}

export function compileRule(input: unknown): CompileResult {
  const parsed = Rule.safeParse(input);
  if (!parsed.success) {
    return {
      ok: false,
      errors: parsed.error.issues.map((i) => ({ path: i.path.join('.') || '(root)', message: i.message })),
      warnings: [],
    };
  }
  const rule = parsed.data;
  const errors: CompileIssue[] = [];
  const warnings: CompileIssue[] = [];
  const stats: Stats = { leaves: 0, maxDepth: 0, detector: false, provenance: false };
  const matcher = compilePredicate(rule.match, 'match', 1, stats, errors);

  if (stats.maxDepth > LIMITS.maxDepth)
    errors.push({ path: 'match', message: `predicate nesting deeper than ${LIMITS.maxDepth}` });
  if (stats.leaves > LIMITS.maxLeaves)
    errors.push({ path: 'match', message: `more than ${LIMITS.maxLeaves} leaf predicates` });
  if ('not' in rule.match)
    errors.push({
      path: 'match',
      message: 'a bare top-level "not" is too broad; combine it with a positive condition',
    });

  const ch = new Set(rule.scope.channels);
  const t = rule.action.type;
  if (t === 'quarantine_tool' && (ch.size !== 1 || !ch.has('description')))
    errors.push({ path: 'action.type', message: 'quarantine_tool applies to the description channel only' });
  if (t === 'redact' && ch.has('description'))
    errors.push({ path: 'action.type', message: 'redact does not apply to tool descriptions' });
  if (t === 'step_up' && (ch.size !== 1 || !ch.has('arguments')))
    errors.push({ path: 'action.type', message: 'step_up applies to the arguments channel only' });
  if (t === 'taint_session' && ch.has('description'))
    errors.push({ path: 'action.type', message: 'taint_session does not apply to descriptions' });
  if (stats.provenance && rule.scope.taint !== 'tainted')
    warnings.push({
      path: 'scope.taint',
      message: 'untraceable checks are usually scoped to tainted sessions',
    });

  const serverRes = rule.scope.servers?.map(globToRegex);
  const toolRes = rule.scope.tools?.map(globToRegex);
  const inScope: CompiledRule['inScope'] = (ctx) => {
    if (!ch.has(ctx.channel)) return false;
    if (rule.scope.riskTiers && !rule.scope.riskTiers.includes(ctx.riskTier)) return false;
    if (rule.scope.taint === 'tainted' && !ctx.tainted) return false;
    if (rule.scope.taint === 'clean' && ctx.tainted) return false;
    if (serverRes && !serverRes.some((r) => r.test(ctx.server))) return false;
    if (toolRes && !toolRes.some((r) => r.test(ctx.tool) || r.test(`${ctx.server}.${ctx.tool}`)))
      return false;
    return true;
  };

  if (errors.length) return { ok: false, errors, warnings };

  // G1 "narrow enough": the rule must not fire on empty or neutral input in any channel it covers.
  if (!stats.detector) {
    for (const channel of CHANNELS) {
      if (!ch.has(channel)) continue;
      const probes = probeContexts(channel);
      const fired = probes.filter((p) => matcher(p) !== null);
      if (fired.some((p) => p.text === '' || p.text === '{}'))
        errors.push({ path: 'match', message: `matches empty ${channel} input` });
      else if (fired.length === probes.length)
        errors.push({ path: 'match', message: `matches every neutral ${channel} probe` });
    }
  }
  if (errors.length) return { ok: false, errors, warnings };

  return {
    ok: true,
    warnings,
    compiled: {
      rule,
      hash: ruleHash(rule),
      needsDetector: stats.detector,
      needsProvenance: stats.provenance,
      inScope,
      match: matcher,
    },
  };
}

export function compileRules(inputs: unknown[]): {
  compiled: CompiledRule[];
  failures: Array<{ index: number; id?: string; errors: CompileIssue[] }>;
} {
  const compiled: CompiledRule[] = [];
  const failures: Array<{ index: number; id?: string; errors: CompileIssue[] }> = [];
  const ids = new Set<string>();
  inputs.forEach((input, index) => {
    const r = compileRule(input);
    const id = (input as { id?: string } | null)?.id;
    if (!r.ok) failures.push({ index, id, errors: r.errors });
    else if (ids.has(r.compiled.rule.id))
      failures.push({ index, id, errors: [{ path: 'id', message: 'duplicate rule id' }] });
    else {
      ids.add(r.compiled.rule.id);
      compiled.push(r.compiled);
    }
  });
  return { compiled, failures };
}

/**
 * Compile a bare predicate without the rule-level G1 checks (depth, probes).
 * For tests and tooling that study predicate semantics; enforcement always uses compileRule.
 */
export function compileMatcher(input: unknown): {
  match: (ctx: MessageContext) => Evidence[] | null;
  issues: CompileIssue[];
} {
  const p = PredicateSchema.parse(input);
  const issues: CompileIssue[] = [];
  const stats: Stats = { leaves: 0, maxDepth: 0, detector: false, provenance: false };
  return { match: compilePredicate(p, 'match', 1, stats, issues), issues };
}
