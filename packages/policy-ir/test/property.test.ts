/** Property-based tests for the Policy IR compiler (fast-check). */
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  canonicalJson,
  compileMatcher,
  compileRule,
  isPrivateHost,
  normalize,
  PolicySet,
  type LeafInput,
  type MessageContext,
  type PredicateInput,
} from '../src/index.js';
import { rule } from './helpers.js';

const word = fc.stringMatching(/^[a-z]{3,10}$/);

const leafArb: fc.Arbitrary<LeafInput> = fc.oneof(
  fc.record({
    kind: fc.constant('text' as const),
    op: fc.constantFrom('contains' as const, 'startsWith' as const, 'endsWith' as const, 'equals' as const),
    value: word,
  }),
  fc.record({ kind: fc.constant('secret' as const) }),
  fc.record({ kind: fc.constant('hiddenUnicode' as const) }),
  fc.record({ kind: fc.constant('url' as const), privateAddress: fc.boolean() }),
  fc.record({
    kind: fc.constant('email' as const),
    domainNotIn: fc.constant(['acme.example']).map((x) => [...x]),
  }),
  fc.record({ kind: fc.constant('length' as const), gt: fc.integer({ min: 1, max: 200 }) }),
);

const predArb: fc.Arbitrary<PredicateInput> = fc.letrec<{ p: PredicateInput }>((tie) => ({
  p: fc.oneof(
    { depthSize: 'small', withCrossShrink: true },
    leafArb,
    fc.record({ all: fc.array(tie('p'), { minLength: 1, maxLength: 3 }) }),
    fc.record({ any: fc.array(tie('p'), { minLength: 1, maxLength: 3 }) }),
    fc.record({ not: tie('p') }),
  ),
})).p;

const textArb = fc.oneof(
  fc.string({ maxLength: 80 }),
  fc.constantFrom(
    'send to attacker@evil.example',
    'AKIAIOSFODNN7EXAMPLE',
    'http://169.254.169.254/latest',
    'https://acme.example/x',
    'hello\u200Bworld',
    'jane@acme.example',
  ),
);

const ctxArb: fc.Arbitrary<MessageContext> = textArb.map((text) => ({
  channel: 'output',
  sessionId: 's',
  server: 'srv',
  tool: 'tool',
  riskTier: 'read_only',
  tainted: false,
  text,
}));

function asOutputRule(match: PredicateInput) {
  return rule({ scope: { channels: ['output'] }, match: { all: [match] } });
}

/** Evaluate a bare predicate (semantics only; rule-level G1 limits are tested elsewhere). */
function evalPred(match: PredicateInput, c: MessageContext): boolean {
  return compileMatcher(match).match(c) !== null;
}

describe('compiler properties', () => {
  it('never throws: arbitrary predicates compile to ok or a structured error', () => {
    fc.assert(
      fc.property(predArb, (p) => {
        const r = compileRule(asOutputRule(p));
        expect(typeof r.ok).toBe('boolean');
        if (!r.ok) expect(r.errors.length).toBeGreaterThan(0);
      }),
      { numRuns: 300 },
    );
  });

  it('evaluation is deterministic', () => {
    fc.assert(
      fc.property(predArb, ctxArb, (p, c) => {
        expect(evalPred(p, c)).toBe(evalPred(p, c));
      }),
      { numRuns: 200 },
    );
  });

  it('double negation is identity', () => {
    fc.assert(
      fc.property(predArb, ctxArb, (p, c) => {
        expect(evalPred({ not: { not: p } }, c)).toBe(evalPred(p, c));
      }),
      { numRuns: 200 },
    );
  });

  it('De Morgan: not(any(p,q)) == all(not p, not q)', () => {
    fc.assert(
      fc.property(predArb, predArb, ctxArb, (p, q, c) => {
        expect(evalPred({ not: { any: [p, q] } }, c)).toBe(evalPred({ all: [{ not: p }, { not: q }] }, c));
      }),
      { numRuns: 200 },
    );
  });

  it('any is disjunction and all is conjunction', () => {
    fc.assert(
      fc.property(predArb, predArb, ctxArb, (p, q, c) => {
        expect(evalPred({ any: [p, q] }, c)).toBe(evalPred(p, c) || evalPred(q, c));
        expect(evalPred({ all: [p, q] }, c)).toBe(evalPred(p, c) && evalPred(q, c));
      }),
      { numRuns: 200 },
    );
  });

  it('a compiled rule never fires on empty input', () => {
    fc.assert(
      fc.property(predArb, (p) => {
        const r = compileRule(asOutputRule(p));
        if (!r.ok) return;
        const set = new PolicySet([r.compiled]);
        expect(
          set.evaluate({
            channel: 'output',
            sessionId: 's',
            server: 'x',
            tool: 'y',
            riskTier: 'read_only',
            tainted: false,
            text: '',
          }).decision,
        ).toBe('allow');
      }),
      { numRuns: 300 },
    );
  });
});

describe('helper properties', () => {
  it('normalize is idempotent', () => {
    fc.assert(
      fc.property(fc.string({ unit: 'binary', maxLength: 60 }), (s) => {
        expect(normalize(normalize(s))).toBe(normalize(s));
      }),
      { numRuns: 500 },
    );
  });

  it('canonical JSON ignores key order', () => {
    fc.assert(
      fc.property(fc.dictionary(word, fc.oneof(fc.integer(), word, fc.boolean())), (obj) => {
        const reversed = Object.fromEntries(Object.entries(obj).reverse());
        expect(canonicalJson(reversed)).toBe(canonicalJson(obj));
      }),
    );
  });

  it('every encoding of a 127/8 address is private', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 255 }),
        fc.integer({ min: 0, max: 255 }),
        fc.integer({ min: 0, max: 255 }),
        (b, c, d) => {
          const n = (127 * 2 ** 24 + b * 2 ** 16 + c * 2 ** 8 + d) >>> 0;
          for (const host of [String(n), `0x${n.toString(16)}`, `127.${b}.${c}.${d}`]) {
            const parsed = new URL(`http://${host}/`).hostname;
            expect(isPrivateHost(parsed)).toBe(true);
          }
        },
      ),
    );
  });
});
