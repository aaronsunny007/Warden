import { describe, expect, it } from 'vitest';
import type { Evaluation, RuleMatch } from '@warden/policy-ir';
import { explainVerdict } from '../src/explain.js';

const match = (over: Partial<RuleMatch>): RuleMatch => ({
  ruleId: 'W-OUT-001',
  version: 1,
  hash: 'h',
  mode: 'enforce',
  action: 'redact',
  severity: 'high',
  message: 'injected instruction removed from tool output',
  owasp: [],
  evidence: [
    { kind: 'text', field: 'text', span: { start: 0, end: 30, text: 'ignore previous instructions' } },
  ],
  ...over,
});

const ev = (enforced: RuleMatch[], observed: RuleMatch[] = []): Evaluation =>
  ({ decision: 'redact', enforced, observed }) as unknown as Evaluation;

describe('explainVerdict', () => {
  it('says what was found, where, and what was done', () => {
    const s = explainVerdict({
      decision: 'redact',
      evaluation: ev([match({})]),
      channel: 'output',
      tool: 'support.get_ticket',
    });
    expect(s).toMatch(/^Cleaned in the output of support\.get_ticket\./);
    expect(s).toContain('injected instruction removed from tool output');
    expect(s).toContain('“ignore previous instructions”');
    expect(s).toContain('[W-OUT-001]');
  });

  it('describes hidden characters without dumping them', () => {
    const s = explainVerdict({
      decision: 'redact',
      evaluation: ev([
        match({
          ruleId: 'W-OUT-003',
          evidence: [{ kind: 'hiddenUnicode', field: 'text', span: { start: 0, end: 1, text: '​' } }],
        }),
      ]),
      channel: 'output',
      tool: 'x.y',
    });
    expect(s).toContain('found hidden characters');
    expect(s).not.toContain('​');
  });

  it('puts the detector verdict and nearest known pattern in words', () => {
    const s = explainVerdict({
      decision: 'block',
      evaluation: ev([
        match({ ruleId: 'W-OUT-006', action: 'block', evidence: [{ kind: 'detector', field: 'text' }] }),
      ]),
      channel: 'output',
      tool: 'x.y',
      layers: [
        {
          layer: 'L1',
          score: 0.91,
          latencyMs: 1,
          label: 'malicious',
          detail: 'top_sim=0.8 nearest=authority',
        },
      ],
    });
    expect(s).toContain('Detector layer L1 rated it an injection (score 0.91)');
    expect(s).toContain('fake claims of authority');
  });

  it('mentions shadow rules as not enforced and appends extras', () => {
    const s = explainVerdict({
      decision: 'allow',
      evaluation: ev([], [match({ ruleId: 'W-OUT-009' })]),
      channel: 'arguments',
      tool: 'a.b',
      extra: ['sanitised and re-verified'],
    });
    expect(s).toContain('Allowed in a call to a.b.');
    expect(s).toContain('sanitised and re-verified.');
    expect(s).toContain('not enforced): W-OUT-009');
  });
});
