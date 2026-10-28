import { describe, expect, it } from 'vitest';
import {
  BUNDLE_SCHEMA,
  compileRule,
  generateSigningKey,
  loadBundle,
  signBundle,
  type Approval,
  type BundleInput,
} from '../src/index.js';
import { rule } from './helpers.js';

const keys = generateSigningKey('test-key');
const trusted = { 'test-key': keys.publicKeyPem };

function approvalFor(input: unknown, stage: Approval['stage'], human = true): Approval {
  const c = compileRule(input);
  if (!c.ok) throw new Error('bad rule');
  return {
    ruleId: c.compiled.rule.id,
    version: c.compiled.rule.version,
    ruleHash: c.compiled.hash,
    stage,
    gateReport: 'a'.repeat(64),
    approvedBy: human ? 'sunny' : 'gate',
    human,
    approvedAt: '2026-10-28T00:00:00Z',
  };
}

function bundle(rules: unknown[], approvals: Approval[]): BundleInput {
  return {
    schema: BUNDLE_SCHEMA,
    id: 'b1',
    createdAt: '2026-10-28T00:00:00Z',
    rules: rules as BundleInput['rules'],
    approvals,
  };
}

describe('signed bundles', () => {
  const r = rule({ match: { kind: 'secret' } });

  it('loads a signed bundle with a human enforce approval', () => {
    const signed = signBundle(bundle([r], [approvalFor(r, 'enforce')]), 'test-key', keys.privateKeyPem);
    const res = loadBundle(signed, { trustedKeys: trusted });
    expect(res.ok).toBe(true);
  });

  it('rejects unsigned bundles unless explicitly allowed', () => {
    expect(loadBundle(bundle([r], [approvalFor(r, 'enforce')]), { trustedKeys: trusted }).ok).toBe(false);
    expect(
      loadBundle(bundle([r], [approvalFor(r, 'enforce')]), { trustedKeys: trusted, allowUnsigned: true }).ok,
    ).toBe(true);
  });

  it('rejects tampering after signing', () => {
    const signed = signBundle(bundle([r], [approvalFor(r, 'enforce')]), 'test-key', keys.privateKeyPem);
    const tampered = JSON.parse(JSON.stringify(signed));
    tampered.rules[0].description = 'changed';
    expect(loadBundle(tampered, { trustedKeys: trusted }).ok).toBe(false);
  });

  it('rejects signatures from untrusted keys', () => {
    const other = generateSigningKey('other');
    const signed = signBundle(bundle([r], [approvalFor(r, 'enforce')]), 'other', other.privateKeyPem);
    expect(loadBundle(signed, { trustedKeys: trusted }).ok).toBe(false);
  });

  it('rejects a rule whose content changed after approval', () => {
    const approved = approvalFor(r, 'enforce');
    const changed = rule({ match: { kind: 'secret', types: ['jwt'] } });
    const signed = signBundle(bundle([changed], [approved]), 'test-key', keys.privateKeyPem);
    const res = loadBundle(signed, { trustedKeys: trusted });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.errors[0]!.message).toMatch(/hash/);
  });

  it('rejects enforce without a human approval, and a mode above the approved stage', () => {
    const machine = signBundle(
      bundle([r], [approvalFor(r, 'enforce', false)]),
      'test-key',
      keys.privateKeyPem,
    );
    expect(loadBundle(machine, { trustedKeys: trusted }).ok).toBe(false);
    const canaryOnly = signBundle(
      bundle([r], [approvalFor(r, 'canary', false)]),
      'test-key',
      keys.privateKeyPem,
    );
    expect(loadBundle(canaryOnly, { trustedKeys: trusted }).ok).toBe(false);
    const canaryRule = rule({ mode: 'canary', match: { kind: 'secret' } });
    const ok = signBundle(
      bundle([canaryRule], [approvalFor(canaryRule, 'canary', false)]),
      'test-key',
      keys.privateKeyPem,
    );
    expect(loadBundle(ok, { trustedKeys: trusted }).ok).toBe(true);
  });

  it('rules in mode off need no approval', () => {
    const off = rule({ mode: 'off', match: { kind: 'secret' } });
    const signed = signBundle(bundle([off], []), 'test-key', keys.privateKeyPem);
    expect(loadBundle(signed, { trustedKeys: trusted }).ok).toBe(true);
  });
});
