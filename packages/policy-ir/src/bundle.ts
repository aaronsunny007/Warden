/**
 * Signed policy bundles.
 *
 * The control plane signs a bundle only after the validation gate passes. The gateway
 * loads a bundle only if the signature verifies and every active rule carries an
 * approval bound to its exact hash at a stage at least as high as its mode.
 * Enforcement additionally needs a human approval (gate stage G8).
 */
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from 'node:crypto';
import { canonicalJson } from './canonical.js';
import { compileRules, type CompiledRule, type CompileIssue } from './compiler.js';
import { PolicySet } from './engine.js';
import { BUNDLE_SCHEMA, Bundle, type Approval, type Mode } from './schema.js';

const STAGE_RANK: Record<Mode, number> = { off: 0, shadow: 1, canary: 2, enforce: 3 };

export interface KeyPairPem {
  keyId: string;
  privateKeyPem: string;
  publicKeyPem: string;
}

export function generateSigningKey(keyId: string): KeyPairPem {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    keyId,
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

function signingPayload(bundle: Bundle): Buffer {
  const { signature: _sig, ...rest } = bundle;
  return Buffer.from(canonicalJson(rest), 'utf8');
}

export function signBundle(input: unknown, keyId: string, privateKeyPem: string): Bundle {
  const bundle = Bundle.parse(input);
  const key = createPrivateKey(privateKeyPem);
  const sig = sign(null, signingPayload(bundle), key).toString('base64');
  return { ...bundle, signature: { alg: 'ed25519', keyId, sig } };
}

export interface VerifyOptions {
  /** keyId -> PEM public key. */
  trustedKeys: Record<string, string>;
  /** Allow an unsigned bundle (development and gate replay only). */
  allowUnsigned?: boolean;
  /** Skip approval checks (gate replay of candidates only). */
  skipApprovals?: boolean;
  /** Enforcement needs a human approval (gate stage G8). Default true; lab and CI may turn it off. */
  requireHumanForEnforce?: boolean;
}

export interface LoadedBundle {
  bundle: Bundle;
  policy: PolicySet;
  compiled: CompiledRule[];
}

export type LoadResult =
  { ok: true; loaded: LoadedBundle; warnings: CompileIssue[] } | { ok: false; errors: CompileIssue[] };

export function approvalCovers(approvals: Approval[], c: CompiledRule, requireHuman = true): string | null {
  const mode = c.rule.mode;
  if (mode === 'off') return null;
  const matching = approvals.filter((a) => a.ruleId === c.rule.id && a.version === c.rule.version);
  if (!matching.length) return `no approval for ${c.rule.id} v${c.rule.version}`;
  const bound = matching.filter((a) => a.ruleHash === c.hash);
  if (!bound.length)
    return `approval for ${c.rule.id} does not match the rule's hash (rule changed after approval)`;
  const best = bound.reduce((a, b) => (STAGE_RANK[b.stage] > STAGE_RANK[a.stage] ? b : a));
  if (STAGE_RANK[best.stage] < STAGE_RANK[mode])
    return `${c.rule.id} is approved for ${best.stage}, not ${mode}`;
  if (requireHuman && mode === 'enforce' && !bound.some((a) => a.stage === 'enforce' && a.human))
    return `${c.rule.id} needs a human approval to enforce`;
  return null;
}

export function loadBundle(input: unknown, opts: VerifyOptions): LoadResult {
  const parsed = Bundle.safeParse(input);
  if (!parsed.success) {
    return {
      ok: false,
      errors: parsed.error.issues.map((i) => ({ path: i.path.join('.') || '(root)', message: i.message })),
    };
  }
  const bundle = parsed.data;
  const errors: CompileIssue[] = [];
  if (bundle.signature) {
    const pem = opts.trustedKeys[bundle.signature.keyId];
    if (!pem) errors.push({ path: 'signature.keyId', message: `untrusted key id ${bundle.signature.keyId}` });
    else {
      let good: boolean;
      try {
        good = verify(
          null,
          signingPayload(bundle),
          createPublicKey(pem),
          Buffer.from(bundle.signature.sig, 'base64'),
        );
      } catch {
        good = false;
      }
      if (!good) errors.push({ path: 'signature', message: 'signature does not verify' });
    }
  } else if (!opts.allowUnsigned) {
    errors.push({ path: 'signature', message: 'bundle is not signed' });
  }
  const { compiled, failures } = compileRules(bundle.rules);
  for (const f of failures)
    for (const e of f.errors)
      errors.push({ path: `rules[${f.index}]${f.id ? `(${f.id})` : ''}.${e.path}`, message: e.message });
  if (!opts.skipApprovals) {
    for (const c of compiled) {
      const problem = approvalCovers(bundle.approvals, c, opts.requireHumanForEnforce ?? true);
      if (problem) errors.push({ path: `rules(${c.rule.id})`, message: problem });
    }
  }
  if (errors.length) return { ok: false, errors };
  return { ok: true, loaded: { bundle, compiled, policy: new PolicySet(compiled) }, warnings: [] };
}

export function emptyBundle(id = 'empty'): Bundle {
  return { schema: BUNDLE_SCHEMA, id, createdAt: new Date(0).toISOString(), rules: [], approvals: [] };
}

export type { KeyObject };
