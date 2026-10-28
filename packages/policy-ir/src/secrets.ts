/** Secret and canary-token patterns. Kept narrow on purpose: each has a distinctive prefix or structure. */
import type { SecretType } from './schema.js';
import type { Span } from './text.js';

const PATTERNS: Record<Exclude<SecretType, 'card_number'>, RegExp> = {
  aws_access_key: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
  github_token: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g,
  slack_token: /\bxox[abposr]-[A-Za-z0-9-]{10,200}\b/g,
  stripe_key: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,99}\b/g,
  openai_key: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,200}\b/g,
  anthropic_key: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{32,200}\b/g,
  google_api_key: /\bAIza[0-9A-Za-z_-]{35}\b/g,
  private_key: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g,
  jwt: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  connection_string:
    /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@/]{1,64}:[^\s@/]{1,128}@[^\s/]+/g,
  canary_token: /\bWARDEN-CANARY-[A-Z0-9]{12}\b/g,
};

const CARD_RE = /\b(?:\d[ -]?){13,19}\b/g;

function luhn(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

export interface SecretHit extends Span {
  type: SecretType;
}

export function findSecrets(text: string, types?: readonly SecretType[]): SecretHit[] {
  const capped = text.slice(0, 262144);
  const want = new Set<SecretType>(types ?? (Object.keys(PATTERNS) as SecretType[]).concat('card_number'));
  const hits: SecretHit[] = [];
  for (const [type, re] of Object.entries(PATTERNS) as Array<[SecretType, RegExp]>) {
    if (!want.has(type)) continue;
    for (const m of capped.matchAll(re)) {
      const start = m.index ?? 0;
      hits.push({ type, start, end: start + m[0].length, text: m[0] });
    }
  }
  if (want.has('card_number')) {
    for (const m of capped.matchAll(CARD_RE)) {
      const digits = m[0].replace(/[ -]/g, '');
      if (digits.length >= 13 && digits.length <= 19 && luhn(digits) && !/^(\d)\1+$/.test(digits)) {
        const start = m.index ?? 0;
        hits.push({ type: 'card_number', start, end: start + m[0].length, text: m[0] });
      }
    }
  }
  return hits.sort((a, b) => a.start - b.start);
}
