/**
 * Plain-English explanations for verdicts. A person reading the dashboard or an audit log should
 * learn what was found, where, which rule or detector layer said so, and what Warden did about it,
 * without knowing rule ids. The structured fields stay on the verdict; this is only the sentence.
 */
import type { Evaluation, RuleMatch } from '@warden/policy-ir';
import type { LayerScore } from './detector.js';
import type { VerdictDecision } from './events/types.js';

const VERB: Record<VerdictDecision, string> = {
  allow: 'Allowed',
  block: 'Blocked',
  redact: 'Cleaned',
  step_up: 'Held for approval',
  quarantine_tool: 'Quarantined the tool',
  approved_step_up: 'Allowed after approval',
};

const WHERE: Record<string, string> = {
  output: 'in the output of',
  description: 'in the description of',
  arguments: 'in a call to',
};

/** What the nearest known attack family means in words. */
const FAMILY: Record<string, string> = {
  override: 'attempts to override earlier instructions',
  authority: 'fake claims of authority',
  role_tags: 'fake role or system tags',
  hidden_markup: 'instructions hidden in markup',
  tool_poison: 'poisoned tool descriptions',
  delayed: 'instructions that wait for a later trigger',
  compliance: 'pressure to comply "for compliance"',
  polite_ps: 'polite requests slipped in as a postscript',
  carrier: 'instructions carried inside ordinary content',
  encoded: 'encoded instructions',
  markdown_exfil: 'data leaving through markdown images or links',
  multilingual: 'instructions in another language',
  public_prompt_injection: 'known public prompt injections',
  agentdojo: 'known agent-benchmark attacks',
};

const KIND: Record<string, string> = {
  hiddenUnicode: 'hidden characters',
  secret: 'a secret',
  text: 'matching text',
  decoded: 'an encoded instruction',
  url: 'a suspicious URL',
  email: 'an email address',
  numeric: 'a number',
  length: 'unusual length',
  untraceable: 'a value not traceable to the user',
  toolRef: 'a reference to another tool',
  detector: 'text the detector scored',
};

function snippet(text: string): string {
  const t = text.replace(/\s+/g, ' ').trim();
  return `“${t.length > 70 ? `${t.slice(0, 70)}…` : t}”`;
}

function ruleSentence(m: RuleMatch): string {
  const found = m.evidence
    .slice(0, 2)
    .map((e) => {
      if (e.kind === 'hiddenUnicode') return 'hidden characters';
      if (e.span?.text) return snippet(e.span.text);
      return e.detail ? `${KIND[e.kind] ?? e.kind} (${e.detail})` : (KIND[e.kind] ?? e.kind);
    })
    .join(' and ');
  const why = m.message ?? m.ruleId;
  return found ? `${why} — found ${found} [${m.ruleId}]` : `${why} [${m.ruleId}]`;
}

function detectorSentence(layers: LayerScore[]): string {
  if (!layers.length) return '';
  const last = layers[layers.length - 1]!;
  const l1 = layers.find((l) => l.layer === 'L1');
  const family = /nearest=([\w-]+)/.exec(l1?.detail ?? '')?.[1];
  const words = family && FAMILY[family] ? ` Closest known pattern: ${FAMILY[family]}.` : '';
  const lead = last.layer === 'L3' ? 'The language-model judge' : `Detector layer ${last.layer}`;
  const stance =
    last.label === 'malicious'
      ? 'rated it an injection'
      : last.label === 'benign'
        ? 'found nothing'
        : 'was unsure';
  return `${lead} ${stance} (score ${last.score.toFixed(2)}).${words}`;
}

export function explainVerdict(opts: {
  decision: VerdictDecision;
  evaluation: Evaluation;
  channel: string;
  tool: string;
  layers?: LayerScore[];
  extra?: string[];
}): string {
  const { decision, evaluation: ev } = opts;
  const where = `${WHERE[opts.channel] ?? 'in'} ${opts.tool}`;
  const reasons = ev.enforced.map(ruleSentence);
  const parts = [`${VERB[decision]} ${where}.`];
  if (reasons.length) parts.push(`${reasons.join('; ')}.`);
  const det = detectorSentence(opts.layers ?? []);
  if (det && (decision !== 'allow' || ev.enforced.length)) parts.push(det);
  if (opts.extra?.length) parts.push(`${opts.extra.join('; ')}.`);
  if (ev.observed.length) {
    parts.push(`Also noticed in shadow mode (not enforced): ${ev.observed.map((m) => m.ruleId).join(', ')}.`);
  }
  return parts.join(' ');
}
