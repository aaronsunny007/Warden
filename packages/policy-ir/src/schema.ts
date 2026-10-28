/**
 * Warden Policy IR.
 *
 * A rule can only express what this fixed vocabulary allows. Rules written by people,
 * templates or an LLM all go through the same schema and the same compiler, so a
 * generated rule cannot smuggle arbitrary logic into enforcement.
 */
import { z } from 'zod';

export const CHANNELS = ['description', 'arguments', 'output'] as const;
export type Channel = (typeof CHANNELS)[number];

/** Risk tiers, from least to most dangerous. */
export const RISK_TIERS = ['read_only', 'internal_write', 'external_send', 'financial_destructive'] as const;
export type RiskTier = (typeof RISK_TIERS)[number];

export const MODES = ['off', 'shadow', 'canary', 'enforce'] as const;
export type Mode = (typeof MODES)[number];

export const ACTIONS = ['block', 'redact', 'step_up', 'quarantine_tool', 'taint_session'] as const;
export type ActionType = (typeof ACTIONS)[number];

export const SECRET_TYPES = [
  'aws_access_key',
  'github_token',
  'slack_token',
  'stripe_key',
  'openai_key',
  'anthropic_key',
  'google_api_key',
  'private_key',
  'jwt',
  'connection_string',
  'card_number',
  'canary_token',
] as const;
export type SecretType = (typeof SECRET_TYPES)[number];

export const LIMITS = {
  maxDepth: 6,
  maxLeaves: 48,
  maxRegexLength: 256,
  maxValues: 64,
  maxValueLength: 512,
  maxDescription: 500,
  maxMessage: 200,
} as const;

/**
 * Field references a predicate reads from the message context.
 * - `text`: the channel's canonical text
 * - `tool`, `server`, `qualifiedTool`, `description`
 * - `args.<path>`: a value inside tool-call arguments; `*` matches one level, `**` any depth
 */
const FIELD_RE = /^(text|tool|server|qualifiedTool|description|args(\.(\*\*|\*|[A-Za-z0-9_-]{1,64})){1,6})$/;
export const FieldRef = z.string().regex(FIELD_RE, 'invalid field reference');
export type FieldRef = z.infer<typeof FieldRef>;

const Str = z.string().min(1).max(LIMITS.maxValueLength);
const HostPattern = z
  .string()
  .min(1)
  .max(253)
  .regex(/^(\*\.)?[A-Za-z0-9.-]+$/, 'host pattern must be a hostname, optionally prefixed by *.');

export const TextLeaf = z
  .object({
    kind: z.literal('text'),
    field: FieldRef.default('text'),
    op: z.enum(['contains', 'equals', 'startsWith', 'endsWith', 'regex', 'anyOf']),
    value: z.union([Str, z.array(Str).min(1).max(LIMITS.maxValues)]),
    caseInsensitive: z.boolean().default(true),
    normalize: z.boolean().default(true),
  })
  .strict();

export const DecodedLeaf = z
  .object({
    kind: z.literal('decoded'),
    field: FieldRef.default('text'),
    encodings: z
      .array(z.enum(['base64', 'hex', 'url', 'rot13']))
      .min(1)
      .max(4),
    anyOf: z.array(Str).min(1).max(LIMITS.maxValues),
  })
  .strict();

export const UrlLeaf = z
  .object({
    kind: z.literal('url'),
    field: FieldRef.default('text'),
    hostIn: z.array(HostPattern).max(LIMITS.maxValues).optional(),
    hostNotIn: z.array(HostPattern).max(LIMITS.maxValues).optional(),
    privateAddress: z.boolean().optional(),
    schemeNotIn: z
      .array(z.string().regex(/^[a-z][a-z0-9+.-]{0,15}$/))
      .max(16)
      .optional(),
    queryLengthGt: z.number().int().min(0).max(65536).optional(),
    markdownImage: z.boolean().optional(),
  })
  .strict();

export const SecretLeaf = z
  .object({
    kind: z.literal('secret'),
    field: FieldRef.default('text'),
    types: z.array(z.enum(SECRET_TYPES)).min(1).max(SECRET_TYPES.length).optional(),
  })
  .strict();

export const HiddenUnicodeLeaf = z
  .object({
    kind: z.literal('hiddenUnicode'),
    field: FieldRef.default('text'),
  })
  .strict();

export const DetectorLeaf = z
  .object({
    kind: z.literal('detector'),
    layer: z.enum(['L1', 'L2', 'L3', 'max']),
    gte: z.number().min(0).max(1),
  })
  .strict();

export const EmailLeaf = z
  .object({
    kind: z.literal('email'),
    field: FieldRef.default('text'),
    domainNotIn: z.array(HostPattern).min(1).max(LIMITS.maxValues),
  })
  .strict();

export const UntraceableLeaf = z
  .object({
    kind: z.literal('untraceable'),
    field: FieldRef,
  })
  .strict();

export const LengthLeaf = z
  .object({
    kind: z.literal('length'),
    field: FieldRef.default('text'),
    gt: z.number().int().min(0).optional(),
    lt: z.number().int().min(1).optional(),
  })
  .strict();

export const NumericLeaf = z
  .object({
    kind: z.literal('numeric'),
    field: FieldRef,
    gt: z.number().optional(),
    lt: z.number().optional(),
  })
  .strict();

export const ToolRefLeaf = z
  .object({
    kind: z.literal('toolRef'),
    field: FieldRef.default('description'),
  })
  .strict();

export const LeafSchemas = [
  TextLeaf,
  DecodedLeaf,
  UrlLeaf,
  SecretLeaf,
  HiddenUnicodeLeaf,
  DetectorLeaf,
  EmailLeaf,
  UntraceableLeaf,
  LengthLeaf,
  NumericLeaf,
  ToolRefLeaf,
] as const;

export const Leaf = z.discriminatedUnion('kind', [...LeafSchemas]);
export type Leaf = z.infer<typeof Leaf>;
export type LeafInput = z.input<typeof Leaf>;

export type Predicate = Leaf | { all: Predicate[] } | { any: Predicate[] } | { not: Predicate };
export type PredicateInput =
  LeafInput | { all: PredicateInput[] } | { any: PredicateInput[] } | { not: PredicateInput };

export const Predicate: z.ZodType<Predicate, PredicateInput> = z.lazy(() =>
  z.union([
    Leaf,
    z.object({ all: z.array(Predicate).min(1).max(LIMITS.maxLeaves) }).strict(),
    z.object({ any: z.array(Predicate).min(1).max(LIMITS.maxLeaves) }).strict(),
    z.object({ not: Predicate }).strict(),
  ]),
);

const ToolGlob = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9_.*-]+$/, 'tool/server globs may use letters, digits, _ . - and *');

export const Scope = z
  .object({
    channels: z.array(z.enum(CHANNELS)).min(1).max(3),
    servers: z.array(ToolGlob).max(LIMITS.maxValues).optional(),
    tools: z.array(ToolGlob).max(LIMITS.maxValues).optional(),
    riskTiers: z.array(z.enum(RISK_TIERS)).min(1).max(4).optional(),
    taint: z.enum(['any', 'tainted', 'clean']).default('any'),
  })
  .strict();
export type Scope = z.infer<typeof Scope>;

export const Action = z
  .object({
    type: z.enum(ACTIONS),
    message: z.string().max(LIMITS.maxMessage).optional(),
  })
  .strict();
export type Action = z.infer<typeof Action>;

export const OwaspId = z.string().regex(/^(ASI|MCP)(0[1-9]|10)$/);

export const Provenance = z
  .object({
    author: z.enum(['human', 'template', 'memory', 'llm']),
    campaign: z.string().max(128).optional(),
    parent: z.string().max(64).optional(),
    createdAt: z.string().max(40).optional(),
    note: z.string().max(LIMITS.maxDescription).optional(),
  })
  .strict();

export const RULE_ID_RE = /^[A-Z][A-Z0-9-]{2,63}$/;

export const Rule = z
  .object({
    id: z.string().regex(RULE_ID_RE, 'rule ids are upper-case, e.g. W-ARG-001'),
    version: z.number().int().min(1).max(1_000_000),
    description: z.string().min(1).max(LIMITS.maxDescription),
    mode: z.enum(MODES),
    canaryPercent: z.number().min(0).max(100).default(10),
    severity: z.enum(['low', 'medium', 'high', 'critical']),
    action: Action,
    scope: Scope,
    match: Predicate,
    owasp: z.array(OwaspId).max(10).default([]),
    provenance: Provenance,
  })
  .strict();
export type Rule = z.infer<typeof Rule>;
export type RuleInput = z.input<typeof Rule>;

export const Approval = z
  .object({
    ruleId: z.string().regex(RULE_ID_RE),
    version: z.number().int().min(1),
    ruleHash: z.string().regex(/^[a-f0-9]{64}$/),
    stage: z.enum(['shadow', 'canary', 'enforce']),
    gateReport: z.string().regex(/^[a-f0-9]{64}$/),
    approvedBy: z.string().min(1).max(128),
    human: z.boolean(),
    approvedAt: z.string().max(40),
  })
  .strict();
export type Approval = z.infer<typeof Approval>;

export const Signature = z
  .object({
    alg: z.literal('ed25519'),
    keyId: z.string().min(1).max(64),
    sig: z.string().min(1).max(256),
  })
  .strict();

export const BUNDLE_SCHEMA = 'warden.policy-bundle/v1';

export const Bundle = z
  .object({
    schema: z.literal(BUNDLE_SCHEMA),
    id: z.string().min(1).max(128),
    createdAt: z.string().max(40),
    rules: z.array(Rule).max(2000),
    approvals: z.array(Approval).max(4000).default([]),
    signature: Signature.optional(),
  })
  .strict();
export type Bundle = z.infer<typeof Bundle>;
export type BundleInput = z.input<typeof Bundle>;

/** The message an evaluated rule sees. Serialisable, so the gate can replay recorded traffic. */
export interface MessageContext {
  channel: Channel;
  sessionId: string;
  server: string;
  tool: string;
  riskTier: RiskTier;
  tainted: boolean;
  /** Canonical text of the channel: the description, the JSON arguments, or the output text. */
  text: string;
  description?: string;
  args?: Record<string, unknown>;
  detector?: Partial<Record<'L1' | 'L2' | 'L3', number>>;
  /** Values traceable to the user's own request or to trusted, pre-taint outputs. */
  provenance?: string[];
  /** Other tool names visible to the agent, for cross-tool reference checks. */
  knownTools?: string[];
}

export function jsonSchema(): unknown {
  return {
    $id: 'https://warden.dev/schema/policy-ir.schema.json',
    title: 'Warden Policy IR',
    rule: z.toJSONSchema(Rule, { io: 'input', unrepresentable: 'any' }),
    bundle: z.toJSONSchema(Bundle, { io: 'input', unrepresentable: 'any' }),
  };
}
