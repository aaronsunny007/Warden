import type { MessageContext, RuleInput } from '../src/index.js';

export function ctx(over: Partial<MessageContext> = {}): MessageContext {
  return {
    channel: 'arguments',
    sessionId: 's-1',
    server: 'email',
    tool: 'send_email',
    riskTier: 'external_send',
    tainted: false,
    text: '{}',
    args: {},
    provenance: [],
    knownTools: [],
    ...over,
  };
}

export function argsCtx(args: Record<string, unknown>, over: Partial<MessageContext> = {}): MessageContext {
  return ctx({ args, text: JSON.stringify(args), ...over });
}

export function rule(over: Partial<RuleInput> & Pick<RuleInput, 'match'>): RuleInput {
  return {
    id: 'T-RULE-001',
    version: 1,
    description: 'test rule',
    mode: 'enforce',
    severity: 'high',
    action: { type: 'block' },
    scope: { channels: ['arguments'] },
    provenance: { author: 'human' },
    ...over,
  };
}
