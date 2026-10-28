/**
 * OWASP coverage: which Warden controls address which risks in the OWASP Top 10 for
 * Agentic Applications (2026) and the OWASP MCP Top 10 (2025, beta).
 */
export const OWASP_ITEMS: Record<string, string> = {
  ASI01: 'Agent Goal Hijack',
  ASI02: 'Tool Misuse & Exploitation',
  ASI03: 'Identity & Privilege Abuse',
  ASI04: 'Agentic Supply Chain Vulnerabilities',
  ASI05: 'Unexpected Code Execution',
  ASI06: 'Memory & Context Poisoning',
  ASI07: 'Insecure Inter-Agent Communication',
  ASI08: 'Cascading Failures',
  ASI09: 'Human-Agent Trust Exploitation',
  ASI10: 'Rogue Agents',
  MCP01: 'Token Mismanagement & Secret Exposure',
  MCP02: 'Privilege Escalation via Scope Creep',
  MCP03: 'Tool Poisoning',
  MCP04: 'Software Supply Chain Attacks & Dependency Tampering',
  MCP05: 'Command Injection & Execution',
  MCP06: 'Intent Flow Subversion',
  MCP07: 'Insufficient Authentication & Authorization',
  MCP08: 'Lack of Audit and Telemetry',
  MCP09: 'Shadow MCP Servers',
  MCP10: 'Context Injection & Over-Sharing',
};

/** Built-in controls that are not policy rules. */
export const BUILTIN_CONTROLS: Array<{ id: string; name: string; owasp: string[]; detail: string }> = [
  {
    id: 'C-PIN',
    name: 'Description pinning and quarantine',
    owasp: ['MCP03', 'MCP04', 'ASI04'],
    detail: 'SHA-256 pin of name, description and schemas; any change quarantines the tool (rug pull).',
  },
  {
    id: 'C-NAMESPACE',
    name: 'Tool namespacing and collision checks',
    owasp: ['MCP03', 'MCP09'],
    detail: 'Every tool is exposed as server.tool; name collisions block auto-approval (shadowing).',
  },
  {
    id: 'C-TAINT',
    name: 'Session taint tracking',
    owasp: ['ASI01', 'ASI06', 'MCP06', 'MCP10'],
    detail: 'Untrusted content taints the session; high-risk sinks then need provenance or step-up.',
  },
  {
    id: 'C-SPOTLIGHT',
    name: 'Spotlighting',
    owasp: ['ASI01', 'MCP10'],
    detail: 'Randomised, provenance-labelled boundaries around every tool output.',
  },
  {
    id: 'C-TIERS',
    name: 'Risk tiers and fail-by-tier',
    owasp: ['ASI02', 'ASI03', 'MCP02', 'ASI08'],
    detail: 'Tools are tiered read-only to financial/destructive; outages fail closed for high-risk calls.',
  },
  {
    id: 'C-STEPUP',
    name: 'Human step-up',
    owasp: ['ASI09', 'ASI02'],
    detail: 'Untraceable high-risk calls wait for a person (elicitation or approval queue).',
  },
  {
    id: 'C-AUDIT',
    name: 'Explained, logged verdicts',
    owasp: ['MCP08'],
    detail: 'Every verdict carries rule ids, layer, score and taint state; streamed to Kafka/Postgres.',
  },
  {
    id: 'C-GATE',
    name: 'Validation-gated policy bundles',
    owasp: ['ASI08', 'ASI10'],
    detail: 'Only signed bundles with approvals bound to rule hashes load; enforcement needs a human.',
  },
];

export function coverage(
  rules: Array<{ id: string; mode: string; owasp: string[] }>,
): Array<{ id: string; name: string; controls: string[]; rules: string[]; enforcedRules: number }> {
  return Object.entries(OWASP_ITEMS).map(([id, name]) => {
    const controls = BUILTIN_CONTROLS.filter((c) => c.owasp.includes(id)).map((c) => c.id);
    const matching = rules.filter((r) => r.owasp.includes(id));
    return {
      id,
      name,
      controls,
      rules: matching.map((r) => r.id),
      enforcedRules: matching.filter((r) => r.mode === 'enforce').length,
    };
  });
}
