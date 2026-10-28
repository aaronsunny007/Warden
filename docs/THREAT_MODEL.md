# Warden — threat model

## What Warden protects

An AI agent and the organisation behind it, when the agent uses tools over MCP. The protected
assets are: the organisation's data (customer records, inboxes, files), its ability to take
correct external actions (email, payments), and the agent's integrity of purpose (doing the user's
task, not an attacker's).

## Trust boundaries

| Party | Trust |
| --- | --- |
| The user and their request | trusted |
| The agent's model | **not** trusted to resist manipulation — it is the thing being defended |
| Warden gateway + signed policy bundle | trusted (the TCB) |
| MCP servers marked `trusted` | trusted to be non-malicious, **not** to return injection-free content |
| MCP servers marked `untrusted` | not trusted at all — their outputs always taint the session |
| Tool outputs (email bodies, web pages, tickets) | **untrusted data**, on every channel |

## Adversaries and capabilities

1. **Malicious/compromised MCP server.** Can ship poisoned tool descriptions, shadow another
   server's tools, hide instructions in Unicode, and change its tools after approval (rug pull).
2. **Indirect prompt injection via content.** An attacker who can place text where the agent will
   read it (a support ticket, an email, a web page) but has no other access.
3. **A hijacked model.** However it was steered, it may attempt data exfiltration or harmful
   external actions with plausible-looking arguments.
4. **An adversary against the learning loop itself (RQ2).** Crafts attacks whose obvious "defence"
   would also fire on benign traffic, trying to trick the self-improvement loop into promoting a
   rule that breaks legitimate work (self-DoS).

### Explicitly out of scope

- Compromise of the host running Warden, the signing key, or the trusted compiler.
- A malicious operator who approves a harmful enforce rule at G8.
- The model provider's own safety; model weights; prompt-level jailbreaks that cause no tool action.
- Network-level attacks on TLS between components (assumed handled by the deployment).

## Defences mapped to adversaries

| Adversary | Primary defences |
| --- | --- |
| Malicious server | description pinning + rug-pull re-list; description scanners (hidden Unicode, model-directed instructions, cross-server references, credential mentions); namespace isolation; quarantine of first-seen dirty tools |
| Indirect injection via content | output inspection (instruction/role-tag/hidden-Unicode/encoded-payload detection), spotlighting, **session taint** |
| Hijacked model | argument checks (SSRF/private-host, non-web schemes, secret egress, data-in-URL), taint-gated step-up on high-risk actions, fail-closed on high-risk when a detector is unavailable |
| Loop adversary (RQ2) | the **G2 benign-replay** and **G3 utility** stages reject any proposed rule that would fire on legitimate traffic, before it can enforce |

## Key security properties

- **Fail-closed on high risk.** If a detection layer is unavailable or times out, high-risk
  channels fail closed; read-only channels fail open (configurable).
- **Signed, hash-bound approvals.** Enforcement requires an Ed25519-signed bundle; an approval is
  bound to the canonical hash of the rule *and its mode*, so a shadow approval cannot authorise
  enforcement, and bundle tampering invalidates the signature.
- **Human in the loop for enforcement (G8).** On by default; the machine-approval opt-out is
  explicit and audited.
- **Set-only taint.** Taint is monotonic within a session: once untrusted content is read, later
  high-risk actions are gated regardless of intervening "clean" steps.

## Lab-only, synthetic data, no live targeting

The red team attacks **only Warden's own lab**. All customer/employee/ticket/payment data is
synthetic. No component targets third-party systems, and the corpus contains only synthetic
attack text. This is a safety constraint of the project, not just a convention.
