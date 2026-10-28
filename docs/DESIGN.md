# Warden — design

## Problem

An AI agent that uses tools over the **Model Context Protocol (MCP)** trusts three things it should
not: the **descriptions** of the tools it is offered, the **arguments** a (possibly manipulated)
model decides to send, and the **outputs** those tools return. Each is an injection surface:

- A malicious or compromised MCP server can ship a **poisoned tool description** that instructs the
  model (tool poisoning, cross-server shadowing, hidden-Unicode instructions).
- A hijacked model can be steered into **exfiltrating data or taking harmful external actions**
  (sending email, issuing refunds, fetching internal URLs).
- **Tool outputs carry outside content** (email bodies, web pages, tickets) that contain indirect
  prompt injections aimed at the agent.

## Approach

Warden is a **gateway** that sits between the agent and its MCP servers. The agent connects to one
MCP endpoint (Warden); Warden proxies to the real servers and inspects all three channels on every
message. It is **policy-driven, signed, and self-improving**, and it is built so that its defences
are proven harmless to benign work before they are ever allowed to block.

```
            ┌─────────────────────────── Warden gateway ───────────────────────────┐
  agent ───▶│  description scan ─ argument checks ─ output inspection ─ taint track  │──▶ MCP servers
            │          │                 │                   │                        │   (email, tickets,
            │          └──────────┬──────┴─────────┬─────────┘                        │    payments, web, …
            │                     ▼                 ▼                                  │    + untrusted ones)
            │            detection cascade    policy engine (signed bundle)           │
            │              L0 → L1 → L2 → L3   block / redact / step-up / quarantine   │
            └───────────────────────────────────────────────────────────────────────┘
                     │ verdict events (ring, JSONL, Postgres, Kafka)
                     ▼
         dashboard   control plane ◀── learning loop (red ↔ blue) ── 8-stage validation gate
```

## Components

- **Policy IR** (`packages/policy-ir`) — a typed rule vocabulary, a **trusted compiler** that
  performs the G1 static checks (rejecting unsafe regexes via `safe-regex2`, malformed matchers),
  a deterministic matching engine, and **Ed25519-signed bundles**. Approvals are bound to the
  canonical-JSON SHA-256 hash of a rule *including its mode*, so a shadow-mode approval can never be
  replayed to authorise enforcement.
- **Gateway** (`packages/gateway`) — the MCP proxy. Pins tool descriptions and re-lists upstream
  tools to catch silent **rug pulls**; applies spotlighting; tracks **session taint** (set-only:
  once outside content is read, the session stays tainted); evaluates the policy; emits a verdict
  per inspected message. Modes per rule: `off | shadow | canary | enforce`.
- **Detection cascade** (`python/warden/detector`) — **L0** deterministic rules → **L1** embedding
  kNN over the dev corpus → **L2** a classifier (`lite-logreg` always available, or an ONNX
  fine-tune / PromptGuard 2) → **L3** a local LLM judge (Ollama) consulted only in the uncertainty
  band. Short-text abstention and a contrastive benign corpus hold the false-positive rate down.
- **Lab** (`packages/lab-servers`) — the synthetic **Acme Support** MCP servers (email, customers,
  files, web, tickets, payments) and deliberately **malicious** servers (facts, weather, audit),
  plus a state API the evaluator reads to judge *what actually happened*.
- **Learning loop** (`python/warden/loop`) — a red team mutates attacks against the live gateway in
  the lab; a confirmed bypass seeds a blue team that proposes a new rule; the **8-stage validation
  gate** decides whether it may promote. Defence memory remembers what each rule answers.
- **Control plane + dashboard** — the approval queue (G8), candidate/gate-report history, and a
  live operator view.

## The validation gate (G1–G8)

The core thesis: a self-improving defence is only safe if each new rule is **proven not to harm
benign work** before it enforces. A proposed rule must pass, in order:

1. **G1 static** — compiles under the trusted compiler; no unsafe regex, no malformed matcher.
2. **G2 benign replay** — replayed over the recorded benign tool-traffic corpus, it must not fire
   on legitimate messages (this is the stage that stops an adversary inducing self-DoS).
3. **G3 utility** — benign task completion must not drop more than the budget.
4. **G4 efficacy** — it must actually stop the confirmed bypass that motivated it.
5. **G5 generalisation** — it should catch held-out variants, not just the one exploit.
6. **G6 cost** — added latency stays within budget.
7. **G7 budget** — rule/LLM/token rate limits (as in AEGIS) are respected.
8. **G8 approval** — a **human** signs the enforce-mode bundle. Machine approval is possible only
   with an explicit, audited opt-out used by CI and the lab, never by default.

## Reproducible, honest evaluation

- **Baselines** B0 (direct, no Warden) → B1 (spotlight only) → B2 (classifier on outputs only) →
  B3 (full baseline ruleset), plus B4 (the loop's promoted rules) for the learning experiment.
- **Research questions**: RQ1 — detection accuracy and **benign utility** vs the baselines;
  RQ2 — the gate prevents an adversary from degrading benign utility via poisoned defence proposals;
  RQ3 — attack success rate falls across loop rounds.
- **Statistics** — Wilson intervals for proportions (clamped at 0 and n), McNemar for paired
  detector comparisons, bootstrap for differences; a **locked test split** scored once.
- Everything runs on free/open-source tooling; the only "cloud" artefact is a Terraform **£0 cost
  tripwire**.

See [THREAT_MODEL.md](THREAT_MODEL.md), [OWASP_MAPPING.md](OWASP_MAPPING.md) and
[DECISIONS.md](DECISIONS.md).
