# Decision log

Short architecture decision records. Newest first. Each records the decision, why, and the
trade-off accepted.

## ADR-0015 — Flagged outputs never supply provenance, even after sanitising

Values in a tool output that tripped a rule or the detector do not count as "traceable" for the
tainted-session argument rules (W-TAINT-*), even when the output is released after sanitising. After
the sanitise change this is the largest remaining utility cost: 32 of the 38 remaining losses are a
legitimate follow-up email whose recipient came from a flagged customer record, stepped up with no human
to approve it in the eval. Counting surviving values would be unsafe: an attacker who controls two fields
can put a benign-looking attacker address in one and the injection in another; sanitising removes the
injection and leaves the address "traceable". Trade-off: ~2.8 points of utility under attack, recoverable
by a human approving the step-up. Revisit only with a real-LLM measurement of that bypass.

## ADR-0014 — Protected-write rule (W-TAINT-003)

A session that has read untrusted content needs step-up to write to a policy/config path or to a
customer master-data note when the content is not traceable. RQ1 showed these integrity goals
(`overwrite-policy`, `tamper-note`) as the weakest. Benign tasks in the scenario write only to
`/shared/outbox/`, so the measured utility cost is nil. Honest limits: the rule was added after seeing the
RQ1 result on the same attack set (development-set evidence, not confirmation), and it only engages once a
session is tainted — an unrecognised injection arriving through a trusted server's own field never taints it
(16 of the 20 remaining `tamper-note` successes).

## ADR-0013 — Sanitise-then-reverify instead of block-or-nothing

Blocking a flagged output discards the legitimate content next to the injection; the first RQ1 run lost 157
of 1,159 attack-case tasks that way even though the victim never complied. When a rule would block, the
gateway first tries to remove the offending text, in two stages: the spans the rules located, then, if the
detector still objects, paragraphs it scores at or above the W-OUT-006 bar on their own (at most 16
paragraphs). The sanitised text is released only if it passes the full rule set and detector cascade
*as delivered*; a detector outage, an unlocatable span or any residual objection leaves it withheld, so a
release is never weaker than the policy's own verdict on the delivered bytes. Redaction also treats JSON-escaped
paragraph breaks as breaks and preserves JSON structure, so one injected paragraph no longer removes a
whole record. Measured: utility under attack 86.5% → 96.7%, 0 attacks newly succeed, 17 newly stopped;
p95 overhead 9.7 → 15.7 ms because the blocked path makes extra detector calls. Trade-off: latency on the
rare blocked path and a more complex output path to reason about; mutation-tested.

## ADR-0012 — Ship the compose/Helm baseline in shadow mode

The lab stack loads the baseline ruleset in **shadow** mode (inspect and record, don't block).
This makes the demo show live verdicts with no human-approval step, while keeping the production
invariant that **enforcement needs the G8 human approval**. A dev signing key is generated into a
volume at init, never committed or imaged. Trade-off: the out-of-the-box demo does not block
attacks until an operator promotes rules; that is the correct default.

## ADR-0011 — £0 by design; Terraform is a tripwire, not a deployment

Warden runs entirely on free/open-source tooling. The Terraform module provisions **no compute** —
only a $1 AWS budget, an optional billing alarm, and optional ECR repos. Spending anything trips an
alarm. Trade-off: no turnkey cloud deploy; by design.

## ADR-0010 — Simulated victim agent for CI; real-LLM victim for headline magnitudes

The default victim is a deterministic **simulated agent** (a pipeline stand-in) so CI is fast and
reproducible. A real LLM victim (Ollama) is optional. RQ2's *mechanism* (the gate rejecting a
benign-overblocking rule) is shown directly by `gate_failures` and unit-tested; the *magnitude* of
induced self-DoS depends on the attacker model and needs the real-LLM victim. We report this
limitation rather than overclaiming.

## ADR-0009 — Locked test split, scored once

The corpus `test_iid` / `test_ood` splits are committed with a SHA-256 lock and are refused unless
`WARDEN_UNLOCK_TEST=1`. L2 training uses dev only. This prevents test-set leakage into tuning.
Trade-off: less data to tune on; the right call for honest numbers.

**Record (2026-10-31).** The split was scored once, by the `verify` workflow, after the classifiers were
trained on dev only. Result: `docs/results/locked-test.json`. The scorer refuses to overwrite its output and the
workflow skips the whole job when that file exists. The fine-tuned DeBERTa L2 failed to train (see the README); we
did not retrain it against this data. Any corrected model must be evaluated on newly collected test data.

## ADR-0008 — Approvals bound to the rule's canonical hash *including mode*

An approval references the canonical-JSON SHA-256 of the rule with its `mode` field. A shadow-mode
approval therefore cannot be replayed to authorise enforcement, and any bundle edit invalidates the
signature. Trade-off: re-approval needed when a rule changes mode; that is the point.

## ADR-0007 — Set-only (monotonic) session taint

Once a session reads untrusted content, it stays tainted; later high-risk actions are gated even
after "clean" steps. Trade-off: some false step-ups on genuinely safe later actions; acceptable
because the alternative (clearing taint) is exploitable.

## ADR-0006 — Four-layer detection cascade with an LLM judge only in the band

L0 rules → L1 kNN → L2 classifier → L3 LLM judge, where L3 runs **only** in the uncertainty band.
This keeps the common case cheap and deterministic and spends the LLM budget only where it moves a
decision. Trade-off: cascade complexity; justified by cost and latency.

## ADR-0005 — Fail-closed on high-risk channels

If a detector is unavailable/times out, high-risk channels fail closed, read-only fail open
(configurable). Trade-off: availability hit on high-risk actions during an outage; the safe default.

## ADR-0004 — Trusted compiler + signed bundles as the policy TCB

Rules are authored in a typed IR and compiled by a trusted compiler that performs static safety
checks (unsafe-regex rejection via `safe-regex2`); only signed bundles load. Trade-off: no arbitrary
code in rules; intentional.

## ADR-0003 — MCP TypeScript SDK v2 (the stable line)

Adopted the v2 MCP SDK (`@modelcontextprotocol/server|client|node`), spec 2026-07-28, after a spike
confirmed it is the stable line. Trade-off: v2's split-package layout; worth it for the current
protocol and elicitation support.

## ADR-0002 — Gateway in TypeScript/Node, detection & research in Python

The inline data-plane (latency-sensitive, MCP-native) is Node/Fastify; the detection cascade,
statistics, evaluation and learning loop are Python. A pnpm + uv monorepo. Trade-off: two
toolchains; each language used where it is strongest.

## ADR-0001 — A gateway, not a model-side guardrail

Warden defends at the MCP boundary rather than inside the model's prompt, so it works regardless of
model, sees all three channels, and can enforce deterministically. Trade-off: it cannot see purely
in-context reasoning that never reaches a tool; that is explicitly out of scope.
