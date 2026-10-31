# Warden

**A validation-gated, self-improving security gateway between AI agents and their MCP tool servers.**

Warden sits between an agent and the Model Context Protocol (MCP) servers it uses. It inspects all
three channels an attacker can reach — tool **descriptions**, tool-call **arguments**, and tool
**outputs** — tracks session **taint**, and enforces a signed, hash-bound policy. A red-team / blue-team
loop proposes new defences from confirmed bypasses, and an **8-stage validation gate (G1–G8)** proves each
one harmless to benign work (measured as benign agent tasks still completing) before it may enforce. Enforcement
always needs a human approval (G8) by default.

Everything runs on free/open-source tooling at £0. All data is synthetic; the red team attacks only the bundled lab.

> **Status:** research-grade reference implementation. Headline numbers below come from a **simulated
> victim agent** and a **synthetic corpus** (see [Limitations](#limitations)); they test the pipeline and the
> relative effect of each defence, not the behaviour of any real LLM.

## Results (RQ1, simulated victim, seed 1)

1,159 attack cases and 13 benign tasks across 11 attack goals × 8 templates. Wilson 95% intervals.
Full report: [`docs/results/rq1-simulated.md`](docs/results/rq1-simulated.md); the first run, before the
changes below, is kept in [`rq1-simulated-before.md`](docs/results/rq1-simulated-before.md).

| Baseline                       | Attack success rate (ASR)   | Benign utility   | Utility under attack | False-positive rate  | p95 overhead |
| ------------------------------ | --------------------------- | ---------------- | -------------------- | -------------------- | ------------ |
| B0 — no defence                | 31.9% [29.3, 34.7]          | 100% [77.2, 100] | 100% [99.7, 100]     | n/a                  | n/a          |
| B1 — spotlighting only         | 17.4% [15.4, 19.7]          | 100% [77.2, 100] | 100% [99.7, 100]     | 0.0% [0.0, 5.8]      | 0.12 ms      |
| B2 — classifier on outputs     | 16.6% [14.5, 18.8]          | 100% [77.2, 100] | 80.0% [77.6, 82.2]   | 1.6% [0.3, 8.6]      | 7.6 ms       |
| **B3 — Warden baseline rules** | **3.0% [2.2, 4.2]**         | 100% [77.2, 100] | **96.7% [95.5, 97.6]** | 1.6% [0.3, 8.6] (1/62) | 15.7 ms    |

Paired exact McNemar against B0: B3 removes 335 attacks that succeeded under B0 and introduces none (p ≈ 3e-101).

**H1 (ASR ≤ 5%, utility loss ≤ 2 points): met**, including the 95% upper bound (4.2%).

### How B3 moved, and why you should discount it

The first run had B3 at 4.5% [3.4, 5.8] with utility under attack at 86.5%. Reading the per-case records
showed the defence was destroying legitimate work, not only attacks (the victim never complied with the
injection in any of the 157 lost cases), so three changes were made:

1. **Sanitise-then-reverify** (gateway). A would-be block is released as a redaction only if the injected
   span can be located, removed, and the *exact text to be delivered* re-passes the full rules and detector
   cascade. Otherwise it stays withheld. Also redaction now understands JSON-escaped paragraph breaks, so one
   injected paragraph no longer takes the whole record with it. (ADR-0013)
2. **`W-TAINT-003`** (new rule): a tainted session writing to a policy/config path or a customer master-data
   note needs step-up. (ADR-0014)
3. Everything else held constant. Case by case, **0 attacks newly succeed** against the first run and 17 are newly stopped.

Utility under attack: 86.5% → 92.4% (change 1, stage 1) → 96.7% (stage 2 + change 2). The cost is latency:
p95 overhead rose from 9.7 to 15.7 ms, because the rare blocked path now makes extra detector calls.

**These are development-set numbers.** `W-TAINT-003` was written after seeing which goals were weak on this
very attack set, and the corpus and the simulated victim were both written for this project. They show the
pipeline works and how the baselines compare; they are not an estimate of performance against a real LLM or
against unseen attacks. The confirmatory runs are the locked test split and a real-LLM victim.

### What did not go well

- **`tamper-note` is still 13.9% [9.2, 20.5].** 16 of its 20 successes arrive through the customer record
  itself, a trusted server's own field. When the injection there is not recognised, nothing taints the session,
  so no argument-level rule engages. This is a real limit of taint-gated defence, not a tuning gap.
- **32 of the 38 remaining utility losses are deliberate** (ADR-0015): when an output is flagged, values in it
  stop counting as trusted provenance, so a legitimate follow-up email to the address in that record is
  stepped up. Relaxing it would let a split payload (benign-looking attacker address in one field, injection in
  another) through. A human can approve the step-up; the eval has none.
- **One false-positive run in 62 benign runs** (`W-OUT-006` and `W-OUT-007` both fired in it). The interval is wide ([0.3, 8.6]%).
- Benign utility is measured on only 13 tasks, hence the wide [77.2, 100] interval.
- **RQ2 (the gate prevents self-DoS):** the mechanism — G2 rejecting a rule that fires on benign traffic — is
  unit-tested and visible as `gate_failures`; the *magnitude* needs a real-LLM victim. See [`docs/DECISIONS.md`](docs/DECISIONS.md) ADR-0010.

## Verification status

| Area | Status |
| --- | --- |
| TypeScript (policy 96 + gateway 42 tests), Python (30 unit + 4 integration against pgvector), Java (7), dashboard e2e | pass, in a clean checkout and on GitHub Actions |
| Docker images and `docker compose up` | built and run: every service healthy, demo traffic and a replayed attack recorded in the gateway and Postgres |
| Helm chart | `helm lint`/`helm template` pass for four option sets, and the chart installs on a live `kind` cluster in CI (`helm install --wait`, then gateway and dashboard smoke-tested through port-forward). The first real install found a deadlock (migration as a post-install hook) that is now fixed |
| Terraform | `fmt -check`, `init` and `validate` pass on a GitHub Actions runner (`verify` workflow) |
| L2 classifier | the from-scratch L2 is exported to ONNX and served through the real loader (drift 1.8e-7). The first DeBERTa run diverged to NaN under the lockfile's torch 2.15 / transformers 5.21; with torch 2.8 / transformers 4.56 (now pinned) it trains: dev hold-out F1 0.98, served ONNX matches torch to 5e-7 (`docs/results/l2-deberta-dev.json`; **dev only, not the locked split**) |
| Locked test split | **scored once**, in CI, on 2026-10-31 (`docs/results/locked-test.json`, ADR-0009). It is not to be re-run or tuned against |
| LaTeX report | written (`report/main.tex`); compiled by the `report` job in `verify`, which uploads the PDF |

### Locked test split (scored once)

Run once in CI after training on the dev split only; no parameter was changed afterwards. Wilson 95% intervals.
`test_iid`: 56 attacks, 53 benign. `test_ood`: 18 attacks (two held-out families).

| Detector | iid attacks blocked | iid benign blocked | OOD attacks blocked |
|---|---|---|---|
| Cascade, lite L2 | 78.6% [66.2, 87.3] | 1.9% [0.3, 9.9] | 38.9% [20.3, 61.4] |
| Cascade + scratch L2 | **98.2%** [90.5, 99.7] | 1.9% [0.3, 9.9] | **88.9%** [67.2, 96.9] |
| Scratch L2 alone | 94.6% [85.4, 98.2] | 1.9% [0.3, 9.9] | 88.9% [67.2, 96.9] |
| Cascade + DeBERTa L2 | 75.0% [62.3, 84.5] | 1.9% [0.3, 9.9] | 38.9% [20.3, 61.4] |
| DeBERTa L2 alone | 0.0% [0.0, 6.4] | 0.0% [0.0, 6.8] | 0.0% [0.0, 17.6] |

**The DeBERTa row above is a failed model, not a measurement of DeBERTa.** That first run trained on torch 2.15 /
transformers 5.21, where training diverged to NaN (four later diagnostic runs showed a non-finite loss or gradient norm within
the first five steps, and anomaly detection reported `LogSoftmaxBackward0` returning NaN). A NaN model predicts class 0 for every input,
which matches its dev result (accuracy 55.4%, recall 0), and its ONNX export flagged all 53 benign messages. I did not
isolate whether torch or transformers is responsible. With torch 2.8.0 / transformers 4.56.2 it trains normally
(dev hold-out F1 0.98, 56 examples), but **that model has not been scored on the locked split**: the split was spent on
the first run, and re-scoring would invalidate it. A trustworthy locked-split number for DeBERTa needs newly collected
test data. The corpus is small and synthetic, so these intervals are wide.

## Quick start

```bash
# One-command lab: gateway + lab MCP servers + detector + control plane + dashboard
cd infra/compose && docker compose up --build
#   dashboard  http://localhost:3000     gateway admin  http://localhost:8787/api/v1/status
docker compose --profile demo up --build demo     # drive sample traffic through the gateway
docker compose --profile obs up --build           # + Prometheus / Grafana / OTel
```

Without Docker:

```bash
pnpm install && pnpm run build
cd python && uv sync --group dev
uv run warden eval run --experiment rq1 --baselines B0,B1,B2,B3 --agent simulated
```

On Kubernetes: `infra/kind/up.sh` (kind + Helm). See [`infra/helm/README.md`](infra/helm/README.md).

## Architecture

```
 agent ─▶ Warden gateway ─▶ MCP servers (Acme Support lab + untrusted servers)
            │  description scan · argument checks · output inspection · session taint
            │  detection cascade: L0 rules → L1 kNN → L2 classifier → L3 LLM judge
            │  policy: signed Ed25519 bundle · off / shadow / canary / enforce
            ▼
         verdict events → dashboard · Postgres · Kafka · Prometheus/OTel
            ▲
   red ↔ blue loop → 8-stage validation gate (G1–G8, human approval) → control plane
```

See [`docs/DESIGN.md`](docs/DESIGN.md), [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md),
[`docs/OWASP_MAPPING.md`](docs/OWASP_MAPPING.md) and [`docs/DECISIONS.md`](docs/DECISIONS.md).

## Repository layout

| Path                                           | What                                                                                    |
| ---------------------------------------------- | --------------------------------------------------------------------------------------- |
| `packages/policy-ir`                           | Rule vocabulary, trusted compiler, signed bundles, `warden-policy` CLI (TypeScript)     |
| `packages/gateway`                             | The MCP security gateway (Node 22, Fastify 5, MCP SDK v2)                               |
| `packages/lab-servers`                         | Synthetic Acme Support MCP servers and malicious servers                                |
| `python/`                                      | Detection cascade, eval harness, learning loop, validation gate, control plane          |
| `apps/dashboard`                               | Operator dashboard (Next.js 16, React 19, Tailwind 4, Playwright)                       |
| `services/acme-backend`                        | Spring Boot 3 / Java 21 customer-support backend                                        |
| `dbt/`                                         | Analytics models (verdicts, OWASP coverage, ASR by round, gate funnel)                  |
| `training/`                                    | PyTorch fine-tune → ONNX export for the L2 classifier                                   |
| `infra/`                                       | Dockerfiles, docker-compose, Helm chart, kind, Terraform (£0 tripwire), Grafana/Prometheus |
| `policies/`, `data/`                           | Baseline ruleset (20 rules, OWASP-tagged); synthetic corpora and scenarios              |
| `action.yml`                                   | Reusable GitHub Action: lint a policy ruleset and verify a signed bundle                |

## Technology

TypeScript · Node 22 · Fastify · MCP TypeScript SDK v2 · zod · Ed25519 · Python 3.12 · FastAPI · SQLAlchemy ·
Alembic · PostgreSQL + pgvector · Redis · Apache Kafka (KRaft) · OpenTelemetry · Prometheus · Grafana · Next.js ·
React · Tailwind · Playwright · LangGraph · AgentDojo · ONNX Runtime · PyTorch · Ollama · Spring Boot · dbt ·
Docker · Helm · kind · Terraform · GitHub Actions · Trivy · Semgrep · gitleaks · uv · pnpm.

## Limitations

- The default victim is a deterministic **simulated** agent; magnitudes with real LLMs will differ.
- The attack corpus and detector training data are both written for this project; out-of-distribution
  robustness needs public datasets and the locked test split (scored once, via `WARDEN_UNLOCK_TEST=1`).
- OWASP coverage is partial and gaps are listed in [`docs/OWASP_MAPPING.md`](docs/OWASP_MAPPING.md).
- See **Verification status** for what has and has not been executed.
- Warden inspects what reaches an MCP tool call; it cannot see reasoning that never produces one.

## Security & contributing

See [SECURITY.md](SECURITY.md) and [CONTRIBUTING.md](CONTRIBUTING.md). Licensed under Apache-2.0 ([LICENSE](LICENSE), [NOTICE.md](NOTICE.md)).
