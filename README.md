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
Full report: [`docs/results/rq1-simulated.md`](docs/results/rq1-simulated.md).

| Baseline                       | Attack success rate (ASR)   | Benign utility   | False-positive rate | p95 overhead |
| ------------------------------ | --------------------------- | ---------------- | ------------------- | ------------ |
| B0 — no defence                | 31.9% [29.3, 34.7]          | 100% [77.2, 100] | n/a                 | n/a          |
| B1 — spotlighting only         | 17.4% [15.4, 19.7]          | 100% [77.2, 100] | 0.0% [0.0, 5.8]     | 0.13 ms      |
| B2 — classifier on outputs     | 16.6% [14.5, 18.8]          | 100% [77.2, 100] | 1.6% [0.3, 8.6]     | 4.0 ms       |
| **B3 — Warden baseline rules** | **4.5% [3.4, 5.8]**         | 100% [77.2, 100] | 1.6% [0.3, 8.6]     | 9.7 ms       |

Paired exact McNemar against B0: B3 removes 318 attacks that succeeded under B0 and introduces none (p ≈ 4e-96).

**H1 (ASR ≤ 5%, utility loss ≤ 2 points):** met on the point estimate (4.5%, 0.0 points) but **not on the
95% upper bound** (5.8%). We report it as not conclusively met.

### What did not go well

- **Utility under attack is lower with defences on** (B3 86.5% vs 100% for B0). The likely cause is that when Warden redacts or blocks the injected action the simulated agent sometimes fails the legitimate task too; we have not yet broken this down per rule, so treat the cause as unconfirmed.
- **Residual weak spots:** `tamper-note` (18.8% ASR under B3) and `overwrite-policy` (9.0%) are not well covered
  by the baseline rules — prime targets for the learning loop.
- **Two false positives in 62 benign runs** (`W-OUT-006`, `W-OUT-007`). The interval is wide ([0.3, 8.6]%).
- Benign utility is measured on only 13 tasks, hence the wide [77.2, 100] interval.
- **RQ2 (the gate prevents self-DoS):** the mechanism — G2 rejecting a rule that fires on benign traffic — is
  unit-tested and visible as `gate_failures`; the *magnitude* needs a real-LLM victim. See [`docs/DECISIONS.md`](docs/DECISIONS.md) ADR-0010.

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
| `policies/`, `data/`                           | Baseline ruleset (19 rules, OWASP-tagged); synthetic corpora and scenarios              |
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
- The Helm chart and Terraform module were authored and reviewed but not executed in the build sandbox.
- Warden inspects what reaches an MCP tool call; it cannot see reasoning that never produces one.

## Security & contributing

See [SECURITY.md](SECURITY.md) and [CONTRIBUTING.md](CONTRIBUTING.md). Licensed under Apache-2.0 ([LICENSE](LICENSE), [NOTICE.md](NOTICE.md)).
