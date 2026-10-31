# Changelog

All notable changes are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added

- `verify` workflow: Helm on a live `kind` cluster, `terraform fmt/init/validate`, DeBERTa L2 fine-tune, a
  write-once locked-test scorer (`warden eval locked`), and a LaTeX report build.
- Full LaTeX report (`report/main.tex`), with tables generated from `docs/results/*.json` by `report/make_tables.py`.
- Loop results (simulated victim): `docs/results/loop-gated` (RQ3) and `docs/results/rq2`.

### Results

- `terraform validate` passes. The locked test split was scored once: cascade + scratch L2 blocks 98.2% of iid and
  88.9% of OOD attacks at 1.9% benign block rate. The DeBERTa fine-tune did not learn (recall 0 on the dev hold-out).

### Fixed

- Dashboard image build (missing `public/` directory) and DeBERTa tokenizer dependencies in CI.

## [0.1.1] - 2026-10-28

### Fixed

- **Compose lab** now runs end to end (first real `docker compose up` found five bugs): `alembic` not on PATH,
  unwritable shared policy volume, missing shadow-stage approvals when signing the demo bundle, and
  `${VAR:-}` config placeholders failing schema validation (gateway now treats YAML null as unset).
- **Helm chart** loads the same init script as compose (it had drifted) and migrates with `python -m alembic`.
- **CI** passes from a clean checkout: build before typecheck, committed `python/uv.lock`, install the `agents`
  extra, tag integration tests so `-m integration` selects them (they were never selected), correct
  `trivy-action` pin, and a narrow gitleaks allowlist for deliberate fake fixtures.

### Changed

- **Gateway: sanitise-then-reverify** for blocked outputs, with JSON-aware redaction (ADR-0013). Utility under
  attack 86.5% → 96.7%; B3 ASR 4.5% → 3.0%; no attack newly succeeds.
- Base images are overridable (`WARDEN_NODE_IMAGE`, `WARDEN_PYTHON_IMAGE`); `uv` is installed from PyPI in the image.
- Demo script replays a synthetic injection attack and prints the shadow detections.

### Added

- Rule **W-TAINT-003** protected-write step-up (ADR-0014); baseline is now 20 rules.
- `training/train_l2_scratch.py`: no-download PyTorch → ONNX L2 with a self-check against the real loader.
- Sanitise end-to-end tests with a stub detector (release, split-payload, outage).

## [0.1.0] - 2026-10-28

### Added

- **Policy IR** (`@warden/policy-ir`): typed rule vocabulary, trusted compiler with G1 static checks,
  Ed25519-signed bundles with hash-bound approvals, `warden-policy` CLI, property-based tests.
- **Gateway** (`@warden/gateway`): MCP proxy inspecting tool descriptions, arguments and outputs;
  description pinning and rug-pull detection; set-only session taint; spotlighting; shadow/canary/enforce
  modes; admin API, Prometheus metrics, OpenTelemetry traces, and event sinks (ring, JSONL, Postgres, Kafka).
- **Lab** (`@warden/lab-servers`): synthetic Acme Support MCP servers and deliberately malicious servers.
- **Detection cascade** (Python): L0 rules, L1 embedding kNN (pgvector), L2 classifier (lite or ONNX), L3 LLM judge.
- **Learning loop**: red/blue loop, defence memory, 8-stage validation gate (G1-G8), control-plane API.
- **Evaluation harness**: baselines B0-B4, AgentDojo adapter, Wilson/McNemar/bootstrap statistics, locked test split.
- **Dashboard** (Next.js 16, Tailwind 4) with Playwright e2e tests.
- **Infra**: Docker images, docker-compose lab (obs/kafka/demo/backend profiles), Helm chart + kind script,
  Terraform cost tripwire, Grafana dashboard.
- **Acme Support backend** (Spring Boot 3, Java 21), **dbt** analytics models, **PyTorch to ONNX** L2 training script.
- **CI/CD**: GitHub Actions (lint, typecheck, tests, e2e, integration), gitleaks/Semgrep/Trivy, Dependabot,
  reusable "Warden Policy Check" Action.
