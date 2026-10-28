# Changelog

All notable changes are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/).

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
