# Contributing to Warden

Thanks for your interest. Warden is a monorepo with a TypeScript/Node data plane and a Python
research stack, plus a Next.js dashboard and a Java backend.

## Prerequisites

- Node ≥ 22.12 and **pnpm 10** (`corepack enable`)
- Python 3.12 and **uv**
- JDK 21 + Maven (only for `services/acme-backend`)
- Docker (only for the compose lab and integration tests)

## Setup

```bash
pnpm install
pnpm run build            # build the TS packages
cd python && uv sync --group dev
```

## Before you push

Run what CI runs:

```bash
# TypeScript / dashboard
pnpm run lint
pnpm run format:check
pnpm -r run typecheck
pnpm run test
pnpm --filter @warden/dashboard exec playwright test   # needs chromium

# Python
cd python
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run warden corpus verify-lock
uv run pytest -m "not integration" -q

# Java
cd services/acme-backend && mvn -B verify
```

`pnpm run format` / `uv run ruff format .` auto-fix formatting.

## Conventions

- **Honest results only.** Never fabricate numbers; report measured values with confidence
  intervals, and state limitations and negative results plainly.
- **Never commit secrets** (keys, tokens, model identifiers). Keys are generated at runtime.
- **The test corpus splits stay locked.** Don't train or tune on `test_iid`/`test_ood`; the lock is
  enforced by `warden corpus verify-lock`.
- **Enforcement needs human approval (G8).** Don't weaken this default. The machine-approval path
  is for CI/lab only and is explicit.
- **Red-team the lab only.** No component may target systems outside the bundled lab.
- Policy changes go through the IR and the trusted compiler; add rules with their OWASP tags.

## Commits & PRs

Small, focused commits with descriptive messages. Add or update tests for behaviour changes. Make
sure CI is green. See [docs/DECISIONS.md](docs/DECISIONS.md) for the architectural rationale behind
the parts you are touching.
