# Warden lab — docker-compose

A one-command local stack: the Warden gateway in front of the Acme Support lab MCP servers,
the Python detection cascade, the control plane and the operator dashboard, with Postgres
(pgvector) and Redis behind them. **Everything is synthetic and for evaluation only.**

## Run

```bash
cd infra/compose
cp .env.example .env            # optional: set WARDEN_ADMIN_TOKEN
docker compose up --build
```

Then open:

| Service                | URL                                      |
| ---------------------- | ---------------------------------------- |
| Dashboard              | http://localhost:3000                    |
| Gateway admin API      | http://localhost:8787/api/v1/status      |
| Gateway Prometheus     | http://localhost:8787/metrics            |
| Detector               | http://localhost:8000/healthz            |

The gateway comes up with the baseline ruleset in **shadow mode** (it inspects every MCP
description, argument and output and records what it *would* block, without blocking). The
signed bundle and its dev signing key are generated into a volume by the `policy-init`
one-shot — no key material is baked into any image or committed to the repo. Promoting a rule
to **enforce** goes through the control plane's G8 approval, exactly as in production.

## Profiles

```bash
docker compose --profile obs up --build       # + Prometheus, Grafana, OTel collector
docker compose --profile kafka up --build      # + Apache Kafka (KRaft) and the audit consumer
docker compose --profile demo up --build demo  # drive sample MCP traffic, print a verdict summary
```

- **obs** — Grafana at http://localhost:3001 (anonymous viewer) with a provisioned
  *Warden — Gateway Overview* dashboard; Prometheus at http://localhost:9090. To send traces,
  set `WARDEN_OTLP_ENDPOINT=http://otel-collector:4318` in `.env`.
- **kafka** — the gateway always publishes verdicts to `warden.verdicts`; without this profile
  those publishes fail silently (the other sinks still record). With it, a real broker runs and
  the `audit-consumer` persists every verdict to Postgres (OWASP MCP08 non-repudiable log).
- **demo** — a best-effort replay that lists tools through the gateway (exercising the
  description scanner and rug-pull guard) and calls a few benign and untrusted tools, then
  prints the verdict tally. Watch it live on the dashboard.

## Teardown

```bash
docker compose --profile obs --profile kafka --profile demo down -v   # -v also drops the volumes
```

## Notes

- First build compiles the TypeScript workspace and resolves the Python environment; subsequent
  builds are cached.
- The L3 LLM judge is **off** unless you point `WARDEN_OLLAMA_URL` at an Ollama server and name
  a model (`WARDEN_JUDGE_MODEL`). The cascade runs L0–L2 without it.
- Data is reset by dropping the `pgdata`, `policy` and `verdicts` volumes (`down -v`).

## Behind a TLS-inspecting proxy or a private registry

The image builds take their base images from build args. Point them at your own mirror, or at a base
image that already trusts your proxy CA, without editing any Dockerfile:

```bash
WARDEN_NODE_IMAGE=registry.example.com/node:22-bookworm-slim \
WARDEN_PYTHON_IMAGE=registry.example.com/python:3.12-slim-bookworm \
docker compose build
```
