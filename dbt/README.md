# Warden analytics (dbt-core)

Turns Warden's operational tables (written by the gateway, control plane and learning loop) into a
small analytics layer: the headline curves and breakdowns used in the write-up and the dashboard.

- **staging** (views): tidy 1:1 projections of `verdicts`, `campaigns`, `candidates`.
- **marts** (tables):
  - `verdicts_by_decision` — volume, taint share and p95 latency by server/channel/decision.
  - `owasp_coverage` — citations per OWASP ASI/MCP category and how many were enforced/flagged.
  - `detection_layer_mix` — verdicts and mean score by cascade layer (L0→L3).
  - `asr_by_round` — attack success rate per learning-loop round (RQ3).
  - `gate_funnel` — proposed defences by validation-gate status/stage/author.

## Run

Point dbt at the Warden Postgres (the compose/Helm defaults match the env below) and build:

```bash
cd dbt
export DBT_PROFILES_DIR=$(pwd)
export DBT_HOST=127.0.0.1 DBT_PORT=5432 DBT_USER=warden DBT_PASSWORD=warden DBT_DBNAME=warden
pip install dbt-core dbt-postgres     # or: uv pip install dbt-core dbt-postgres
dbt debug        # check the connection
dbt build        # run models + tests
```

No credentials live in the repo — the profile reads `DBT_*` from the environment. `dbt parse`
validates the project graph without a database.
