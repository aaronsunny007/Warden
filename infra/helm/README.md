# Warden Helm chart

Deploys the full Warden lab stack to Kubernetes: the gateway, the Acme Support lab MCP servers,
the detection cascade, the control plane and the dashboard, with Postgres (pgvector) and Redis.
**Lab/evaluation use only — all data is synthetic.**

## On a local kind cluster (one command)

```bash
infra/kind/up.sh          # create cluster, build + load images, helm install
kubectl -n warden port-forward svc/dashboard 3000:3000
# http://localhost:3000
```

## Manual install

```bash
# Build and make the images available to your cluster first (e.g. `kind load docker-image`).
helm upgrade --install warden infra/helm/warden \
  --namespace warden --create-namespace --wait
```

Common overrides:

```bash
--set adminToken=$(openssl rand -hex 16)   # protect the admin API
--set detector.ollamaUrl=http://ollama:11434 --set detector.judgeModel=qwen2.5:7b   # enable L3
--set postgres.persistence.enabled=true    # keep the database across restarts
--set ingress.enabled=true --set ingress.host=warden.example
```

## Notes

- **Service names are fixed** (`gateway`, `control`, `detector`, `lab`, `postgres`, `redis`,
  `dashboard`) so in-cluster DNS matches the URLs the dashboard image bakes at build time and the
  gateway config references. Install at most one release per namespace.
- The gateway runs an init container that generates a dev Ed25519 signing key into an `emptyDir`
  and signs the baseline ruleset in **shadow mode** — no key material is committed or baked into
  an image. Promoting a rule to enforce still goes through the control plane's G8 approval.
- A regular Job (named per release revision) runs the Alembic migration; the detector, control and
  gateway pods wait on an init container until the schema exists. It is deliberately not a Helm hook:
  `helm install --wait` waits for pod readiness before post-install hooks run, which would deadlock.
- The default resource requests/limits are sized for a laptop cluster. Raise them for real load.

> The chart was authored to Helm conventions; `helm lint`/`helm template` were not run in the
> build sandbox (no outbound access to fetch the Helm binary). Run `helm lint infra/helm/warden`
> locally before deploying.
