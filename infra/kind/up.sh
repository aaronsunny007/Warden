#!/usr/bin/env bash
# Bring up the Warden lab on a local kind cluster, end to end:
#   create the cluster, build the images, load them into kind, then install the Helm chart.
#
# Prerequisites: docker, kind, kubectl, helm.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CLUSTER="${WARDEN_KIND_CLUSTER:-warden}"
NS="${WARDEN_NAMESPACE:-warden}"
TAG="${WARDEN_IMAGE_TAG:-dev}"

cd "$REPO_ROOT"

echo "==> creating kind cluster '$CLUSTER' (if absent)"
if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  kind create cluster --config infra/kind/kind-config.yaml
fi

echo "==> building images"
docker build -f infra/docker/node.Dockerfile      -t "warden/node:$TAG"      .
docker build -f infra/docker/python.Dockerfile    -t "warden/python:$TAG"    .
docker build -f apps/dashboard/Dockerfile         -t "warden/dashboard:$TAG" .

echo "==> loading images into kind"
for img in node python dashboard; do
  kind load docker-image "warden/$img:$TAG" --name "$CLUSTER"
done

echo "==> installing the Helm chart"
helm upgrade --install warden infra/helm/warden \
  --namespace "$NS" --create-namespace \
  --set images.node.tag="$TAG" \
  --set images.python.tag="$TAG" \
  --set images.dashboard.tag="$TAG" \
  --wait --timeout 10m

cat <<EOF

Warden is up. Open the dashboard:

  kubectl --namespace $NS port-forward svc/dashboard 3000:3000
  # http://localhost:3000

Tear down:

  helm --namespace $NS uninstall warden
  kind delete cluster --name $CLUSTER
EOF
