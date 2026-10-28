#!/bin/sh
# One-shot: produce a signed baseline policy bundle for the compose lab.
#
# The compose demo ships the baseline in SHADOW mode: Warden inspects all three MCP channels
# and records what it *would* block, without blocking, so the dashboard shows live verdicts
# with no human-approval step. Promoting a rule to enforce is the control plane's job (G8).
#
# A fresh Ed25519 key pair is generated into the shared /policy volume on first run and reused
# after; the private key never leaves the volume and is never baked into an image.
set -eu

POLICY_DIR=/policy
KEY_ID=warden-dev
RULES_SRC=/app/policies/baseline.rules.json
BUNDLE_OUT="$POLICY_DIR/baseline.bundle.json"

mkdir -p "$POLICY_DIR"

if [ -f "$BUNDLE_OUT" ] && [ -f "$POLICY_DIR/$KEY_ID.pub.pem" ]; then
  echo "[policy-init] bundle already present, leaving it in place"
  exit 0
fi

echo "[policy-init] rewriting baseline rules to shadow mode"
node -e '
const fs = require("fs");
const rules = JSON.parse(fs.readFileSync(process.argv[1], "utf8"))
  .map((r) => ({ ...r, mode: "shadow" }));
fs.writeFileSync(process.argv[2], JSON.stringify(rules, null, 2));
' "$RULES_SRC" "$POLICY_DIR/rules.shadow.json"

if [ ! -f "$POLICY_DIR/$KEY_ID.key.pem" ]; then
  echo "[policy-init] generating dev signing key"
  node packages/policy-ir/dist/cli.js keygen --key-id "$KEY_ID" --out-dir "$POLICY_DIR" >/dev/null
fi

echo "[policy-init] assembling and signing the bundle"
node packages/policy-ir/dist/cli.js bundle \
  --rules "$POLICY_DIR/rules.shadow.json" --id baseline-demo --out "$POLICY_DIR/unsigned.json"
node packages/policy-ir/dist/cli.js sign \
  --bundle "$POLICY_DIR/unsigned.json" --key "$POLICY_DIR/$KEY_ID.key.pem" \
  --key-id "$KEY_ID" --out "$BUNDLE_OUT"
node packages/policy-ir/dist/cli.js verify \
  --bundle "$BUNDLE_OUT" --pub "$POLICY_DIR/$KEY_ID.pub.pem"

echo "[policy-init] wrote $BUNDLE_OUT"
