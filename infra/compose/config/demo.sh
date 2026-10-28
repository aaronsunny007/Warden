#!/bin/sh
# Replay demo: drive a few MCP calls through the running Warden gateway so the dashboard and
# the audit log light up, then print a short verdict summary. Lab data only; best-effort.
set -eu

GW="${WARDEN_GATEWAY_URL:-http://gateway:8787}"
TOKEN="${WARDEN_ADMIN_TOKEN:-}"

echo "[demo] waiting for the gateway to be ready"
i=0
until python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('$GW/healthz').status==200 else 1)" 2>/dev/null; do
  i=$((i + 1)); [ "$i" -gt 60 ] && { echo "[demo] gateway never became ready"; exit 1; }
  sleep 2
done

echo "[demo] driving MCP traffic through Warden"
python - "$GW" <<'PY'
import asyncio, sys
from warden.eval.tools import ToolSession

GW = sys.argv[1]
# The malicious servers (facts, weather) carry poisoned descriptions and tainting outputs; the
# Acme servers are benign. Listing tools exercises the description scanner (pinning / rug-pull);
# the calls exercise the argument and output channels.
BENIGN = [
    ("tickets.get_ticket", {"id": "T-501"}),
    ("customers.lookup_customer", {"customer_id": "1040"}),
    ("email.send_email", {"to": "jane.doe@gmail.example", "subject": "Your invoice",
                          "body": "Hi Jane, we will reissue your invoice with the corrected VAT number."}),
]
UNTRUSTED = [("facts.random_fact", {}), ("weather.get_forecast", {"city": "London"})]

async def main() -> None:
    async with ToolSession("demo-session", "Confirm the VAT reissue for ticket T-501",
                           gateway_url=GW, servers=[]) as ts:
        tools = await ts.list_tools()
        print(f"[demo] gateway exposes {len(tools)} tool(s) after description scanning")
        for name, args in BENIGN + UNTRUSTED:
            tc = await ts.call(name, args)
            flag = "error/blocked" if tc.is_error else "ok"
            print(f"[demo]   {name:<28} -> {flag}")

asyncio.run(main())
PY

echo "[demo] recent verdicts:"
python - "$GW" "$TOKEN" <<'PY'
import json, sys, urllib.request
gw, token = sys.argv[1], sys.argv[2]
req = urllib.request.Request(f"{gw}/api/v1/verdicts?limit=50")
if token:
    req.add_header("authorization", f"Bearer {token}")
try:
    rows = json.load(urllib.request.urlopen(req))
except Exception as e:  # noqa: BLE001
    print(f"[demo] could not read verdicts: {e}"); sys.exit(0)
from collections import Counter
by_decision = Counter(r.get("decision") for r in rows)
print(f"[demo] {len(rows)} verdict(s): " + ", ".join(f"{k}={v}" for k, v in by_decision.items()))
print("[demo] open the dashboard at http://localhost:3000")
PY
