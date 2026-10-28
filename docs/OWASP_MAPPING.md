# OWASP coverage

Warden's baseline ruleset is mapped to the **OWASP Agentic Security Initiative (ASI)** Top 10 and
the **OWASP MCP** Top 10. Each rule carries its OWASP tags in the policy IR, so coverage is derived
from the rules themselves (see `policies/baseline.rules.json`) and surfaced live on the dashboard's
coverage panel and in the dbt `owasp_coverage` mart.

## Baseline rules → OWASP categories

| Rule | Channel | Action | OWASP |
| --- | --- | --- | --- |
| W-DESC-001 | description | quarantine_tool | MCP03, ASI04 — hidden Unicode (zero-width / bidi / tag chars) in a description |
| W-DESC-002 | description | quarantine_tool | MCP03, ASI01, ASI04 — description contains model-directed instructions |
| W-DESC-003 | description | quarantine_tool | MCP03, MCP09 — cross-server shadowing (references another server's tools) |
| W-DESC-004 | description | quarantine_tool | MCP03, MCP01 — description mentions sensitive files / credential stores |
| W-DESC-005 | description | quarantine_tool | MCP03 — cascade scores the description as an injection |
| W-ARG-001 | arguments | block | ASI02, MCP05 — SSRF: private / loopback / link-local / cloud-metadata target |
| W-ARG-002 | arguments | block | ASI02, MCP05 — non-web URL scheme (file, gopher, dict, ftp, …) |
| W-ARG-003 | arguments | block | MCP01, ASI02, MCP10 — secret / credential / canary egress |
| W-ARG-004 | arguments | block | ASI01, MCP10 — markdown-image data exfiltration to an external URL |
| W-ARG-005 | arguments | block | ASI01, MCP06, MCP10 — post-read long query-string egress to a new host |
| W-TAINT-001 | arguments | step_up | ASI01, ASI02, MCP06 — tainted session: untraceable recipient/destination |
| W-TAINT-002 | arguments | step_up | ASI02, ASI09 — tainted session: untraceable payment / refund amount |
| W-TAINT-003 | arguments | step_up | ASI01, ASI02, ASI06 — tainted session: write to a protected resource (policy/config path, customer master-data note) |
| W-OUT-001 | output | redact | ASI01, MCP10, ASI06 — indirect prompt injection in tool output |
| W-OUT-002 | output | redact | ASI01, MCP10 — role/boundary-tag spoofing in output |
| W-OUT-003 | output | redact | ASI01, MCP10 — hidden Unicode in output |
| W-OUT-004 | output | redact | MCP01, MCP10 — secrets/credentials in output |
| W-OUT-005 | output | block | ASI01, MCP10 — encoded (base64/hex/rot13) instruction in output |
| W-OUT-006 | output | block | ASI01, MCP10 — cascade confident the output is an injection |
| W-OUT-007 | output | taint_session | ASI01, ASI06 — cascade suspicious: taint so later actions are gated |

## Category coverage

**OWASP ASI (Agentic) Top 10**

| ID | Category | Covered by |
| --- | --- | --- |
| ASI01 | Agent goal / instruction hijack | W-DESC-002, W-ARG-004/005, W-TAINT-001/003, W-OUT-001/002/003/005/006/007 |
| ASI02 | Tool / action abuse | W-ARG-001/002/003, W-TAINT-001/002/003 |
| ASI04 | Deceptive tool metadata | W-DESC-001/002 |
| ASI06 | Memory / context poisoning | W-OUT-001, W-OUT-007, W-TAINT-003 |
| ASI09 | Unsafe financial / high-impact actions | W-TAINT-002 |
| ASI03, ASI05, ASI07, ASI08, ASI10 | — | **gaps** — see below |

**OWASP MCP Top 10**

| ID | Category | Covered by |
| --- | --- | --- |
| MCP01 | Sensitive data / credential exposure | W-DESC-004, W-ARG-003, W-OUT-004 |
| MCP03 | Tool poisoning | W-DESC-001…005 |
| MCP05 | SSRF via tool arguments | W-ARG-001/002 |
| MCP06 | Indirect prompt injection via content | W-ARG-005, W-TAINT-001, W-OUT-001 |
| MCP09 | Cross-server shadowing | W-DESC-003 |
| MCP10 | Exfiltration / covert channels | W-ARG-003/004/005, W-OUT-001…006 |
| MCP02, MCP04, MCP07, MCP08 | — | partial / out of band (below) |

## Honest gaps

Warden does not claim full coverage. Known gaps the baseline does **not** address with a rule:

- **MCP07 (insufficient authentication)** and **MCP02/MCP04 (auth/authorization of the servers
  themselves)** are deployment concerns, not message-inspection concerns — Warden assumes the
  operator authenticates its upstreams.
- **MCP08 (insufficient logging / non-repudiation)** is addressed operationally, not by a rule: the
  verdict event stream (ring → JSONL → Postgres → Kafka audit consumer) is the audit log.
- **ASI03/05/07/08/10** (e.g. resource exhaustion, supply-chain, cascading multi-agent failures)
  are out of scope for a single inline gateway and are not claimed.

Coverage is a starting ruleset, extended over time by the learning loop (each promoted rule passes
the validation gate and carries its own OWASP tags).
