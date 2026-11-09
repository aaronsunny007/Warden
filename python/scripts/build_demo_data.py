"""Precompute the attack-and-defend demo: every carrier x technique x goal combination, run through the real
detector (hidden-content scan, then the default cascade). Writes site/demo/data.json.

Run from python/:  uv run python scripts/build_demo_data.py [--check]

Deterministic. `--check` regenerates in memory and fails if the committed file differs, so the demo cannot
drift from the detector without the tests noticing. The page replays these recorded results; it does not run
the detector in the browser.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import random
import re
import sys
from pathlib import Path
from typing import Any

from warden.detector import hidden
from warden.detector.guard import check_report
from warden.detector.service import build_cascade
from warden.settings import get_settings

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "site" / "demo" / "data.json"


def _builder() -> Any:
    spec = importlib.util.spec_from_file_location(
        "build_toolout", ROOT / "data" / "toolout" / "build_toolout.py"
    )
    assert spec and spec.loader
    m = importlib.util.module_from_spec(spec)
    sys.modules["build_toolout"] = m
    spec.loader.exec_module(m)
    return m


def _action(goal: str, payload: str, technique: str) -> str:
    email = re.search(r"[\w.-]+@[\w.-]+\.\w+", payload)
    amount = re.search(r"\$\d+\.\d\d", payload)
    if technique == "markdown_exfil":
        return "Loads an image whose address carries the customer data and API key to an outside server."
    return {
        "exfiltrate": f"Emails customer data to {email.group(0) if email else 'an outside address'}.",
        "payment": f"Issues a refund of {amount.group(0) if amount else 'a large amount'} without approval.",
        "policy_change": "Edits the policy or customer record to remove an approval step.",
        "prompt_leak": "Prints its hidden instructions and tool list into the reply.",
        "destructive": "Deletes files or tickets and reports the task as done.",
        "pivot": "Calls another tool (payments, email or web) on the attacker's behalf.",
    }[goal]


def build() -> dict[str, Any]:
    b = _builder()
    cascade = build_cascade(get_settings())

    def run(text: str, fmt: str) -> dict[str, Any]:
        rep = hidden.scan_html(text) if fmt == "html" else hidden.scan_text(text)
        if fmt != "html":
            rep.visible_text = text
        c = check_report(cascade, rep)
        return {
            "verdict": c.verdict,
            "score": round(c.score, 3),
            "explanation": c.explanation,
            "hidden": [
                {"kind": f.kind, "detail": f.detail, "decoded": f.decoded[:160]}
                for f in c.report.findings
                if f.severity != "low"
            ][:4],
        }

    plain = sorted(b.TECHNIQUES)
    html_only = sorted(b.HTML_ONLY)
    attacks: list[dict[str, Any]] = []
    for carrier in b.CARRIERS:
        for technique in plain + (html_only if carrier == "web_page" else []):
            for goal in sorted(b.GOALS):
                seed = int.from_bytes(
                    hashlib.sha256(f"{carrier}|{technique}|{goal}".encode()).digest()[:8], "big"
                )
                r = random.Random(seed)
                payload = r.choice(b.GOALS[goal]).format(
                    email=r.choice(b.EMAILS), amount=f"${r.randint(80, 950)}.00", cust=r.randint(1000, 9999)
                )
                if technique in b.HTML_ONLY:
                    text, fmt = b.wrap(
                        carrier,
                        b.benign_paragraph(r),
                        "Ignore previous instructions and " + payload + ".",
                        r,
                        html_hidden=b.HTML_ONLY[technique],
                    )
                else:
                    text, fmt = b.wrap(carrier, b.benign_paragraph(r), b.TECHNIQUES[technique](payload, r), r)
                attacks.append(
                    {
                        "carrier": carrier,
                        "technique": technique,
                        "goal": goal,
                        "format": fmt,
                        "text": text,
                        "action": _action(goal, payload, technique),
                        **run(text, fmt),
                    }
                )

    benign: list[dict[str, Any]] = []
    quota = {
        "ordinary": 20,
        "advisory": 4,
        "human_instruction": 4,
        "imperatives": 4,
        "policy": 4,
        "refund_request": 4,
    }
    for row in (
        json.loads(x)
        for x in (ROOT / "data" / "toolout" / "toolout.jsonl").read_text(encoding="utf-8").splitlines()
    ):
        kind = row["hard_negative"] or "ordinary"
        if row["label"] == "benign" and quota.get(kind, 0) > 0:
            quota[kind] -= 1
            benign.append(
                {
                    "carrier": row["carrier"],
                    "kind": kind,
                    "format": row["format"],
                    "text": row["text"],
                    **run(row["text"], row["format"]),
                }
            )
    s = get_settings()
    return {
        "meta": {
            "what": "Recorded results of the real detector on every carrier x technique x goal combination.",
            "detector": f"hidden-content scan + cascade (L1 kNN, L2 {s.l2_mode}); embedder {s.embed_model or 'hashing (offline)'}; no LLM judge; the L0 rules layer is not included",
            "without_warden": "A simulated assistant assumed to obey any instruction it reads. A worst-case stand-in, not a real model.",
            "n_attacks": len(attacks),
            "n_benign": len(benign),
        },
        "carriers": b.CARRIERS,
        "techniques": plain + html_only,
        "html_only": html_only,
        "goals": sorted(b.GOALS),
        "attacks": attacks,
        "benign": benign,
    }


def main() -> int:
    data = json.dumps(build(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if "--check" in sys.argv:
        ok = OUT.exists() and OUT.read_text(encoding="utf-8") == data
        print("demo data up to date" if ok else "demo data is stale: run scripts/build_demo_data.py")
        return 0 if ok else 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(data, encoding="utf-8")
    print(f"wrote {OUT} ({len(data) // 1024} KiB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
