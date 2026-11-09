"""Plain-English explanation of a detector verdict, including hidden-content findings."""

from __future__ import annotations

import re

from warden.detector.cascade import Detection
from warden.detector.hidden import HiddenReport

FAMILY = {
    "override": "attempts to override earlier instructions",
    "authority": "fake claims of authority",
    "role_tags": "fake role or system tags",
    "hidden_markup": "instructions hidden in markup",
    "tool_poison": "poisoned tool descriptions",
    "delayed": "instructions that wait for a later trigger",
    "compliance": 'pressure to comply "for compliance"',
    "polite_ps": "polite requests slipped in as a postscript",
    "carrier": "instructions carried inside ordinary content",
    "encoded": "encoded instructions",
    "markdown_exfil": "data leaving through markdown images or links",
    "multilingual": "instructions in another language",
    "public_prompt_injection": "known public prompt injections",
    "agentdojo": "known agent-benchmark attacks",
}
WHERE = {"output": "tool output", "description": "tool description", "arguments": "tool-call arguments"}
VERB = {"malicious": "Blocked", "uncertain": "Held for review", "benign": "Allowed"}


def _snip(s: str, n: int = 70) -> str:
    t = " ".join(s.split())
    return f"“{t[:n]}…”" if len(t) > n else f"“{t}”"


def explain(d: Detection, verdict: str, channel: str, hidden: HiddenReport | None = None) -> str:
    parts = [f"{VERB.get(verdict, verdict.title())} ({WHERE.get(channel, channel)})."]
    if hidden is not None and hidden.findings:
        worst = [f for f in hidden.findings if f.severity != "low"] or hidden.findings
        for f in worst[:3]:
            where = f" on {f.location}" if f.location else ""
            said = f", and it says {_snip(f.decoded)}" if f.decoded else ""
            parts.append(f"Hidden content{where}: {f.detail}{said}.")
    if d.layers:
        last = d.layers[-1]
        stance = {
            "malicious": "rated it an injection",
            "benign": "found nothing",
            "uncertain": "was unsure",
        }.get(last.label, "could not decide")
        lead = "The language-model judge" if last.layer == "L3" else f"Detector layer {last.layer}"
        parts.append(f"{lead} {stance} (score {last.score:.2f}).")
        l1 = next((layer for layer in d.layers if layer.layer == "L1"), None)
        fam = re.search(r"nearest=([\w-]+)", l1.detail) if l1 else None
        if fam and fam.group(1) in FAMILY and verdict != "benign":
            parts.append(f"Closest known pattern: {FAMILY[fam.group(1)]}.")
    if verdict == "uncertain" and hidden is not None and hidden.has_payload:
        parts.append("Text a person cannot see is never treated as safe, so it was not allowed through.")
    return " ".join(parts)
