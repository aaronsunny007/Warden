"""One call that does what the service and every adapter need: scan for hidden content, run the
cascade on everything a model would read, apply the "never benign if it hides instructions" rule,
and explain the result in words."""

from __future__ import annotations

from dataclasses import dataclass

from warden.detector import hidden
from warden.detector.cascade import Cascade, Detection
from warden.detector.explain import explain


@dataclass
class Checked:
    verdict: str  # benign | uncertain | malicious
    score: float
    detection: Detection
    report: hidden.HiddenReport
    explanation: str


def apply_hidden_rule(verdict: str, r: hidden.HiddenReport) -> str:
    """Hidden instructions are an anomaly in themselves: never wave them through as benign."""
    if verdict == "benign" and r.severity == "high" and r.has_payload:
        return "uncertain"
    return verdict


def check_report(
    cascade: Cascade, rep: hidden.HiddenReport, channel: str = "output", risk_tier: str = "read_only"
) -> Checked:
    d = cascade.detect(rep.detection_text()[:65536] or " ", channel, risk_tier)
    verdict = apply_hidden_rule(d.verdict, rep)
    return Checked(verdict, d.score, d, rep, explain(d, verdict, channel, rep))


def check_text(cascade: Cascade, text: str, channel: str = "output", risk_tier: str = "read_only") -> Checked:
    rep = hidden.scan_text(text)
    rep.visible_text = text  # the cascade reads the original text plus anything that was hidden in it
    return check_report(cascade, rep, channel, risk_tier)


def check_bytes(
    cascade: Cascade, data: bytes, kind: str = "auto", channel: str = "output", risk_tier: str = "read_only"
) -> Checked:
    return check_report(cascade, hidden.scan(data, kind), channel, risk_tier)
