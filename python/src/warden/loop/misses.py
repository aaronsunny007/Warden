"""Learn from mistakes: every wrongly passed attack is logged, and the blue team proposes a fix that has to
survive the validation gate.

What runs here and what does not (the report says so too): the replay stages G1 (lint), G2 (benign replay),
G4 (does it block the miss) and G5 (does it survive mutations) run offline through the trusted policy CLI. The
live stages G3, G6 and G7 need the lab stack, and G8 is a human. A rule that clears the offline stages is written
out in *shadow* mode as a proposal for review; nothing here ever enforces anything.

Honesty rule: a miss taken from a scored test set spends that set. Fixing a rule from a miss and then re-scoring
the same set would measure memorisation, so use fresh data to check a learned rule.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from warden.corpus import load
from warden.loop.blue import BlueTeam
from warden.loop.campaign import Campaign
from warden.loop.gate import GateThresholds, ValidationGate
from warden.loop.memory import DefenceMemory, campaign_signature

CHANNELS = {"description", "arguments", "output"}


@dataclass
class Miss:
    id: str
    text: str
    channel: str = "output"
    source: str = "report"  # report | eval:<set> | canary
    goal: str = "unspecified"
    note: str = ""
    verdict_at_time: str = "benign"
    ts: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def signature(self) -> str:
        return campaign_signature(self.goal, f"miss:{self.source}", self.text)


class MissLog:
    """Append-only JSONL, deduplicated by attack signature."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _lines(self) -> list[str]:
        if not self.path.exists():
            return []
        return [x for x in self.path.read_text(encoding="utf-8").splitlines() if x.strip()]

    def all(self) -> list[Miss]:
        return [Miss(**json.loads(x)) for x in self._lines()]

    def count(self) -> int:
        return len(self._lines())

    def add(
        self,
        text: str,
        *,
        channel: str = "output",
        source: str = "report",
        goal: str = "unspecified",
        note: str = "",
        verdict: str = "benign",
    ) -> Miss | None:
        if channel not in CHANNELS:
            raise ValueError(f"channel must be one of {sorted(CHANNELS)}")
        if not text.strip():
            raise ValueError("text is empty")
        existing = self.all()
        m = Miss(
            id=f"miss-{len(existing) + 1:05d}",
            text=text[:20000],
            channel=channel,
            source=source,
            goal=goal,
            note=note[:500],
            verdict_at_time=verdict,
        )
        if any(x.signature == m.signature for x in existing):
            return None  # already logged
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(m), ensure_ascii=False) + "\n")
        return m


def campaign_of(m: Miss) -> Campaign:
    return Campaign(
        id=m.id,
        run_id="miss-log",
        round=0,
        family=m.source,
        goal=m.goal,
        vector=f"miss:{m.source}",
        channel=m.channel,
        payload=m.text,
    )


def dev_benign_messages(limit: int = 400) -> list[dict[str, Any]]:
    """Benign replay messages for G2: the dev corpus's benign rows, as output-channel text."""
    rows = [e for e in load(["dev"]) if e.label == "benign"][:limit]
    return [
        {
            "id": e.id,
            "label": "benign",
            "ctx": {
                "channel": "output",
                "sessionId": "gate",
                "server": "lab",
                "tool": "read",
                "riskTier": "read_only",
                "tainted": False,
                "text": e.text,
            },
        }
        for e in rows
    ]


@dataclass
class Outcome:
    miss_id: str
    signature: str
    proposed: bool
    author: str = ""
    rule_id: str = ""
    passed_offline_gate: bool = False
    failed_stage: str = ""
    stages: list[dict[str, Any]] = field(default_factory=list)
    rule: dict[str, Any] | None = None
    skipped_live_stages: list[str] = field(default_factory=lambda: ["G3", "G6", "G7", "G8"])
    note: str = ""

    @property
    def deferred(self) -> bool:
        return self.failed_stage.startswith("deferred")


def learn(
    misses: list[Miss],
    benign: list[dict[str, Any]] | None = None,
    thresholds: GateThresholds | None = None,
) -> list[Outcome]:
    memory = DefenceMemory()
    blue = BlueTeam(memory)
    gate = ValidationGate(
        thresholds=thresholds, benign_corpus=benign if benign is not None else dev_benign_messages()
    )
    out: list[Outcome] = []
    for i, m in enumerate(misses):
        c = campaign_of(m)
        p = blue.propose(c, round_no=i)
        if p is None:
            out.append(
                Outcome(
                    m.id,
                    c.signature,
                    False,
                    note="no template matched; a person or the LLM blue team has to write this one",
                )
            )
            continue
        report = gate.run(p.rule, c)
        bad = next((s for s in report.stages if not s.passed), None)
        failed = bad.stage if bad else ""
        if bad and bad.detail.get("reason") == "rule budget exhausted":
            failed = "deferred: hourly rule budget"  # a safety cap on the loop, not a verdict on the rule
        out.append(
            Outcome(
                m.id,
                c.signature,
                True,
                p.author,
                p.rule["id"],
                report.passed,
                failed,
                [asdict(s) for s in report.stages],
                p.rule if report.passed else None,
            )
        )
    return out


def to_markdown(outcomes: list[Outcome]) -> str:
    ok = [o for o in outcomes if o.passed_offline_gate]
    deferred = sum(o.deferred for o in outcomes)
    lines = [
        "# What Warden learned from its misses",
        "",
        f"{len(outcomes)} logged miss(es); {sum(o.proposed for o in outcomes)} got a proposed rule; {len(ok)} cleared the offline gate (G1, G2, G4, G5).",
        "Live stages G3, G6 and G7 and the human approval G8 have **not** run. Nothing here enforces; proposals are in shadow mode.",
        *(
            [
                f"{deferred} proposal(s) were deferred by the hourly new-rule budget (a safety cap), not rejected; rerun later."
            ]
            if deferred
            else []
        ),
        "",
        "| miss | rule | author | offline gate | failed at |",
        "|---|---|---|---|---|",
    ]
    for o in outcomes:
        lines.append(
            f"| {o.miss_id} | {o.rule_id or '-'} | {o.author or '-'} | {'pass' if o.passed_offline_gate else 'fail' if o.proposed else 'no proposal'} | {o.failed_stage or o.note or '-'} |"
        )
    return "\n".join(lines) + "\n"


def write_report(outcomes: list[Outcome], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "learning-report.json").write_text(json.dumps([asdict(o) for o in outcomes], indent=2))
    (out_dir / "learning-report.md").write_text(to_markdown(outcomes))
    rules = [o.rule for o in outcomes if o.rule]
    if rules:
        (out_dir / "proposed-rules.json").write_text(json.dumps(rules, indent=2))
