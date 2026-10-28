"""Blue team: propose a candidate defence for a confirmed bypass.

Order, as in the design: defence memory first (reuse or generalise an existing rule), then
templates, and only then a local LLM as a last resort. Output is always a Policy IR rule dict;
it is the validation gate, not the blue team, that decides whether it may ever enforce. The
blue team is unprivileged: it emits typed Policy IR that the trusted compiler validates, and
it never calls tools.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

from warden.detector.text import normalize
from warden.loop.campaign import Campaign
from warden.loop.memory import DefenceMemory

# Common words that carry no signal; a rule keyed on these would over-block.
_STOP = set(
    [
        "the",
        "a",
        "an",
        "and",
        "or",
        "but",
        "to",
        "of",
        "in",
        "on",
        "for",
        "with",
        "from",
        "your",
        "you",
        "i",
        "me",
        "my",
        "we",
        "our",
        "they",
        "them",
        "this",
        "that",
        "these",
        "those",
        "is",
        "are",
        "was",
        "be",
        "been",
        "being",
        "do",
        "does",
        "did",
        "have",
        "has",
        "had",
        "will",
        "would",
        "can",
        "could",
        "should",
        "please",
        "thank",
        "thanks",
        "hi",
        "hello",
        "dear",
        "regards",
        "best",
        "it",
        "its",
        "as",
        "at",
        "by",
        "if",
        "so",
        "then",
        "than",
        "also",
        "just",
        "only",
        "not",
        "no",
        "yes",
        "here",
        "there",
        "when",
        "where",
        "what",
        "which",
        "who",
        "how",
        "all",
        "any",
    ]
)


@dataclass
class Proposal:
    rule: dict[str, Any]
    author: str  # memory | template | llm
    signature: str
    note: str


def _signal_phrases(payload: str, max_phrases: int = 3) -> list[str]:
    """Distinctive 3-4 word phrases from the payload, avoiding stopword-only runs.

    Phrases are contiguous runs of whitespace-separated tokens of the NORMALISED text, so each is
    guaranteed to be a substring of what the compiler sees (a text `contains` match then fires).
    Ranking counts a token as signal when its letters-only form is not a stopword, so short words
    and punctuation-bearing tokens (an address, a path) still anchor a phrase.
    """
    norm = normalize(payload).lower()
    tokens = norm.split()

    def is_signal(tok: str) -> bool:
        letters = re.sub(r"[^a-z0-9]", "", tok)
        return bool(letters) and letters not in _STOP

    phrases: list[str] = []
    for n in (4, 3):
        for i in range(len(tokens) - n + 1):
            window = tokens[i : i + n]
            if sum(is_signal(w) for w in window) >= max(2, n - 1):
                phrases.append(" ".join(window))
    freq = Counter(phrases)
    ranked = sorted(set(phrases), key=lambda p: (-sum(is_signal(w) for w in p.split()), -freq[p], p))
    return ranked[:max_phrases]


def _owasp_for(channel: str, goal: str) -> list[str]:
    if channel == "description":
        return ["MCP03", "ASI04"]
    if channel == "arguments":
        return ["ASI02", "MCP10"] if "exfil" in goal or "leak" in goal else ["ASI02"]
    return ["ASI01", "MCP10"]


def _next_version(memory: DefenceMemory, rule_id: str) -> int:
    existing = [r for r in memory._by_id.values() if r.rule_id == rule_id]
    return max((r.version for r in existing), default=0) + 1


class BlueTeam:
    def __init__(self, memory: DefenceMemory, llm: Any | None = None, budget: Any | None = None) -> None:
        self.memory = memory
        self.llm = llm
        self.budget = budget

    def propose(self, campaign: Campaign, round_no: int = 0) -> Proposal | None:
        # 1) Memory: an existing rule already answers this signature -> reuse by adding the signature.
        hit = self.memory.lookup(campaign.signature)
        if hit is not None:
            return Proposal(hit.rule, "memory", campaign.signature, f"reused {hit.rule_id} v{hit.version}")
        # 2) Templates.
        tpl = self._template(campaign, round_no)
        if tpl is not None:
            return tpl
        # 3) LLM last resort.
        if self.llm is not None and (self.budget is None or self.budget.allow_llm(2000)):
            return self._llm(campaign, round_no)
        return None

    def _rule_id(self, campaign: Campaign, round_no: int) -> str:
        prefix = {"description": "WL-DESC", "arguments": "WL-ARG", "output": "WL-OUT"}[campaign.channel]
        return f"{prefix}-{campaign.signature[:6].upper()}"

    def _template(self, c: Campaign, round_no: int) -> Proposal | None:
        rid = self._rule_id(c, round_no)
        version = _next_version(self.memory, rid)
        owasp = _owasp_for(c.channel, c.goal)
        base = {
            "id": rid,
            "version": version,
            "owasp": owasp,
            "provenance": {"author": "template", "campaign": c.id, "note": c.goal},
        }

        if c.channel == "arguments" and c.exfil_value:
            # An argument carried a value that should not be reachable; block that class of value.
            if "@" in c.exfil_value:
                match: dict[str, Any] = {"kind": "email", "field": "args.**", "domainNotIn": ["acme.example"]}
            elif c.exfil_value.replace(".", "").isdigit():
                match = {"kind": "numeric", "field": "args.**", "gt": max(0.0, float(c.exfil_value) - 0.01)}
            else:
                match = {"kind": "url", "field": "args.**", "privateAddress": True}
            return Proposal(
                {
                    **base,
                    "description": f"Blue-team rule for {c.id}: block a high-risk call whose argument reaches {c.exfil_value[:40]}.",
                    "mode": "shadow",
                    "severity": "high",
                    "action": {
                        "type": "step_up",
                        "message": "destination not traceable to the user's request",
                    },
                    "scope": {
                        "channels": ["arguments"],
                        "taint": "tainted",
                        "riskTiers": ["external_send", "financial_destructive"],
                    },
                    "match": match,
                },
                "template",
                c.signature,
                "argument-sink template",
            )

        phrases = _signal_phrases(c.payload)
        if not phrases:
            return None
        if c.channel == "description":
            return Proposal(
                {
                    **base,
                    "description": f"Blue-team rule for {c.id}: quarantine a tool whose description contains injected instructions.",
                    "mode": "shadow",
                    "severity": "critical",
                    "action": {
                        "type": "quarantine_tool",
                        "message": "tool description contains injected instructions",
                    },
                    "scope": {"channels": ["description"]},
                    "match": {
                        "any": [
                            {"kind": "text", "field": "text", "op": "contains", "value": p} for p in phrases
                        ]
                    },
                },
                "template",
                c.signature,
                "description-phrase template",
            )
        # output channel
        return Proposal(
            {
                **base,
                "description": f"Blue-team rule for {c.id}: redact an injected instruction in tool output.",
                "mode": "shadow",
                "severity": "high",
                "action": {"type": "redact", "message": "injected instruction removed from tool output"},
                "scope": {"channels": ["output"]},
                "match": {
                    "any": [{"kind": "text", "field": "text", "op": "contains", "value": p} for p in phrases]
                },
            },
            "template",
            c.signature,
            "output-phrase template",
        )

    def _llm(self, c: Campaign, round_no: int) -> Proposal | None:
        from warden.loop.llm import propose_rule_via_llm

        rule = propose_rule_via_llm(
            self.llm,
            c,
            self._rule_id(c, round_no),
            _next_version(self.memory, self._rule_id(c, round_no)),
            _owasp_for(c.channel, c.goal),
        )
        if rule is None:
            return None
        return Proposal(rule, "llm", c.signature, "llm-proposed")
