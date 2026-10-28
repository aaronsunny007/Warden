"""Defence memory.

Promoted defences are stored with the campaign signatures they answer, so a repeat or a
variant of an attack is met from memory instead of re-deriving a rule. Rules that stop firing
are retired. Backed by the `defences` table, with an in-memory fallback for tests.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from warden.detector.text import normalize

_WORD = re.compile(r"[a-z0-9]+")


def campaign_signature(goal: str, vector: str, payload: str) -> str:
    """A stable signature for an attack: its goal and delivery vector, plus a token shingle of the
    normalised payload. Variants of one attack share a signature; unrelated attacks do not."""
    tokens = _WORD.findall(normalize(payload).lower())
    shingle = " ".join(sorted(set(tokens)))[:400]
    return hashlib.sha256(f"{goal}|{vector}|{shingle}".encode()).hexdigest()[:24]


@dataclass
class DefenceRecord:
    rule_id: str
    version: int
    rule_hash: str
    rule: dict[str, Any]
    signatures: list[str] = field(default_factory=list)
    hits: int = 0
    retired: bool = False
    last_hit_at: str | None = None


class DefenceMemory:
    """In-memory defence memory (tests and single-run loops)."""

    def __init__(self) -> None:
        self._by_id: dict[str, DefenceRecord] = {}
        self._by_sig: dict[str, str] = {}

    def lookup(self, signature: str) -> DefenceRecord | None:
        rid = self._by_sig.get(signature)
        rec = self._by_id.get(rid) if rid else None
        return rec if rec and not rec.retired else None

    def remember(self, rec: DefenceRecord) -> None:
        self._by_id[rec.rule_id] = rec
        for sig in rec.signatures:
            self._by_sig[sig] = rec.rule_id

    def add_signature(self, rule_id: str, signature: str) -> None:
        rec = self._by_id.get(rule_id)
        if rec and signature not in rec.signatures:
            rec.signatures.append(signature)
            self._by_sig[signature] = rule_id

    def record_hit(self, rule_id: str) -> None:
        rec = self._by_id.get(rule_id)
        if rec:
            rec.hits += 1
            rec.last_hit_at = datetime.now(UTC).isoformat()

    def retire(self, rule_id: str) -> None:
        rec = self._by_id.get(rule_id)
        if rec:
            rec.retired = True

    def active(self) -> list[DefenceRecord]:
        return [r for r in self._by_id.values() if not r.retired]

    def rules(self) -> list[dict[str, Any]]:
        return [r.rule for r in self.active()]


class PgDefenceMemory(DefenceMemory):
    """Defence memory backed by the `defences` table; loads existing rows on construction."""

    def __init__(self, database_url: str) -> None:
        super().__init__()
        from sqlalchemy import select

        from warden.db.models import Defence
        from warden.db.session import session_factory

        self._sf = session_factory(database_url)
        self._Defence = Defence
        with self._sf() as s:
            for d in s.execute(select(Defence)).scalars():
                rec = DefenceRecord(
                    d.rule_id,
                    d.version,
                    d.rule_hash,
                    d.rule,
                    list(d.signatures),
                    d.hits,
                    d.retired,
                    d.last_hit_at.isoformat() if d.last_hit_at else None,
                )
                super().remember(rec)

    def remember(self, rec: DefenceRecord) -> None:
        super().remember(rec)
        from sqlalchemy.dialects.postgresql import insert

        with self._sf.begin() as s:
            stmt = insert(self._Defence).values(
                rule_id=rec.rule_id,
                version=rec.version,
                rule_hash=rec.rule_hash,
                rule=rec.rule,
                signatures=rec.signatures,
                hits=rec.hits,
                retired=rec.retired,
            )
            s.execute(
                stmt.on_conflict_do_update(
                    index_elements=["rule_id", "version"],
                    set_={"signatures": rec.signatures, "rule_hash": rec.rule_hash, "rule": rec.rule},
                )
            )
