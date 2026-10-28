"""Optional persistence of loop records to Postgres, so the control plane and dashboard can read
campaigns, candidates and gate reports. No-op when no database is configured; never fatal to the
loop (a DB hiccup must not stop the defence loop)."""

from __future__ import annotations

import logging
from typing import Any

from warden.loop.campaign import Campaign
from warden.loop.gate import GateReport

log = logging.getLogger("warden.loop.persist")


class LoopStore:
    def __init__(self, database_url: str) -> None:
        self.enabled = bool(database_url)
        self._sf = None
        if self.enabled:
            try:
                from warden.db.session import session_factory

                self._sf = session_factory(database_url)
            except Exception as e:  # noqa: BLE001 - persistence is best-effort
                log.warning("loop persistence disabled: %s", e)
                self.enabled = False

    def _do(self, fn: Any) -> None:
        if not self.enabled or self._sf is None:
            return
        try:
            with self._sf.begin() as s:
                fn(s)
        except Exception as e:  # noqa: BLE001 - best-effort
            log.warning("loop persistence write failed: %s", e)

    def campaign(self, c: Campaign, bypass: bool) -> None:
        from warden.db.models import Campaign as Row

        self._do(
            lambda s: s.merge(
                Row(id=c.id, run_id=c.run_id, round=c.round, family=c.family, goal=c.goal, vector=c.vector, payload=c.payload, operators=c.operators, bypass=bypass, judge={}, trace={})
            )
        )

    def candidate(self, candidate_id: str, campaign_id: str, author: str, rule: dict[str, Any], rule_hash: str, status: str, stage: str, report_id: str | None) -> None:
        from warden.db.models import Candidate as Row

        self._do(lambda s: s.merge(Row(id=candidate_id, campaign_id=campaign_id, author=author, rule=rule, rule_hash=rule_hash, status=status, stage=stage, report_id=report_id)))

    def gate_report(self, report: GateReport) -> str:
        from warden.db.models import GateReport as Row

        rid = report.digest()
        self._do(lambda s: s.merge(Row(id=rid, candidate_id=report.candidate_id, passed=report.passed, report={"rule_id": report.rule_id, "stages": [{"stage": st.stage, "passed": st.passed, "detail": st.detail} for st in report.stages]})))
        return rid

    def defence(self, rec: Any) -> None:
        from warden.db.models import Defence as Row

        self._do(lambda s: s.merge(Row(rule_id=rec.rule_id, version=rec.version, rule_hash=rec.rule_hash, rule=rec.rule, signatures=rec.signatures, hits=rec.hits, retired=rec.retired)))
