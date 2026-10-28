"""Control-plane API (FastAPI).

Read-only views over the loop's records (campaigns, candidates, gate reports, defences) for the
dashboard, plus the promotion workflow: a candidate that passed the gate is signed into a new
policy bundle and offered to the gateway, but promotion to *enforce* needs a human approval
(gate stage G8). The control plane never enforces anything itself and never calls tools; it only
assembles and signs bundles the gateway then verifies.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select

from warden import __version__, policy_cli
from warden.db.models import Campaign, Candidate, Defence, GateReport
from warden.db.session import session_factory
from warden.settings import Settings, get_settings


class ApproveRequest(BaseModel):
    approver: str
    stage: str = "enforce"


def _signing_key(s: Settings) -> tuple[Path, str]:
    if not s.signing_key:
        raise HTTPException(503, "no signing key configured (WARDEN_SIGNING_KEY)")
    return Path(s.signing_key), s.signing_key_id


def create_app(settings: Settings | None = None) -> FastAPI:
    s = settings or get_settings()
    sf = session_factory(s.database_url)
    app = FastAPI(title="Warden control plane", version=__version__)

    @app.get("/healthz")
    def healthz() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/v1/campaigns")
    def campaigns(limit: int = 100, bypass_only: bool = False) -> list[dict[str, Any]]:
        with sf() as db:
            q = select(Campaign).order_by(Campaign.created_at.desc()).limit(min(limit, 1000))
            if bypass_only:
                q = q.where(Campaign.bypass.is_(True))
            return [
                {"id": c.id, "run_id": c.run_id, "round": c.round, "family": c.family, "goal": c.goal, "vector": c.vector, "bypass": c.bypass, "created_at": c.created_at.isoformat()}
                for c in db.execute(q).scalars()
            ]

    @app.get("/v1/candidates")
    def candidates(status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        with sf() as db:
            q = select(Candidate).order_by(Candidate.created_at.desc()).limit(min(limit, 1000))
            if status:
                q = q.where(Candidate.status == status)
            return [
                {"id": c.id, "author": c.author, "status": c.status, "stage": c.stage, "rule_id": c.rule["id"], "rule_hash": c.rule_hash, "report_id": c.report_id, "created_at": c.created_at.isoformat()}
                for c in db.execute(q).scalars()
            ]

    @app.get("/v1/candidates/{candidate_id}")
    def candidate(candidate_id: str) -> dict[str, Any]:
        with sf() as db:
            c = db.get(Candidate, candidate_id)
            if not c:
                raise HTTPException(404, "unknown candidate")
            report = db.get(GateReport, c.report_id) if c.report_id else None
            return {"id": c.id, "author": c.author, "status": c.status, "stage": c.stage, "rule": c.rule, "rule_hash": c.rule_hash, "report": report.report if report else None}

    @app.get("/v1/gate-reports/{report_id}")
    def gate_report(report_id: str) -> dict[str, Any]:
        with sf() as db:
            r = db.get(GateReport, report_id)
            if not r:
                raise HTTPException(404, "unknown report")
            return {"id": r.id, "candidate_id": r.candidate_id, "passed": r.passed, "report": r.report, "created_at": r.created_at.isoformat()}

    @app.get("/v1/defences")
    def defences() -> list[dict[str, Any]]:
        with sf() as db:
            return [
                {"rule_id": d.rule_id, "version": d.version, "hits": d.hits, "retired": d.retired, "signatures": len(d.signatures), "owasp": d.rule.get("owasp", [])}
                for d in db.execute(select(Defence).where(Defence.retired.is_(False))).scalars()
            ]

    @app.post("/v1/candidates/{candidate_id}/approve")
    def approve(candidate_id: str, body: ApproveRequest) -> dict[str, Any]:
        """Human approval (G8): sign the candidate's rule, at its gate-tested hash, into a bundle."""
        key_path, key_id = _signing_key(s)
        with sf.begin() as db:
            c = db.get(Candidate, candidate_id)
            if not c:
                raise HTTPException(404, "unknown candidate")
            if c.status != "awaiting_approval":
                raise HTTPException(409, f"candidate is {c.status}, not awaiting_approval")
            report = db.get(GateReport, c.report_id) if c.report_id else None
            if not report or not report.passed:
                raise HTTPException(409, "candidate has no passing gate report")
            active = [d.rule for d in db.execute(select(Defence).where(Defence.retired.is_(False))).scalars()]
            rule = {**c.rule, "mode": body.stage}
            rules = [r for r in active if r["id"] != rule["id"]] + [rule]
            hashes = policy_cli.hashes(rules)
            approvals = [
                {"ruleId": r["id"], "version": r["version"], "ruleHash": hashes[r["id"]], "stage": body.stage if r["id"] == rule["id"] else r.get("mode", "enforce"),
                 "gateReport": report.id if r["id"] == rule["id"] else "0" * 64, "approvedBy": body.approver, "human": r["id"] == rule["id"], "approvedAt": datetime.now(UTC).isoformat()}
                for r in rules
            ]
            bundle = policy_cli.sign(policy_cli.build_bundle(rules, approvals, f"promote-{candidate_id}"), key_path, key_id)
            c.status = "approved"
            c.stage = body.stage
        return {"ok": True, "candidate": candidate_id, "stage": body.stage, "bundle_id": bundle["id"], "note": "deliver this signed bundle to the gateway (PUT /api/v1/policy) or commit it for the gateway to hot-reload"}

    @app.get("/v1/stats")
    def stats() -> dict[str, Any]:
        with sf() as db:
            return {
                "campaigns": db.execute(select(func.count()).select_from(Campaign)).scalar_one(),
                "bypasses": db.execute(select(func.count()).select_from(Campaign).where(Campaign.bypass.is_(True))).scalar_one(),
                "candidates": db.execute(select(func.count()).select_from(Candidate)).scalar_one(),
                "defences": db.execute(select(func.count()).select_from(Defence).where(Defence.retired.is_(False))).scalar_one(),
            }

    return app
