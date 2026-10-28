"""Warden's PostgreSQL schema: audit log, attack corpus with embeddings, loop and gate records."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import ARRAY, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

EMBED_DIM = 2048


class Base(DeclarativeBase):
    pass


class Verdict(Base):
    """Every gateway verdict (OWASP MCP08). Written by the gateway's Postgres sink or the Kafka consumer."""

    __tablename__ = "verdicts"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    session_id: Mapped[str] = mapped_column(String(128), index=True)
    server: Mapped[str] = mapped_column(String(64))
    tool: Mapped[str] = mapped_column(String(128))
    channel: Mapped[str] = mapped_column(String(16))
    risk_tier: Mapped[str] = mapped_column(String(32))
    decision: Mapped[str] = mapped_column(String(32), index=True)
    rule_ids: Mapped[list[str]] = mapped_column(ARRAY(String(64)), default=list)
    shadow_rule_ids: Mapped[list[str]] = mapped_column(ARRAY(String(64)), default=list)
    layer: Mapped[str] = mapped_column(String(16))
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    tainted: Mapped[bool] = mapped_column(Boolean, default=False)
    latency_ms: Mapped[float] = mapped_column(Float)
    explanation: Mapped[str] = mapped_column(Text)
    owasp: Mapped[list[str]] = mapped_column(ARRAY(String(8)), default=list)
    bundle_id: Mapped[str] = mapped_column(String(128))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)


class CorpusItem(Base):
    """Attack and benign examples; dev-split embeddings back the L1 layer (pgvector)."""

    __tablename__ = "corpus"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    text: Mapped[str] = mapped_column(Text)
    label: Mapped[str] = mapped_column(String(16), index=True)
    family: Mapped[str] = mapped_column(String(64), default="")
    split: Mapped[str] = mapped_column(String(16), index=True)
    source: Mapped[str] = mapped_column(String(64), default="")
    channel: Mapped[str] = mapped_column(String(16), default="output")
    embedding: Mapped[Any] = mapped_column(Vector(), nullable=True)  # dimension follows the embedder
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Campaign(Base):
    """A red-team attack and its full trace; a confirmed bypass seeds the blue team."""

    __tablename__ = "campaigns"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    run_id: Mapped[str] = mapped_column(String(64), index=True)
    round: Mapped[int] = mapped_column(Integer, default=0)
    family: Mapped[str] = mapped_column(String(64))
    goal: Mapped[str] = mapped_column(String(64))
    vector: Mapped[str] = mapped_column(String(128))
    payload: Mapped[str] = mapped_column(Text)
    operators: Mapped[list[str]] = mapped_column(ARRAY(String(32)), default=list)
    bypass: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    judge: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    trace: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


class Candidate(Base):
    """A proposed defence and where it is in the gate."""

    __tablename__ = "candidates"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    campaign_id: Mapped[str | None] = mapped_column(ForeignKey("campaigns.id"), nullable=True)
    author: Mapped[str] = mapped_column(String(16))  # memory | template | llm | human
    rule: Mapped[dict[str, Any]] = mapped_column(JSONB)
    rule_hash: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(
        String(24), index=True
    )  # proposed | gating | failed | awaiting_approval | approved | rejected | rolled_back
    stage: Mapped[str] = mapped_column(String(8), default="G1")
    report_id: Mapped[str | None] = mapped_column(String(64), nullable=True)


class GateReport(Base):
    __tablename__ = "gate_reports"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # sha256 of the canonical report
    candidate_id: Mapped[str] = mapped_column(ForeignKey("candidates.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    passed: Mapped[bool] = mapped_column(Boolean)
    report: Mapped[dict[str, Any]] = mapped_column(JSONB)


class Defence(Base):
    """Defence memory: promoted rules with the campaign signatures they answer."""

    __tablename__ = "defences"
    rule_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_hash: Mapped[str] = mapped_column(String(64))
    rule: Mapped[dict[str, Any]] = mapped_column(JSONB)
    signatures: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_hit_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    hits: Mapped[int] = mapped_column(Integer, default=0)
    retired: Mapped[bool] = mapped_column(Boolean, default=False)


class BenignCall(Base):
    """The benign tool-traffic corpus (G2): every MCP message from benign task runs."""

    __tablename__ = "benign_calls"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(64), index=True)
    scenario: Mapped[str] = mapped_column(String(64))
    channel: Mapped[str] = mapped_column(String(16))
    ctx: Mapped[dict[str, Any]] = mapped_column(JSONB)


class HumanLabel(Base):
    """Gold labels written blind to the judge's verdicts, for Cohen's kappa."""

    __tablename__ = "human_labels"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(String(64), index=True)
    label: Mapped[str] = mapped_column(String(16))
    labeller: Mapped[str] = mapped_column(String(64))
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class EvalRun(Base):
    __tablename__ = "eval_runs"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    experiment: Mapped[str] = mapped_column(String(32), index=True)
    config: Mapped[dict[str, Any]] = mapped_column(JSONB)
    results: Mapped[dict[str, Any]] = mapped_column(JSONB)


Index("ix_verdicts_ts_decision", Verdict.ts, Verdict.decision)
