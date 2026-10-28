"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-10-28 06:00:55.437000
"""

import pgvector.sqlalchemy
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    op.create_table(
        "benign_calls",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("scenario", sa.String(length=64), nullable=False),
        sa.Column("channel", sa.String(length=16), nullable=False),
        sa.Column("ctx", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_benign_calls_run_id"), "benign_calls", ["run_id"], unique=False)
    op.create_table(
        "campaigns",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("round", sa.Integer(), nullable=False),
        sa.Column("family", sa.String(length=64), nullable=False),
        sa.Column("goal", sa.String(length=64), nullable=False),
        sa.Column("vector", sa.String(length=128), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("operators", sa.ARRAY(sa.String(length=32)), nullable=False),
        sa.Column("bypass", sa.Boolean(), nullable=False),
        sa.Column("judge", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("trace", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_campaigns_bypass"), "campaigns", ["bypass"], unique=False)
    op.create_index(op.f("ix_campaigns_run_id"), "campaigns", ["run_id"], unique=False)
    op.create_table(
        "corpus",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("label", sa.String(length=16), nullable=False),
        sa.Column("family", sa.String(length=64), nullable=False),
        sa.Column("split", sa.String(length=16), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("channel", sa.String(length=16), nullable=False),
        sa.Column("embedding", pgvector.sqlalchemy.vector.VECTOR(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_corpus_label"), "corpus", ["label"], unique=False)
    op.create_index(op.f("ix_corpus_split"), "corpus", ["split"], unique=False)
    op.create_table(
        "defences",
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("rule_hash", sa.String(length=64), nullable=False),
        sa.Column("rule", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("signatures", sa.ARRAY(sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_hit_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("hits", sa.Integer(), nullable=False),
        sa.Column("retired", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("rule_id", "version"),
    )
    op.create_table(
        "eval_runs",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("experiment", sa.String(length=32), nullable=False),
        sa.Column("config", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("results", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_eval_runs_experiment"), "eval_runs", ["experiment"], unique=False)
    op.create_table(
        "human_labels",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("case_id", sa.String(length=64), nullable=False),
        sa.Column("label", sa.String(length=16), nullable=False),
        sa.Column("labeller", sa.String(length=64), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_human_labels_case_id"), "human_labels", ["case_id"], unique=False)
    op.create_table(
        "verdicts",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("session_id", sa.String(length=128), nullable=False),
        sa.Column("server", sa.String(length=64), nullable=False),
        sa.Column("tool", sa.String(length=128), nullable=False),
        sa.Column("channel", sa.String(length=16), nullable=False),
        sa.Column("risk_tier", sa.String(length=32), nullable=False),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("rule_ids", sa.ARRAY(sa.String(length=64)), nullable=False),
        sa.Column("shadow_rule_ids", sa.ARRAY(sa.String(length=64)), nullable=False),
        sa.Column("layer", sa.String(length=16), nullable=False),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("tainted", sa.Boolean(), nullable=False),
        sa.Column("latency_ms", sa.Float(), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("owasp", sa.ARRAY(sa.String(length=8)), nullable=False),
        sa.Column("bundle_id", sa.String(length=128), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_verdicts_decision"), "verdicts", ["decision"], unique=False)
    op.create_index(op.f("ix_verdicts_session_id"), "verdicts", ["session_id"], unique=False)
    op.create_index(op.f("ix_verdicts_ts"), "verdicts", ["ts"], unique=False)
    op.create_index("ix_verdicts_ts_decision", "verdicts", ["ts", "decision"], unique=False)
    op.create_table(
        "candidates",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("campaign_id", sa.String(length=64), nullable=True),
        sa.Column("author", sa.String(length=16), nullable=False),
        sa.Column("rule", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("rule_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("stage", sa.String(length=8), nullable=False),
        sa.Column("report_id", sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(
            ["campaign_id"],
            ["campaigns.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_candidates_rule_hash"), "candidates", ["rule_hash"], unique=False)
    op.create_index(op.f("ix_candidates_status"), "candidates", ["status"], unique=False)
    op.create_table(
        "gate_reports",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("candidate_id", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("passed", sa.Boolean(), nullable=False),
        sa.Column("report", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(
            ["candidate_id"],
            ["candidates.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_gate_reports_candidate_id"), "gate_reports", ["candidate_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_gate_reports_candidate_id"), table_name="gate_reports")
    op.drop_table("gate_reports")
    op.drop_index(op.f("ix_candidates_status"), table_name="candidates")
    op.drop_index(op.f("ix_candidates_rule_hash"), table_name="candidates")
    op.drop_table("candidates")
    op.drop_index("ix_verdicts_ts_decision", table_name="verdicts")
    op.drop_index(op.f("ix_verdicts_ts"), table_name="verdicts")
    op.drop_index(op.f("ix_verdicts_session_id"), table_name="verdicts")
    op.drop_index(op.f("ix_verdicts_decision"), table_name="verdicts")
    op.drop_table("verdicts")
    op.drop_index(op.f("ix_human_labels_case_id"), table_name="human_labels")
    op.drop_table("human_labels")
    op.drop_index(op.f("ix_eval_runs_experiment"), table_name="eval_runs")
    op.drop_table("eval_runs")
    op.drop_table("defences")
    op.drop_index(op.f("ix_corpus_split"), table_name="corpus")
    op.drop_index(op.f("ix_corpus_label"), table_name="corpus")
    op.drop_table("corpus")
    op.drop_index(op.f("ix_campaigns_run_id"), table_name="campaigns")
    op.drop_index(op.f("ix_campaigns_bypass"), table_name="campaigns")
    op.drop_table("campaigns")
    op.drop_index(op.f("ix_benign_calls_run_id"), table_name="benign_calls")
    op.drop_table("benign_calls")
