"""Kafka -> Postgres audit consumer: every gateway verdict lands in the `verdicts` table."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from typing import Any

from sqlalchemy.dialects.postgresql import insert

from warden.db.models import Verdict
from warden.db.session import session_factory

log = logging.getLogger("warden.audit")


def to_row(v: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": v["id"],
        "ts": datetime.fromisoformat(v["ts"].replace("Z", "+00:00")),
        "session_id": v["sessionId"],
        "server": v["server"],
        "tool": v["tool"],
        "channel": v["channel"],
        "risk_tier": v["riskTier"],
        "decision": v["decision"],
        "rule_ids": v.get("ruleIds", []),
        "shadow_rule_ids": v.get("shadowRuleIds", []),
        "layer": v.get("layer", "L0"),
        "score": v.get("score"),
        "tainted": bool(v.get("tainted")),
        "latency_ms": float(v.get("latencyMs", 0)),
        "explanation": v.get("explanation", ""),
        "owasp": v.get("owasp", []),
        "bundle_id": v.get("bundleId", ""),
        "payload": v,
    }


def write_batch(rows: list[dict[str, Any]]) -> int:
    if not rows:
        return 0
    sf = session_factory()
    with sf.begin() as s:
        s.execute(insert(Verdict).values(rows).on_conflict_do_nothing(index_elements=["id"]))
    return len(rows)


async def consume(brokers: str, topic: str = "warden.verdicts", group: str = "warden-audit") -> None:
    from aiokafka import AIOKafkaConsumer

    consumer = AIOKafkaConsumer(
        topic,
        bootstrap_servers=brokers,
        group_id=group,
        enable_auto_commit=False,
        auto_offset_reset="earliest",
    )
    await consumer.start()
    try:
        while True:
            batch = await consumer.getmany(timeout_ms=1000, max_records=500)
            rows = []
            for msgs in batch.values():
                for m in msgs:
                    event = json.loads(m.value)
                    if event.get("type") == "verdict":
                        rows.append(to_row(event["data"]))
            if rows:
                await asyncio.to_thread(write_batch, rows)
                log.info("wrote %d verdicts", len(rows))
            if batch:
                await consumer.commit()
    finally:
        await consumer.stop()
