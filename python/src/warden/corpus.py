"""Seed corpus access. The test splits stay locked unless WARDEN_UNLOCK_TEST=1 (final runs only)."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from warden.settings import get_settings


@dataclass(frozen=True)
class Example:
    id: str
    text: str
    label: str  # attack | benign
    family: str
    split: str  # dev | test_iid | test_ood
    channel: str = "output"
    goal: str = ""
    source: str = "warden-synthetic"


class LockedSplitError(RuntimeError):
    pass


def _corpus_dir() -> Path:
    return get_settings().data_dir / "corpus"


def load(splits: Iterable[str] = ("dev",), labels: Iterable[str] = ("attack", "benign")) -> list[Example]:
    want_splits = set(splits)
    if any(s.startswith("test") for s in want_splits) and os.environ.get("WARDEN_UNLOCK_TEST") != "1":
        raise LockedSplitError(
            "test splits are locked; set WARDEN_UNLOCK_TEST=1 only for the final locked run"
        )
    want_labels = set(labels)
    out: list[Example] = []
    for name in ("attacks.jsonl", "benign.jsonl", "imported.jsonl"):
        path = _corpus_dir() / name
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            if r["split"] in want_splits and r["label"] in want_labels:
                out.append(
                    Example(
                        id=r["id"],
                        text=r["text"],
                        label=r["label"],
                        family=r.get("family", ""),
                        split=r["split"],
                        channel=r.get("channel", "output"),
                        goal=r.get("goal", ""),
                        source=r.get("source", ""),
                    )
                )
    return out


def verify_lock() -> bool:
    """Recompute the test-split commitment and compare with LOCKED.sha256."""
    ids: list[str] = []
    for name in ("attacks.jsonl", "benign.jsonl"):
        path = _corpus_dir() / name
        for line in path.read_text().splitlines():
            if line.strip():
                r = json.loads(line)
                if str(r["split"]).startswith("test"):
                    ids.append(r["id"])
    digest = hashlib.sha256("\n".join(sorted(ids)).encode()).hexdigest()
    committed = (_corpus_dir() / "LOCKED.sha256").read_text().split()[0]
    return digest == committed
