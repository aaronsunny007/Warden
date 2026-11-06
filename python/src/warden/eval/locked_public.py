"""One-shot score of the detection cascade on the public held-out split (data/heldout).

This is a *second* locked split, added after the synthetic test split was spent. It is public
data (deepset/prompt-injections, test file), so unlike the synthetic corpus it is not written by the
same hands as the training data. Nothing is tuned against it: the channel, variants and metrics
are fixed in data/heldout/README.md before any score exists, and the output file is write-once.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from warden.corpus import Example, LockedSplitError
from warden.detector.service import build_cascade
from warden.eval.locked import _score
from warden.settings import get_settings

UNLOCK_ENV = "WARDEN_UNLOCK_PUBLIC_HELDOUT"


def _dir() -> Path:
    return get_settings().data_dir / "heldout"


def load_public() -> list[Example]:
    """Load the public held-out examples. Callers must have passed the unlock gate."""
    out: list[Example] = []
    for line in (_dir() / "public_deepset_test.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            out.append(
                Example(
                    id=r["id"],
                    text=r["text"],
                    label=r["label"],
                    family=r["family"],
                    split=r["split"],
                    channel=r["channel"],
                    goal=r.get("goal", ""),
                    source=r["source"],
                )
            )
    return out


def verify_public_lock() -> bool:
    """Recompute the id commitment and compare with data/heldout/LOCKED.sha256."""
    ids = sorted(e.id for e in load_public())
    digest = hashlib.sha256("\n".join(ids).encode()).hexdigest()
    return digest == (_dir() / "LOCKED.sha256").read_text().split()[0]


def run(out: Path, onnx: dict[str, str] | None = None) -> dict[str, object]:
    if os.environ.get(UNLOCK_ENV) != "1":
        raise LockedSplitError(f"set {UNLOCK_ENV}=1 for the one-shot public held-out run")
    if out.exists():
        raise FileExistsError(f"{out} exists: the public held-out split is scored once")
    if not verify_public_lock():
        raise LockedSplitError("data/heldout/LOCKED.sha256 does not match the public held-out split")
    s = get_settings()
    examples = load_public()
    results: dict[str, object] = {
        "split": "public_heldout (deepset/prompt-injections test, Apache-2.0)",
        "n": len(examples),
        "embedder": s.embed_model,
        "l2_mode": s.l2_mode,
        "judge": bool(s.judge_model),
    }
    variants: dict[str, dict[str, object]] = {
        "cascade_full": {"cascade": "full"},
        "l2_only": {"cascade": "l2only"},
    }
    for tag, d in (onnx or {}).items():
        variants[f"cascade_full+{tag}"] = {"cascade": "full", "l2_mode": "onnx", "l2_onnx_dir": d}
        variants[f"l2_only+{tag}"] = {"cascade": "l2only", "l2_mode": "onnx", "l2_onnx_dir": d}
    for name, upd in variants.items():
        c = build_cascade(s.model_copy(update=upd))
        results[name] = _score(c, examples)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    return results
