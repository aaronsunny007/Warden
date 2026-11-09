"""One-shot scores of the detection cascade on the round-2 fresh test splits (data/heldout/fresh).

Protocol, training pool and caveats are fixed in data/heldout/fresh/README.md before any model is trained on the
new data. Each split is scored once: the unlock env var is required, the id commitment is verified, and the output
file is write-once. Nothing is tuned against these numbers.
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

UNLOCK_ENV = "WARDEN_UNLOCK_FRESH_HELDOUT"
SPLITS = ("neuralchemy_test", "jackhhao_test")


def _dir() -> Path:
    return get_settings().data_dir / "heldout" / "fresh"


def load_fresh(split: str) -> list[Example]:
    """Load one fresh split. Callers must have passed the unlock gate."""
    if split not in SPLITS:
        raise ValueError(f"unknown split {split!r}; expected one of {SPLITS}")
    out: list[Example] = []
    for line in (_dir() / f"{split}.jsonl").read_text(encoding="utf-8").splitlines():
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


def verify_fresh_lock(split: str) -> bool:
    """Recompute the id commitment for one split and compare with data/heldout/fresh/LOCKED.sha256."""
    digest = hashlib.sha256(
        "\n".join(e.id for e in sorted(load_fresh(split), key=lambda e: e.id)).encode()
    ).hexdigest()
    for line in (_dir() / "LOCKED.sha256").read_text().splitlines():
        parts = line.split()
        if len(parts) > 1 and parts[1] == split:
            return parts[0] == digest
    return False


def run(
    split: str,
    out: Path,
    onnx: dict[str, str] | None = None,
    lite_extra: dict[str, str] | None = None,
) -> dict[str, object]:
    """Score `split` once. `onnx` maps tag -> ONNX bundle dir; `lite_extra` maps tag -> JSONL of extra lite training."""
    if os.environ.get(UNLOCK_ENV) != "1":
        raise LockedSplitError(f"set {UNLOCK_ENV}=1 for the one-shot fresh held-out run")
    if out.exists():
        raise FileExistsError(f"{out} exists: each fresh split is scored once")
    if not verify_fresh_lock(split):
        raise LockedSplitError(f"data/heldout/fresh/LOCKED.sha256 does not match {split}")
    s = get_settings()
    examples = load_fresh(split)
    results: dict[str, object] = {
        "split": split,
        "n": len(examples),
        "embedder": s.embed_model,
        "l2_mode": s.l2_mode,
        "judge": bool(s.judge_model),
    }
    classifiers: dict[str, dict[str, object]] = {"lite": {}}
    for tag, d in (lite_extra or {}).items():
        classifiers[f"lite+{tag}"] = {"l2_extra_train": d}
    for tag, d in (onnx or {}).items():
        classifiers[f"onnx+{tag}"] = {"l2_mode": "onnx", "l2_onnx_dir": d}
    for ctag, cupd in classifiers.items():
        for kind, cascade in (("cascade_full", "full"), ("l2_only", "l2only")):
            c = build_cascade(s.model_copy(update={"cascade": cascade, **cupd}))
            results[f"{kind}:{ctag}"] = _score(c, examples)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    return results
