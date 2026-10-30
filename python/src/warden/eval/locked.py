"""Final locked-split run: score the detection cascade on test_iid / test_ood exactly once.

Nothing is tuned against these numbers. The output file is write-once: a second run refuses
unless it is deleted, so a re-roll after seeing the result is a visible, deliberate act.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from warden.corpus import LockedSplitError, load, verify_lock
from warden.detector.cascade import Cascade
from warden.detector.service import build_cascade
from warden.settings import get_settings
from warden.stats import wilson


def _rate(hits: int, n: int) -> dict[str, object]:
    r = wilson(hits, n)
    return {"hits": hits, "n": n, "rate": round(r.value, 4), "ci95": [round(r.low, 4), round(r.high, 4)]}


def _score(cascade: Cascade, examples: list) -> dict[str, object]:  # type: ignore[type-arg]
    atk = [e for e in examples if e.label == "attack"]
    ben = [e for e in examples if e.label == "benign"]
    ds = {e.id: cascade.detect(e.text, e.channel) for e in examples}
    out: dict[str, object] = {
        "attack_blocked": _rate(sum(ds[e.id].verdict == "malicious" for e in atk), len(atk)),
        "attack_flagged": _rate(sum(ds[e.id].verdict != "benign" for e in atk), len(atk)),
    }
    if ben:
        out["benign_blocked"] = _rate(sum(ds[e.id].verdict == "malicious" for e in ben), len(ben))
        out["benign_flagged"] = _rate(sum(ds[e.id].verdict != "benign" for e in ben), len(ben))
    fam: dict[str, tuple[int, int]] = {}
    for e in atk:
        h, n = fam.get(e.family, (0, 0))
        fam[e.family] = (h + (ds[e.id].verdict != "benign"), n + 1)
    out["attack_flagged_by_family"] = {k: _rate(*v) for k, v in sorted(fam.items())}
    return out


def run(out: Path, onnx: dict[str, str] | None = None) -> dict[str, object]:
    if os.environ.get("WARDEN_UNLOCK_TEST") != "1":
        raise LockedSplitError("set WARDEN_UNLOCK_TEST=1 for the final locked run")
    if out.exists():
        raise FileExistsError(f"{out} exists: the locked split is scored once")
    if not verify_lock():
        raise LockedSplitError("LOCKED.sha256 does not match the test split")
    s = get_settings()
    results: dict[str, object] = {
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
        results[name] = {split: _score(c, load([split])) for split in ("test_iid", "test_ood")}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    return results
