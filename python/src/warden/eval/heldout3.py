"""Score two new, independent test sets once: the tool-output set v2 (data/toolout2) and public round 3 (data/heldout/round3).

Both are rebuilt from pinned third-party sources (the repo holds only builders, source hashes and manifests) and checked
against their commitments before anything is scored. The unlock env var is required and the output is write-once.
Detector changes were made against the train/dev splits only; nothing is tuned against these numbers.

Variants scored on the same items:
  corpus-lite   L2 fitted on the project corpus at start-up, texts read whole (the earlier default classifier)
  docs-lite     the shipped default: lite L2 fitted with the v2 train split, long texts read in windows
  deberta       the pooled DeBERTa-v3-xsmall ONNX bundle, if models/l2-deberta-pooled exists (never the default)
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Any

from warden.corpus import LockedSplitError
from warden.detector.guard import check_text
from warden.detector.service import build_cascade
from warden.eval.toolout import _rate
from warden.settings import get_settings

UNLOCK_ENV = "WARDEN_UNLOCK_HELDOUT3"


def _load(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _sha(x: bytes | str) -> str:
    return hashlib.sha256(x if isinstance(x, bytes) else x.encode("utf-8")).hexdigest()


def toolout2_rows(root: Path) -> list[dict[str, Any]]:
    d = root / "data" / "toolout2"
    b = _load(d / "build_toolout2.py", "build_toolout2")
    items = b.build("test")
    man = "".join(f"{i['id']} {b.sha(i['text'])} {i['label']} {i['technique']}\n" for i in items)
    lock = dict(ln.split()[::-1] for ln in (d / "LOCKED.sha256").read_text().splitlines() if ln.strip())
    ids = "\n".join(i["id"] for i in items)
    if lock.get("test-ids") != _sha(ids) or lock.get("manifest.test.txt") != _sha(man):
        raise LockedSplitError(
            "toolout2 test set does not match data/toolout2/LOCKED.sha256 (sources or packages differ)"
        )
    return items  # type: ignore[no-any-return]


def round3_rows(root: Path) -> list[dict[str, Any]]:
    d = root / "data" / "heldout" / "round3"
    rows = [json.loads(x) for x in (d / "test.jsonl").read_text(encoding="utf-8").split("\n") if x.strip()]
    ids = "".join(f"{r['id']} {r['label']}\n" for r in rows)
    lock = (d / "LOCKED.sha256").read_text().split()[0]
    if _sha(ids) != lock or ids != (d / "ids.txt").read_text():
        raise LockedSplitError("round-3 test set does not match data/heldout/round3/LOCKED.sha256")
    return rows


def _verdicts(cascade: Any, rows: list[dict[str, Any]]) -> list[str]:
    return [check_text(cascade, r["text"]).verdict for r in rows]


def _summ(rows: list[dict[str, Any]], v: list[str], key: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    groups: dict[str, list[int]] = defaultdict(list)
    for i, r in enumerate(rows):
        groups[f"all {r['label']}"].append(i)
        groups[f"{r['label']}: {r[key]}"].append(i) if key else None
    for g, idx in sorted(groups.items()):
        out[g] = {
            "blocked": _rate(sum(v[i] == "malicious" for i in idx), len(idx)),
            "flagged": _rate(sum(v[i] != "benign" for i in idx), len(idx)),
        }
    return out


def _variants() -> dict[str, Any]:
    s = get_settings()
    out = {
        "corpus-lite": build_cascade(s.model_copy(update={"l2_lite_weights": "none", "window_words": 0})),
        "docs-lite": build_cascade(s.model_copy(update={"l2_lite_weights": "", "window_words": 64})),
    }
    bundle = s.repo_root / "models" / "l2-deberta-pooled"
    if (bundle / "model.onnx").exists():
        out["deberta"] = build_cascade(
            s.model_copy(update={"l2_mode": "onnx", "l2_onnx_dir": str(bundle), "window_words": 64})
        )
    return out


def to_markdown(res: dict[str, Any]) -> str:
    def pct(x: dict[str, Any]) -> str:
        return f"{100 * x['rate']:.1f}% [{100 * x['low']:.1f}, {100 * x['high']:.1f}] ({x['k']}/{x['n']})"

    lines = [
        "# Two new test sets, scored once",
        "",
        "Rebuilt from pinned third-party sources, commitments verified, detector never tuned on them. 95% Wilson intervals.",
        "See `data/toolout2/README.md` and `data/heldout/round3/README.md` for what each set is and is not.",
        "",
    ]
    for ds, title in (
        (
            "toolout2",
            "Tool-output set v2 (InjecAgent attacks, real npm documentation, self-written hard negatives)",
        ),
        ("round3", "Public round 3 (jayavibhav/prompt-injection test)"),
    ):
        lines += [f"## {title}", ""]
        for var, groups in res[ds].items():
            lines += [f"### {var}", "", "| group | blocked | blocked or flagged |", "|---|---|---|"]
            lines += [f"| {g} | {pct(x['blocked'])} | {pct(x['flagged'])} |" for g, x in groups.items()]
            lines += [""]
    return "\n".join(lines)


def run(out_json: Path, out_md: Path | None = None) -> dict[str, Any]:
    if os.environ.get(UNLOCK_ENV) != "1":
        raise LockedSplitError(f"set {UNLOCK_ENV}=1 for the one-shot run")
    if out_json.exists():
        raise FileExistsError(f"{out_json} exists: these sets are scored once")
    root = get_settings().repo_root
    sets = {"toolout2": (toolout2_rows(root), "technique"), "round3": (round3_rows(root), "")}
    res: dict[str, Any] = {ds: {} for ds in sets}
    for var, cascade in _variants().items():
        for ds, (rows, key) in sets.items():
            res[ds][var] = _summ(rows, _verdicts(cascade, rows), key)
    res["n"] = {ds: len(rows) for ds, (rows, _) in sets.items()}
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(res, indent=2))
    if out_md:
        out_md.write_text(to_markdown(res))
    return res
