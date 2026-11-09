"""The round-2 public training pool (see data/heldout/fresh/README.md for the protocol).

Downloads the pinned training/validation files, deduplicates them against each other, the project corpus and
every test split (spent or fresh), and returns plain lists. Nothing here ever touches a test file's labels for
training: test texts are only used to *exclude* overlapping training rows.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "build_fresh_splits", ROOT / "data" / "heldout" / "build_fresh_splits.py"
)
assert _SPEC and _SPEC.loader
_B = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_B)


def _cached(key: str, cache: Path | None) -> bytes:
    if cache is not None:
        f = cache / key
        if f.exists():
            return f.read_bytes()
    raw = _B.fetch(key)
    if cache is not None:
        cache.mkdir(parents=True, exist_ok=True)
        (cache / key).write_bytes(raw)
    return raw


def load_pool(cache: Path | None = None) -> dict[str, tuple[list[str], list[int]]]:
    """{'train': (texts, labels), 'val': (texts, labels)}; label 1 = injection/jailbreak, 0 = benign."""
    rows = {k: _B.texts_labels(k, _cached(k, cache)) for k in ("ds_train", "nc_train", "nc_validation")}
    blocked = {
        _B.norm(t)
        for k in ("ds_test", "nc_test", "jb_test")
        for t, _ in _B.texts_labels(k, _cached(k, cache))
    }
    for f in ("attacks", "benign"):
        for line in (ROOT / "data" / "corpus" / f"{f}.jsonl").read_text(encoding="utf-8").splitlines():
            if line.strip():
                blocked.add(_B.norm(json.loads(line)["text"]))
    out: dict[str, tuple[list[str], list[int]]] = {}
    seen: set[str] = set()
    for name, keys in (
        ("val", ("nc_validation",)),
        ("train", ("ds_train", "nc_train")),
    ):  # val claims overlaps first
        texts: list[str] = []
        labels: list[int] = []
        for k in keys:
            for t, y in rows[k]:
                n = _B.norm(t)
                if n in blocked or n in seen:
                    continue
                seen.add(n)
                texts.append(t)
                labels.append(y)
        out[name] = (texts, labels)
    return out
