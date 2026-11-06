"""Rebuild data/heldout/public_deepset_test.jsonl and LOCKED.sha256 from the public source.

    uv run --no-project --with pandas --with pyarrow python data/heldout/build_public_split.py

Deterministic: the source revision and parquet SHA-256 are pinned, rows are sorted by id, and
nothing is sampled. It only ever reads the dataset's official *test* file.
"""

from __future__ import annotations

import hashlib
import json
import sys
import urllib.request
from io import BytesIO
from pathlib import Path

import pandas as pd

REVISION = "4f61ecb038e9c3fb77e21034b22511b523772cdd"
PARQUET_SHA256 = "39ac797cabc157eeed58435a08593b2952bb6cb16fc394a2d383f447cc7b246e"
HERE = Path(__file__).parent


def main() -> int:
    # A literal https URL (pinned revision and file): nothing dynamic reaches urllib.
    raw = urllib.request.urlopen(
        "https://huggingface.co/datasets/deepset/prompt-injections/resolve/"
        "4f61ecb038e9c3fb77e21034b22511b523772cdd/data/test-00000-of-00001-701d16158af87368.parquet",
        timeout=60,
    ).read()
    got = hashlib.sha256(raw).hexdigest()
    if got != PARQUET_SHA256:
        print(f"source changed: sha256 {got} != pinned {PARQUET_SHA256}", file=sys.stderr)
        return 1
    df = pd.read_parquet(BytesIO(raw))
    rows = []
    for text, label in zip(df["text"], df["label"], strict=True):
        rows.append(
            {
                "id": "pub-" + hashlib.sha256(text.encode()).hexdigest()[:12],
                "text": text,
                "label": "attack" if int(label) == 1 else "benign",
                "family": "public_prompt_injection",
                "channel": "output",  # fixed before scoring: the corpus default and its dominant channel
                "goal": "",
                "source": f"deepset/prompt-injections@{REVISION[:7]} test (Apache-2.0)",
                "split": "public_heldout",
            }
        )
    rows.sort(key=lambda r: r["id"])
    assert len({r["id"] for r in rows}) == len(rows), "id collision"
    (HERE / "public_deepset_test.jsonl").write_text(
        "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in rows), encoding="utf-8"
    )
    digest = hashlib.sha256("\n".join(sorted(r["id"] for r in rows)).encode()).hexdigest()
    (HERE / "LOCKED.sha256").write_text(
        f"{digest}  public held-out ids (deepset/prompt-injections test), committed before scoring\n"
    )
    n_atk = sum(r["label"] == "attack" for r in rows)
    print(f"{len(rows)} rows ({n_atk} attack, {len(rows) - n_atk} benign); commitment {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
