"""Rebuild the two fresh locked test splits in data/heldout/fresh/ from their public sources.

    uv run --no-project --with httpx --with pandas --with pyarrow python data/heldout/build_fresh_splits.py

Deterministic: every source file is pinned by revision and SHA-256, rows are deduplicated and sorted by id,
nothing is sampled. Only the datasets' official *test* files become test splits. A test row whose normalised
text also appears in any training source (or in the spent deepset test split) is dropped, and the counts are
printed, so the splits cannot leak by construction.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from io import BytesIO
from pathlib import Path

import httpx
import pandas as pd

HERE = Path(__file__).parent
OUT = HERE / "fresh"
NC = "neuralchemy/Prompt-injection-dataset"
NC_REV = "7d70432dfcf47a821612cbf9d34e9d9e3ad20e75"
JB = "jackhhao/jailbreak-classification"
JB_REV = "2f2ceeb39658696fd3f462403562b6eea5306287"
DS = "deepset/prompt-injections"
DS_REV = "4f61ecb038e9c3fb77e21034b22511b523772cdd"

# (url path under the dataset, sha256). The hash makes the build fail loudly if upstream changes.
SOURCES = {
    "nc_train": (
        NC,
        NC_REV,
        "core/train-00000-of-00001.parquet",
        "c0724f8e00eebb65c001be9ba94291d1608e5da0374012e53dfd4077c5f92558",
    ),
    "nc_validation": (
        NC,
        NC_REV,
        "core/validation-00000-of-00001.parquet",
        "bbd417bfd0df1553dd769e814a0b62ca58ad5b1d08d153c90f66937a4af74deb",
    ),
    "nc_test": (
        NC,
        NC_REV,
        "core/test-00000-of-00001.parquet",
        "fb5432035fdd8453d61f6593bfe78ee2970403c5ea59959b642a6708e2bef670",
    ),
    "jb_train": (
        JB,
        JB_REV,
        "default/jailbreak_dataset_train.csv",
        "a5cb24b0865ef37a248d6d82bd21026ce39c89f11abae5d26d4ae58aad3ffe40",
    ),
    "jb_test": (
        JB,
        JB_REV,
        "default/jailbreak_dataset_test.csv",
        "a546ce540973d8f5ef87ce3be4bd21ee5923154b9dda86eba5a12c7fa00829da",
    ),
    "ds_train": (
        DS,
        DS_REV,
        "data/train-00000-of-00001-9564e8b05b4757ab.parquet",
        "2e10bc7ab30f542c97e4e83e2a5683000b5057d25ec10908784c631d44124c04",
    ),
    "ds_test": (
        DS,
        DS_REV,
        "data/test-00000-of-00001-701d16158af87368.parquet",
        "39ac797cabc157eeed58435a08593b2952bb6cb16fc394a2d383f447cc7b246e",
    ),
}


def norm(t: str) -> str:
    return re.sub(r"\s+", " ", str(t)).strip().lower()


def fetch(key: str) -> bytes:
    repo, rev, path, want = SOURCES[key]
    url = f"https://huggingface.co/datasets/{repo}/resolve/{rev}/{path}"
    raw = httpx.get(url, timeout=120, follow_redirects=True).raise_for_status().content
    got = hashlib.sha256(raw).hexdigest()
    if want and got != want:
        print(f"{key}: source changed: sha256 {got} != pinned {want}", file=sys.stderr)
        raise SystemExit(1)
    if not want:
        print(f"{key}: sha256 {got} (not pinned yet)")
    return raw


def texts_labels(key: str, raw: bytes) -> list[tuple[str, int]]:
    if key.startswith("jb_"):
        df = pd.read_csv(BytesIO(raw))
        return [(t, int(y == "jailbreak")) for t, y in zip(df["prompt"], df["type"], strict=True)]
    df = pd.read_parquet(BytesIO(raw))
    return [(t, int(y)) for t, y in zip(df["text"], df["label"], strict=True)]


def main() -> int:
    data = {k: texts_labels(k, fetch(k)) for k in SOURCES}
    seen_train = {norm(t) for k in ("nc_train", "nc_validation", "jb_train", "ds_train") for t, _ in data[k]}
    seen_train |= {
        norm(json.loads(line)["text"])
        for f in ("attacks", "benign")
        for line in (HERE.parent / "corpus" / f"{f}.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    spent = {norm(t) for t, _ in data["ds_test"]}
    OUT.mkdir(exist_ok=True)
    lines = []
    for key, tag, name in (("nc_test", "nc", "neuralchemy_test"), ("jb_test", "jb", "jackhhao_test")):
        repo, rev, _, _ = SOURCES[key]
        rows, seen, dropped = [], set(), {"dup": 0, "in_train": 0, "in_spent": 0}
        for text, label in data[key]:
            n = norm(text)
            if n in seen:
                dropped["dup"] += 1
            elif n in seen_train:
                dropped["in_train"] += 1
            elif n in spent:
                dropped["in_spent"] += 1
            else:
                seen.add(n)
                rows.append(
                    {
                        "id": f"fresh-{tag}-" + hashlib.sha256(text.encode()).hexdigest()[:12],
                        "text": text,
                        "label": "attack" if label == 1 else "benign",
                        "family": f"fresh_{tag}",
                        "channel": "output",  # same fixed channel as the first held-out split
                        "goal": "",
                        "source": f"{repo}@{rev[:7]} test (Apache-2.0)",
                        "split": f"fresh_{tag}",
                    }
                )
        rows.sort(key=lambda r: r["id"])
        assert len({r["id"] for r in rows}) == len(rows), "id collision"
        (OUT / f"{name}.jsonl").write_text(
            "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in rows), encoding="utf-8"
        )
        digest = hashlib.sha256("\n".join(r["id"] for r in rows).encode()).hexdigest()
        lines.append(
            f"{digest}  {name} ids ({repo} test), committed before any model was trained on the new data\n"
        )
        n_atk = sum(r["label"] == "attack" for r in rows)
        print(
            f"{name}: {len(rows)} rows ({n_atk} attack, {len(rows) - n_atk} benign); dropped {dropped}; {digest}"
        )
    (OUT / "LOCKED.sha256").write_text("".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
