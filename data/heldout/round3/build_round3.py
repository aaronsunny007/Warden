"""Round 3: a new public test set the detector has never seen, plus one more public training source.

    python data/heldout/round3/build_round3.py

  test   jayavibhav/prompt-injection, official TEST file only. Rows whose normalised text appears in ANY training
         source (corpus, tool-output train split, deepset/neuralchemy/jackhhao train, xTRam1 train) or in a spent test
         split are dropped; then 500 attacks and 500 benign are drawn with a fixed seed.
  train  xTRam1/safe-guard-prompt-injection, official TRAIN file only (its test file is not used anywhere).

The dataset licences are not stated upstream, so the texts are not committed: the repo holds this builder, the pinned
source hashes and the id list. The scorer rebuilds the test file and refuses to run if the ids differ.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import random
import re
import sys
from io import BytesIO
from pathlib import Path

import httpx
import pandas as pd

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SEED = 20261113
XT = ("xTRam1/safe-guard-prompt-injection", "a3a877d608f37b7d20d9945671902df895ecdb46", "data/train-00000-of-00001.parquet")
JV = ("jayavibhav/prompt-injection", "a5bd9869c16d22ffebda9fa91a13a759b8669bb6", "data/test-00000-of-00001.parquet")
PINS = HERE / "SOURCES.sha256"

_spec = importlib.util.spec_from_file_location("bfs", ROOT / "data" / "heldout" / "build_fresh_splits.py")
assert _spec and _spec.loader
bfs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bfs)


def norm(t: str) -> str:
    return re.sub(r"\s+", " ", str(t)).strip().lower()


def get(src: tuple[str, str, str]) -> list[tuple[str, int]]:
    cache = HERE / ".cache"
    cache.mkdir(exist_ok=True)
    f = cache / (src[0].replace("/", "_") + "_" + Path(src[2]).name)
    if not f.exists():
        url = f"https://huggingface.co/datasets/{src[0]}/resolve/{src[1]}/{src[2]}"
        f.write_bytes(httpx.get(url, timeout=600, follow_redirects=True).raise_for_status().content)
    raw = f.read_bytes()
    h = hashlib.sha256(raw).hexdigest()
    pins = dict(ln.split()[::-1] for ln in PINS.read_text().splitlines() if ln.strip()) if PINS.exists() else {}
    if f.name in pins and pins[f.name] != h:
        raise SystemExit(f"{f.name}: source changed ({h} != {pins[f.name]})")
    if f.name not in pins:
        with PINS.open("a") as fh:
            fh.write(f"{h}  {f.name}\n")
    df = pd.read_parquet(BytesIO(raw))
    return [(str(t), int(y)) for t, y in zip(df["text"], df["label"], strict=True)]


def main() -> int:
    xt, jv = get(XT), get(JV)
    blocked: set[str] = set()
    for k in ("nc_train", "nc_validation", "jb_train", "ds_train", "ds_test", "nc_test", "jb_test"):
        blocked |= {norm(t) for t, _ in bfs.texts_labels(k, bfs.fetch(k))}
    for f in ("attacks", "benign"):
        for line in (ROOT / "data" / "corpus" / f"{f}.jsonl").read_text(encoding="utf-8").splitlines():
            if line.strip():
                blocked.add(norm(json.loads(line)["text"]))
    t2 = ROOT / "data" / "toolout2" / "train.jsonl"
    if t2.exists():
        blocked |= {norm(json.loads(x)["text"]) for x in t2.read_text(encoding="utf-8").splitlines() if x.strip()}
    train, seen = [], set()
    jv_norms = {norm(t) for t, _ in jv}
    for t, y in xt:
        n = norm(t)
        if n in blocked or n in seen or n in jv_norms:  # a train row that is also in the test file is dropped
            continue
        seen.add(n)
        train.append({"text": t, "label": y})
    train_norms = seen | blocked
    pool, seen2, dropped = {0: [], 1: []}, set(), 0
    for t, y in jv:
        n = norm(t)
        if n in train_norms or n in seen2:
            dropped += 1
            continue
        seen2.add(n)
        pool[y].append(t)
    rng = random.Random(SEED)
    test = []
    for y, name in ((1, "attack"), (0, "benign")):
        ts = sorted(pool[y], key=lambda s: hashlib.sha256(s.encode()).hexdigest())
        for t in rng.sample(ts, 500):
            test.append({"id": "r3-" + hashlib.sha256(t.encode()).hexdigest()[:12], "text": t, "label": name})
    test.sort(key=lambda r: r["id"])
    (HERE / "test.jsonl").write_text("".join(json.dumps(r) + "\n" for r in test), encoding="utf-8")
    (HERE / "train_xtram1.jsonl").write_text("".join(json.dumps(r) + "\n" for r in train), encoding="utf-8")
    ids = "".join(f"{r['id']} {r['label']}\n" for r in test)
    (HERE / "ids.txt").write_text(ids)
    (HERE / "LOCKED.sha256").write_text(f"{hashlib.sha256(ids.encode()).hexdigest()}  ids.txt\n")
    print(f"train {len(train)} ({sum(r['label'] for r in train)} attacks); test pool dropped {dropped}; test {len(test)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
