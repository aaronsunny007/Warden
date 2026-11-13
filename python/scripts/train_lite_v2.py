"""Fit the lite L2 on the project corpus (dev split) plus the v2 TRAIN split, and save the weights.

    python scripts/train_lite_v2.py [--out ../models/lite-l2-docs.npz]

The v2 train split is built by data/toolout2/build_toolout2.py from third-party text (InjecAgent attacker instructions
and the README text of npm packages). It is not committed; only the fitted weights are. Packages and attacker
instructions are assigned to train/dev/test by hash, so dev and test never share a package or an instruction with
the data this script reads. It never reads the locked test splits.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from warden.corpus import load
from warden.detector.classifier import LiteClassifier

ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    out = (
        Path(sys.argv[sys.argv.index("--out") + 1])
        if "--out" in sys.argv
        else ROOT / "models" / "lite-l2-docs.npz"
    )
    dev = load(["dev"])
    xs = [e.text for e in dev]
    ys = [1 if e.label == "attack" else 0 for e in dev]
    extra = [
        json.loads(x)
        for x in (ROOT / "data/toolout2/train.jsonl").read_text(encoding="utf-8").splitlines()
        if x.strip()
    ]
    xs += [r["text"] for r in extra]
    ys += [1 if r["label"] == "attack" else 0 for r in extra]
    if (
        "--pool" in sys.argv or "--pool-no-r3" in sys.argv
    ):  # add the public pool and the round-3 training source (never any test split)
        sys.path.insert(0, str(ROOT / "training"))
        from public_pool import load_pool

        pool = load_pool(ROOT / "data" / "heldout" / ".pool-cache")
        xs += pool["train"][0] + pool["val"][0]
        ys += pool["train"][1] + pool["val"][1]
        r3 = (
            []
            if "--pool-no-r3" in sys.argv
            else [
                json.loads(x)
                for x in (ROOT / "data/heldout/round3/train_xtram1.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
                if x.strip()
            ]
        )
        xs += [r["text"] for r in r3]
        ys += [r["label"] for r in r3]
    print(f"{len(dev)} corpus + {len(extra)} train = {len(xs)} examples ({sum(ys)} attacks)")
    clf = LiteClassifier(dim=8192, epochs=2000, lr=2.0, l2=1e-4, dtype="float32").fit(xs, ys)
    out.parent.mkdir(parents=True, exist_ok=True)
    clf.save(out)
    print("saved", out)


if __name__ == "__main__":
    main()
