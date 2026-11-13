"""Cross-dataset DEV check: score a weights file on a held-out slice of the xTRam1 training file.

Used to ask "does adding the public pool help on a dataset the model did not train on?" without touching any test split.
    WARDEN_L2_LITE_WEIGHTS=w.npz python scripts/eval_public_dev.py [n]
"""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path

from warden.detector.guard import check_text
from warden.detector.service import build_cascade
from warden.settings import get_settings

R3 = Path(__file__).resolve().parents[2] / "data/heldout/round3/train_xtram1.jsonl"


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 800
    rows = [json.loads(x) for x in R3.read_text(encoding="utf-8").splitlines() if x.strip()]
    random.Random(7).shuffle(rows)
    a = [r for r in rows if r["label"] == 1][: n // 2]
    b = [r for r in rows if r["label"] == 0][: n // 2]
    cascade = build_cascade(get_settings())
    for name, rs in (("attack", a), ("benign", b)):
        vs = [check_text(cascade, r["text"]).verdict for r in rs]
        print(
            f"{name}: n={len(vs)} blocked {100 * sum(v == 'malicious' for v in vs) / len(vs):.1f}%  flagged {100 * sum(v != 'benign' for v in vs) / len(vs):.1f}%"
        )


if __name__ == "__main__":
    main()
