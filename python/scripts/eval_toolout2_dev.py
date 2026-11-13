"""Score the v2 DEV split (never the test split). This is the loop detector changes are developed against.

    python scripts/eval_toolout2_dev.py [--json out.json]

Reports, per technique, how often the full pipeline (hidden scan, then cascade) blocks, flags or passes.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

from warden.detector.guard import check_text
from warden.detector.service import build_cascade
from warden.settings import get_settings

DEV = Path(__file__).resolve().parents[2] / "data" / "toolout2" / "dev.jsonl"


def main() -> None:
    rows = [json.loads(x) for x in DEV.read_text(encoding="utf-8").splitlines() if x.strip()]
    cascade = build_cascade(get_settings())
    by: dict[str, dict[str, int]] = defaultdict(lambda: {"n": 0, "blocked": 0, "flagged": 0})
    for r in rows:
        v = check_text(cascade, r["text"]).verdict
        for key in (f"{r['label']}:{r['technique']}", f"{r['label']}:ALL"):
            by[key]["n"] += 1
            by[key]["blocked"] += v == "malicious"
            by[key]["flagged"] += v != "benign"
    for k in sorted(by):
        d = by[k]
        print(
            f"{k:38s} n={d['n']:4d}  blocked {100 * d['blocked'] / d['n']:5.1f}%  flagged {100 * d['flagged'] / d['n']:5.1f}%"
        )
    if "--json" in sys.argv:
        Path(sys.argv[sys.argv.index("--json") + 1]).write_text(json.dumps(by, indent=1))


if __name__ == "__main__":
    main()
