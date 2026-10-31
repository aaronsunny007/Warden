"""Generate the LaTeX tables the report includes from docs/results/*.json.

Usage: python report/make_tables.py   (run from the repo root; stdlib only)
Tables whose source results do not exist are skipped, and main.tex includes them only if present.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "docs" / "results"
OUT = Path(__file__).resolve().parent / "tables"


def pct(m: dict) -> str:
    lo, hi = m["ci95"]
    return f"{m['hits']}/{m['n']} = {m['rate'] * 100:.1f}\\% [{lo * 100:.1f}, {hi * 100:.1f}]"


def locked() -> None:
    src = RES / "locked-test.json"
    if not src.exists():
        return
    d = json.loads(src.read_text())
    names = {
        "cascade_full": "Cascade (lite L2)",
        "l2_only": "Lite L2 alone",
        "cascade_full+deberta": "Cascade + DeBERTa L2",
        "l2_only+deberta": "DeBERTa L2 alone",
        "cascade_full+scratch": "Cascade + scratch L2",
        "l2_only+scratch": "Scratch L2 alone",
    }
    rows = [
        "\\begin{tabular}{lllll}\\toprule",
        "Variant & iid attacks blocked & iid benign blocked & iid benign flagged & OOD attacks blocked \\\\\\midrule",
    ]
    for key, label in names.items():
        if key not in d:
            continue
        iid, ood = d[key]["test_iid"], d[key]["test_ood"]
        rows.append(
            f"{label} & {pct(iid['attack_blocked'])} & {pct(iid['benign_blocked'])} & "
            f"{pct(iid['benign_flagged'])} & {pct(ood['attack_blocked'])} \\\\"
        )
    rows.append("\\bottomrule\\end{tabular}")
    (OUT / "locked.tex").write_text("\n".join(rows) + "\n")


def loop() -> None:
    gated = RES / "loop-gated" / "loop.json"
    if gated.exists():
        d = json.loads(gated.read_text())
        rows = [
            "\\begin{tabular}{rrrrrr}\\toprule",
            "Round & Attempts & Bypasses & ASR & Promoted & Gate rejections \\\\\\midrule",
        ]
        for r in d["rounds"]:
            rows.append(
                f"{r['round']} & {r['attempts']} & {r['bypasses']} & {r['asr'] * 100:.1f}\\% & "
                f"{r['promoted']} & {r['gate_failures']} \\\\"
            )
        rows.append("\\bottomrule\\end{tabular}")
        (OUT / "rq3.tex").write_text("\n".join(rows) + "\n")
    rq2 = RES / "rq2" / "rq2.json"
    if rq2.exists():
        s = json.loads(rq2.read_text())
        rows = [
            "\\begin{tabular}{lrr}\\toprule",
            "& Gated & Ungated \\\\\\midrule",
            f"Rules promoted & {s['promoted_gated']} & {s['promoted_ungated']} \\\\",
            f"Gate rejections & {s['gate_failures_gated']} & -- \\\\",
            f"Harmful promotions & {s['harmful_promotions_gated']} & {s['harmful_promotions_ungated']} \\\\",
            f"Benign utility lost (points) & {s['gated_utility_lost_points']} & {s['ungated_utility_lost_points']} \\\\",
            "\\bottomrule\\end{tabular}",
        ]
        (OUT / "rq2.tex").write_text("\n".join(rows) + "\n")


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    locked()
    loop()
