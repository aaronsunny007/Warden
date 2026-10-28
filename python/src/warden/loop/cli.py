"""`warden loop` and `warden gate` subcommands, registered by the top-level CLI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _run_loop(a: argparse.Namespace) -> int:
    from warden.loop.orchestrator import run_loop_experiment

    res = run_loop_experiment(
        gated=not a.ungated,
        rounds=a.rounds,
        attempts=a.attempts,
        seed=a.seed,
        out_dir=Path(a.out) if a.out else None,
    )
    last = res["rounds"][-1] if res["rounds"] else {}
    print(
        json.dumps(
            {
                "out": res["out"],
                "gated": res["gated"],
                "promoted": res["meta"].get("promoted"),
                "final_round": last,
            },
            indent=2,
            default=str,
        )
    )
    return 0


def _run_rq2(a: argparse.Namespace) -> int:
    """Induced self-DoS: run the loop gated and ungated and compare benign utility lost."""
    from warden.loop.orchestrator import run_loop_experiment

    out = Path(a.out) if a.out else None
    gated = run_loop_experiment(True, a.rounds, a.attempts, a.seed, out / "gated" if out else None, start_rules=a.start_rules, blend_rate=a.blend_rate)
    ungated = run_loop_experiment(False, a.rounds, a.attempts, a.seed, out / "ungated" if out else None, start_rules=a.start_rules, blend_rate=a.blend_rate)

    def lost(res: dict[str, Any]) -> float:
        base = res["meta"]["baseline_utility"]
        base_rate = base[0] / base[1] if base[1] else 0.0
        final = res["rounds"][-1]["benign_utility"] if res["rounds"] else base
        final_rate = final[0] / final[1] if final[1] else 0.0
        return round((base_rate - final_rate) * 100, 2)

    gated_lost, ungated_lost = lost(gated), lost(ungated)
    factor = (ungated_lost / gated_lost) if gated_lost > 0 else (float("inf") if ungated_lost > 0 else 1.0)
    summary = {
        "gated_utility_lost_points": gated_lost,
        "ungated_utility_lost_points": ungated_lost,
        "ratio_ungated_to_gated": factor,
        "harmful_promotions_gated": sum(r["harmful_promotions"] for r in gated["rounds"]),
        "harmful_promotions_ungated": sum(r["harmful_promotions"] for r in ungated["rounds"]),
        "H2_gate_cuts_harm_10x": factor >= 10 or (ungated_lost > 0 and gated_lost == 0),
    }
    if out:
        (out / "rq2.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2, default=str))
    return 0


def register(sub: Any) -> None:
    loop = sub.add_parser("loop", help="the self-improving defence loop").add_subparsers(
        dest="sub", required=True
    )
    r = loop.add_parser("run", help="run the loop for N rounds against a live gateway")
    r.add_argument("--rounds", type=int, default=5)
    r.add_argument("--attempts", type=int, default=30)
    r.add_argument(
        "--ungated", action="store_true", help="promote every proposal with no gate (RQ2 adversary)"
    )
    r.add_argument("--seed", type=int, default=0)
    r.add_argument("--out")
    r.add_argument("--start-rules", default="minimal", choices=["minimal", "baseline"])
    r.add_argument("--blend-rate", type=float, default=0.0, help="RQ2: fraction of attacks that blend in benign phrasing")
    r.set_defaults(fn=_run_loop)

    rq2 = loop.add_parser("rq2", help="induced self-DoS: gated vs ungated")
    rq2.add_argument("--rounds", type=int, default=4)
    rq2.add_argument("--attempts", type=int, default=30)
    rq2.add_argument("--seed", type=int, default=0)
    rq2.add_argument("--out")
    rq2.add_argument("--start-rules", default="minimal", choices=["minimal", "baseline"])
    rq2.add_argument("--blend-rate", type=float, default=0.5, help="fraction of attacks that blend in benign phrasing")
    rq2.set_defaults(fn=_run_rq2)
