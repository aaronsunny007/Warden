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
    gated = run_loop_experiment(
        True,
        a.rounds,
        a.attempts,
        a.seed,
        out / "gated" if out else None,
        start_rules=a.start_rules,
        blend_rate=a.blend_rate,
    )
    ungated = run_loop_experiment(
        False,
        a.rounds,
        a.attempts,
        a.seed,
        out / "ungated" if out else None,
        start_rules=a.start_rules,
        blend_rate=a.blend_rate,
    )

    def lost(res: dict[str, Any]) -> float:
        base = res["meta"]["baseline_utility"]
        base_rate = base[0] / base[1] if base[1] else 0.0
        final = res["rounds"][-1]["benign_utility"] if res["rounds"] else base
        final_rate = final[0] / final[1] if final[1] else 0.0
        return round((base_rate - final_rate) * 100, 2)

    gated_lost, ungated_lost = lost(gated), lost(ungated)
    factor = (ungated_lost / gated_lost) if gated_lost > 0 else (float("inf") if ungated_lost > 0 else 1.0)
    g_harm = sum(r["harmful_promotions"] for r in gated["rounds"])
    u_harm = sum(r["harmful_promotions"] for r in ungated["rounds"])
    summary = {
        "gated_utility_lost_points": gated_lost,
        "ungated_utility_lost_points": ungated_lost,
        "ratio_ungated_to_gated": factor,
        "harmful_promotions_gated": g_harm,
        "harmful_promotions_ungated": u_harm,
        "gate_failures_gated": sum(r["gate_failures"] for r in gated["rounds"]),
        "promoted_gated": gated["meta"].get("promoted"),
        "promoted_ungated": ungated["meta"].get("promoted"),
        "H2_gate_cuts_harm_10x": factor >= 10 or (u_harm > 0 and g_harm == 0),
        "note": (
            "Results use the simulated victim agent (a pipeline stand-in, not a real LLM). "
            "H2's mechanism — the gate rejecting a candidate that would fire on benign traffic — is "
            "shown directly by gate_failures here and unit-tested in test_gate_blocks_benign_overblocker_at_g2; "
            "the magnitude of induced self-DoS depends on the attacker model and needs the real-LLM victim."
        ),
    }
    if out:
        (out / "rq2.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2, default=str))
    return 0


def _miss_add(a: argparse.Namespace) -> int:
    from warden.loop.misses import MissLog

    text = Path(a.file).read_text(encoding="utf-8") if a.file else a.text
    m = MissLog(a.log).add(text, channel=a.channel, source=a.source, goal=a.goal, note=a.note)
    print(json.dumps({"logged": m is not None, "id": m.id if m else None}))
    return 0


def _miss_import(a: argparse.Namespace) -> int:
    """Log the attacks a scored set let through (as listed in its results file)."""
    from warden.eval import toolout
    from warden.loop.misses import MissLog

    results = json.loads(Path(a.results).read_text())
    ids = set(results[a.view]["misses"])
    log, n = MissLog(a.log), 0
    for r in toolout.load():
        if r["id"] in ids and log.add(
            r["text"], source="eval:toolout", goal=r["goal"], note=f"{r['carrier']}/{r['technique']}"
        ):
            n += 1
    print(json.dumps({"imported": n, "of": len(ids)}))
    return 0


def _learn(a: argparse.Namespace) -> int:
    from warden.loop import misses

    outcomes = misses.learn(misses.MissLog(a.log).all())
    misses.write_report(outcomes, Path(a.out))
    print(misses.to_markdown(outcomes))
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
    r.add_argument(
        "--blend-rate", type=float, default=0.0, help="RQ2: fraction of attacks that blend in benign phrasing"
    )
    r.set_defaults(fn=_run_loop)

    ms = loop.add_parser("miss", help="the miss log").add_subparsers(dest="miss_sub", required=True)
    ma = ms.add_parser("add", help="log an attack that was let through")
    ma.add_argument("--log", default="miss-log.jsonl")
    ma.add_argument("--text", default="")
    ma.add_argument("--file")
    ma.add_argument("--channel", default="output", choices=["description", "arguments", "output"])
    ma.add_argument("--source", default="report")
    ma.add_argument("--goal", default="unspecified")
    ma.add_argument("--note", default="")
    ma.set_defaults(fn=_miss_add)
    mi = ms.add_parser("import-toolout", help="log the attacks a toolout results file says were passed")
    mi.add_argument("--log", default="miss-log.jsonl")
    mi.add_argument("--results", default="docs/results/toolout.json")
    mi.add_argument("--view", default="full_pipeline", choices=["raw_cascade", "full_pipeline"])
    mi.set_defaults(fn=_miss_import)
    ln = loop.add_parser(
        "learn", help="propose rules for logged misses and run them through the offline gate"
    )
    ln.add_argument("--log", default="miss-log.jsonl")
    ln.add_argument("--out", default="learned")
    ln.set_defaults(fn=_learn)

    rq2 = loop.add_parser("rq2", help="induced self-DoS: gated vs ungated")
    rq2.add_argument("--rounds", type=int, default=4)
    rq2.add_argument("--attempts", type=int, default=30)
    rq2.add_argument("--seed", type=int, default=0)
    rq2.add_argument("--out")
    rq2.add_argument("--start-rules", default="minimal", choices=["minimal", "baseline"])
    rq2.add_argument(
        "--blend-rate", type=float, default=0.5, help="fraction of attacks that blend in benign phrasing"
    )
    rq2.set_defaults(fn=_run_rq2)
