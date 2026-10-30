"""`warden` command line.

warden detector serve [--port 8000]
warden eval run --experiment rq1 --baselines B0,B1,B2,B3 [--agent simulated|ollama:qwen2.5:7b] [--templates a,b] [--seeds 1] [--sample N]
warden corpus verify-lock
warden audit consume --brokers localhost:9092
warden loop run ...        (see `warden loop --help`)
warden gate ...            (see `warden gate --help`)
warden control serve       control-plane API for the dashboard
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path


def _csv(v: str | None) -> list[str] | None:
    return [x.strip() for x in v.split(",") if x.strip()] if v else None


def cmd_detector(a: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run(
        "warden.detector.service:create_app", factory=True, host=a.host, port=a.port, log_level="info"
    )
    return 0


def cmd_eval(a: argparse.Namespace) -> int:
    from warden.eval.runner import run

    extra: dict[str, list[dict[str, object]]] = {}
    for spec in a.extra_rules or []:
        baseline, _, path = spec.partition("=")
        extra[baseline] = json.loads(Path(path).read_text())
    res = run(
        experiment=a.experiment,
        baselines=_csv(a.baselines) or ["B0", "B3"],
        agent_name=a.agent,
        templates=_csv(a.templates),
        seeds=a.seeds,
        sample=a.sample,
        include_mcp=not a.no_mcp,
        out_dir=Path(a.out) if a.out else None,
        extra_rules=extra,
        export_benign=Path(a.export_benign) if a.export_benign else None,
        ollama_url=a.ollama_url,
    )
    print(json.dumps({"out": res["out"], "hypotheses": res["hypotheses"]}, indent=2, default=str))
    if a.fail_on_hypothesis and any(h and not (h["asr_ok"] and h["utility_ok"]) for h in res["hypotheses"]):
        return 3
    return 0


def cmd_locked(a: argparse.Namespace) -> int:
    from warden.eval.locked import run

    onnx = dict(x.split("=", 1) for x in a.onnx or [])
    print(json.dumps(run(Path(a.out), onnx), indent=2))
    return 0


def cmd_agentdojo(a: argparse.Namespace) -> int:
    import asyncio

    from warden.eval.runner import run_agentdojo_experiment

    res = asyncio.run(
        run_agentdojo_experiment(
            a.suite,
            _csv(a.baselines) or ["B0", "B3"],
            agent_name=a.agent,
            max_user_tasks=a.max_user_tasks,
            max_injection_tasks=a.max_injection_tasks,
            seeds=a.seeds,
            out_dir=Path(a.out) if a.out else None,
            ollama_url=a.ollama_url,
        )
    )
    print(json.dumps({"out": res["out"], "hypotheses": res["hypotheses"]}, indent=2, default=str))
    return 0


def cmd_control(a: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run("warden.control.service:create_app", factory=True, host=a.host, port=a.port, log_level="info")
    return 0


def cmd_corpus(a: argparse.Namespace) -> int:
    from warden.corpus import verify_lock

    ok = verify_lock()
    print("locked test split matches its commitment" if ok else "LOCKED.sha256 does not match the test split")
    return 0 if ok else 1


def cmd_audit(a: argparse.Namespace) -> int:
    import asyncio

    from warden.audit import consume

    asyncio.run(consume(a.brokers, a.topic))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="warden")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("detector").add_subparsers(dest="sub", required=True).add_parser("serve")
    d.add_argument("--host", default="127.0.0.1")
    d.add_argument("--port", type=int, default=8000)
    d.set_defaults(fn=cmd_detector)

    eval_sub = sub.add_parser("eval").add_subparsers(dest="sub", required=True)
    e = eval_sub.add_parser("run", help="V2: the Acme Support lab")
    e.add_argument("--experiment", default="rq1")
    e.add_argument("--baselines", default="B0,B1,B2,B3")
    e.add_argument("--agent", default="simulated")
    e.add_argument("--templates")
    e.add_argument("--seeds", type=int, default=1)
    e.add_argument("--sample", type=int)
    e.add_argument("--no-mcp", action="store_true")
    e.add_argument("--out")
    e.add_argument(
        "--extra-rules", action="append", help="BASELINE=rules.json, e.g. B4=results/loop/promoted.json"
    )
    e.add_argument("--export-benign", help="write the benign message corpus (G2) to this JSONL path")
    e.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    e.add_argument(
        "--fail-on-hypothesis",
        action="store_true",
        help="exit 3 if B3/B4 miss the H1 targets (CI merge gate)",
    )
    e.set_defaults(fn=cmd_eval)

    lk = eval_sub.add_parser("locked", help="score the locked test splits once (needs WARDEN_UNLOCK_TEST=1)")
    lk.add_argument("--out", default="../docs/results/locked-test.json")
    lk.add_argument(
        "--onnx", action="append", help="TAG=dir of an extra ONNX L2 bundle to score alongside lite"
    )
    lk.set_defaults(fn=cmd_locked)

    ad = eval_sub.add_parser("agentdojo", help="V1: run an AgentDojo suite through each baseline")
    ad.add_argument("--suite", default="banking", choices=["workspace", "banking", "travel", "slack"])
    ad.add_argument("--baselines", default="B0,B3")
    ad.add_argument("--agent", default="simulated")
    ad.add_argument("--max-user-tasks", type=int)
    ad.add_argument("--max-injection-tasks", type=int)
    ad.add_argument("--seeds", type=int, default=1)
    ad.add_argument("--out")
    ad.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    ad.set_defaults(fn=cmd_agentdojo)

    ctl = sub.add_parser("control").add_subparsers(dest="sub", required=True).add_parser("serve")
    ctl.add_argument("--host", default="127.0.0.1")
    ctl.add_argument("--port", type=int, default=8008)
    ctl.set_defaults(fn=cmd_control)

    c = sub.add_parser("corpus").add_subparsers(dest="sub", required=True).add_parser("verify-lock")
    c.set_defaults(fn=cmd_corpus)

    au = sub.add_parser("audit").add_subparsers(dest="sub", required=True).add_parser("consume")
    au.add_argument("--brokers", default="localhost:9092")
    au.add_argument("--topic", default="warden.verdicts")
    au.set_defaults(fn=cmd_audit)

    try:
        from warden.loop.cli import register as register_loop

        register_loop(sub)
    except ImportError:
        pass
    return p


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    args = build_parser().parse_args(argv)
    rc: int = args.fn(args)
    return rc


if __name__ == "__main__":
    sys.exit(main())
