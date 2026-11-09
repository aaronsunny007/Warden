"""Score the tool-output injection set (data/toolout) once.

The set is synthetic and written by this project, so it measures how the detector handles *these* templates
(poisoned emails, web pages, PDFs, tickets, JSON records and more), not how it fares in the wild. Protocol:
the id commitment in data/toolout/LOCKED.sha256 is verified, the unlock env var is required, and the output is
write-once. Each configuration is scored on the same items and nothing is tuned against the result.

Two views are reported: the cascade on the raw text, and the full pipeline (hidden-content scan first, so
HTML-hidden and invisible-character payloads are decoded before the cascade reads them).
"""

from __future__ import annotations

import hashlib
import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Any

from warden.corpus import LockedSplitError
from warden.detector import hidden
from warden.detector.cascade import Cascade
from warden.detector.guard import check_report
from warden.detector.service import build_cascade
from warden.settings import get_settings
from warden.stats import wilson

UNLOCK_ENV = "WARDEN_UNLOCK_TOOLOUT"


def _dir() -> Path:
    return get_settings().data_dir / "toolout"


def load() -> list[dict[str, Any]]:
    return [
        json.loads(x)
        for x in (_dir() / "toolout.jsonl").read_text(encoding="utf-8").splitlines()
        if x.strip()
    ]


def verify_lock() -> bool:
    d = _dir()
    lock = dict(
        (p[1], p[0])
        for p in (ln.split() for ln in (d / "LOCKED.sha256").read_text().splitlines())
        if len(p) == 2
    )
    ids = hashlib.sha256("\n".join(sorted(str(r["id"]) for r in load())).encode()).hexdigest()
    return (
        lock.get("ids") == ids
        and lock.get("toolout.jsonl") == hashlib.sha256((d / "toolout.jsonl").read_bytes()).hexdigest()
    )


def _rate(k: int, n: int) -> dict[str, Any]:
    r = wilson(k, n)
    return {
        "k": k,
        "n": n,
        "rate": None if not n else round(r.value, 4),
        "low": round(r.low, 4),
        "high": round(r.high, 4),
    }


def verdicts(cascade: Cascade, rows: list[dict[str, Any]], pipeline: bool) -> dict[str, str]:
    out: dict[str, str] = {}
    for r in rows:
        if pipeline:
            rep = hidden.scan_html(r["text"]) if r["format"] == "html" else hidden.scan_text(r["text"])
            if r["format"] != "html":
                rep.visible_text = r["text"]
            out[r["id"]] = check_report(cascade, rep).verdict
        else:
            out[r["id"]] = cascade.detect(r["text"], "output").verdict
    return out


def summarise(rows: list[dict[str, Any]], v: dict[str, str]) -> dict[str, Any]:
    atk = [r for r in rows if r["label"] == "attack"]
    ben = [r for r in rows if r["label"] == "benign"]
    res: dict[str, Any] = {
        "attack_blocked": _rate(sum(v[r["id"]] == "malicious" for r in atk), len(atk)),
        "attack_flagged": _rate(sum(v[r["id"]] != "benign" for r in atk), len(atk)),
        "benign_blocked": _rate(sum(v[r["id"]] == "malicious" for r in ben), len(ben)),
        "benign_flagged": _rate(sum(v[r["id"]] != "benign" for r in ben), len(ben)),
    }
    for key, field_name in (("by_technique", "technique"), ("by_carrier", "carrier")):
        g: dict[str, list[Any]] = defaultdict(list)
        for r in atk:
            g[r[field_name]].append(r)
        res[key] = {
            k: {
                "blocked": _rate(sum(v[x["id"]] == "malicious" for x in xs), len(xs)),
                "flagged": _rate(sum(v[x["id"]] != "benign" for x in xs), len(xs)),
            }
            for k, xs in sorted(g.items())
        }
    hn: dict[str, list[Any]] = defaultdict(list)
    for r in ben:
        hn[r["hard_negative"] or "ordinary"].append(r)
    res["benign_by_kind"] = {
        k: {
            "blocked": _rate(sum(v[x["id"]] == "malicious" for x in xs), len(xs)),
            "flagged": _rate(sum(v[x["id"]] != "benign" for x in xs), len(xs)),
        }
        for k, xs in sorted(hn.items())
    }
    res["misses"] = [r["id"] for r in atk if v[r["id"]] == "benign"]
    return res


def to_markdown(res: dict[str, Any]) -> str:
    def pct(x: dict[str, Any]) -> str:
        return (
            "n/a"
            if x["rate"] is None
            else f"{100 * x['rate']:.1f}% [{100 * x['low']:.1f}, {100 * x['high']:.1f}] ({x['k']}/{x['n']})"
        )

    lines = [
        "# Tool-output injection set: scores",
        "",
        "Synthetic set written by this project (see `data/toolout/README.md`). Scored once. 95% Wilson intervals.",
        "",
    ]
    for name, title in (
        ("raw_cascade", "Cascade on the raw text"),
        ("full_pipeline", "Full pipeline (hidden-content scan, then cascade)"),
    ):
        r = res[name]
        lines += [f"## {title}", "", "| measure | value |", "|---|---|"]
        for k, label in (
            ("attack_blocked", "attacks blocked"),
            ("attack_flagged", "attacks blocked or flagged"),
            ("benign_blocked", "benign wrongly blocked"),
            ("benign_flagged", "benign wrongly blocked or flagged"),
        ):
            lines.append(f"| {label} | {pct(r[k])} |")
        lines += [
            "",
            "Attacks blocked or flagged, by technique:",
            "",
            "| technique | flagged | blocked |",
            "|---|---|---|",
        ]
        lines += [
            f"| {t} | {pct(x['flagged'])} | {pct(x['blocked'])} |" for t, x in r["by_technique"].items()
        ]
        lines += [
            "",
            "Benign wrongly blocked or flagged, by kind:",
            "",
            "| kind | flagged | blocked |",
            "|---|---|---|",
        ]
        lines += [
            f"| {t} | {pct(x['flagged'])} | {pct(x['blocked'])} |" for t, x in r["benign_by_kind"].items()
        ]
        lines += [""]
    return "\n".join(lines)


def run(out_json: Path, out_md: Path | None = None) -> dict[str, Any]:
    if os.environ.get(UNLOCK_ENV) != "1":
        raise LockedSplitError(f"set {UNLOCK_ENV}=1 for the one-shot tool-output run")
    if out_json.exists():
        raise FileExistsError(f"{out_json} exists: the tool-output set is scored once")
    if not verify_lock():
        raise LockedSplitError("data/toolout/LOCKED.sha256 does not match toolout.jsonl")
    s = get_settings()
    rows = load()
    cascade = build_cascade(s)
    res: dict[str, Any] = {
        "n": len(rows),
        "embedder": s.embed_model or "hashing (offline)",
        "l2_mode": s.l2_mode,
        "judge": bool(s.judge_model),
        "raw_cascade": summarise(rows, verdicts(cascade, rows, pipeline=False)),
        "full_pipeline": summarise(rows, verdicts(cascade, rows, pipeline=True)),
    }
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(res, indent=2))
    if out_md:
        out_md.write_text(to_markdown(res))
    return res
