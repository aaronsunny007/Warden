"""The demo replays recorded detector results; they must not drift from the detector or from the page."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _script():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(
        "build_demo_data", ROOT / "python" / "scripts" / "build_demo_data.py"
    )
    assert spec and spec.loader
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_committed_demo_data_matches_a_fresh_run() -> None:
    fresh = _script().build()
    saved = json.loads((ROOT / "site" / "demo" / "data.json").read_text(encoding="utf-8"))
    key = lambda a: (a["carrier"], a["technique"], a["goal"], a["verdict"])  # noqa: E731
    assert [key(a) for a in fresh["attacks"]] == [key(a) for a in saved["attacks"]]
    assert [b["verdict"] for b in fresh["benign"]] == [b["verdict"] for b in saved["benign"]]


def test_demo_data_is_complete_and_the_page_says_it_is_recorded() -> None:
    d = json.loads((ROOT / "site" / "demo" / "data.json").read_text(encoding="utf-8"))
    assert d["meta"]["n_attacks"] == len(d["attacks"]) == 822
    assert {a["verdict"] for a in d["attacks"]} <= {"benign", "uncertain", "malicious"}
    assert any(b["verdict"] != "benign" for b in d["benign"])  # false alarms are shown, not hidden
    page = (ROOT / "site" / "demo" / "index.html").read_text(encoding="utf-8")
    assert "recorded" in page and "simulated" in page and "not a security guarantee" in page
