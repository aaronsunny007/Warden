"""The scoreboard page is generated from committed results and re-checks the locked-set commitments."""

from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _mod():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("scoreboard", ROOT / "site" / "scoreboard.py")
    assert spec and spec.loader
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_all_committed_sets_match_their_commitments() -> None:
    rows = _mod().checks(ROOT)
    assert len(rows) >= 6 and all(r["status"] == "match" for r in rows), rows


def test_a_tampered_set_is_flagged(tmp_path: Path) -> None:
    for sub in ("corpus", "heldout", "toolout"):
        shutil.copytree(ROOT / "data" / sub, tmp_path / "data" / sub)
    f = tmp_path / "data" / "toolout" / "toolout.jsonl"
    f.write_text(f.read_text().replace('"to-a0000"', '"to-a9999"', 1))
    rows = {r["set"]: r["status"] for r in _mod().checks(tmp_path)}
    assert rows["Tool-output injection set (ids)"] == "MISMATCH"
    assert rows["Tool-output injection set (file)"] == "MISMATCH"
    assert rows["deepset/prompt-injections test"] == "match"


def test_page_shows_scores_and_the_rules() -> None:
    page = _mod().build(ROOT)
    assert "Scoreboard" in page and "spent" in page and "Tool outputs (synthetic)" in page
    assert "66.9%" in page and "23.6%" in page  # the toolout row, including its bad benign number
    assert "out of distribution" in page and "Project corpus (iid)" in page
    assert "None are on this page" in page
