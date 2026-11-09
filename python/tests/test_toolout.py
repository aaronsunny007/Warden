"""The tool-output set: deterministic, committed hash matches, scorer gating, and a smoke score."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from warden.corpus import LockedSplitError
from warden.eval import toolout

BUILD = Path(__file__).resolve().parents[2] / "data" / "toolout" / "build_toolout.py"


def _builder():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("build_toolout", BUILD)
    assert spec and spec.loader
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_generator_is_deterministic_and_matches_the_committed_file() -> None:
    items = _builder().make()
    on_disk = toolout.load()
    assert [json.dumps(x, sort_keys=True) for x in items] == [json.dumps(x, sort_keys=True) for x in on_disk]
    assert toolout.verify_lock()


def test_set_has_the_advertised_shape() -> None:
    rows = toolout.load()
    atk = [r for r in rows if r["label"] == "attack"]
    assert len(atk) == len(rows) - len(atk) == 360
    assert {r["carrier"] for r in rows} >= {"email", "web_page", "pdf_text", "ticket", "crm_json", "csv"}
    assert len({r["id"] for r in rows}) == len(rows)
    assert all(r["technique"] for r in atk) and not any(
        r["technique"] for r in rows if r["label"] == "benign"
    )
    assert sum(1 for r in rows if r["hard_negative"]) >= 100


def test_scorer_refuses_without_unlock_and_never_overwrites(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(toolout.UNLOCK_ENV, raising=False)
    with pytest.raises(LockedSplitError):
        toolout.run(tmp_path / "o.json")
    monkeypatch.setenv(toolout.UNLOCK_ENV, "1")
    existing = tmp_path / "o.json"
    existing.write_text("{}")
    with pytest.raises(FileExistsError):
        toolout.run(existing)
    assert existing.read_text() == "{}"


def test_summarise_counts() -> None:
    rows = [
        {"id": "a", "label": "attack", "technique": "t", "carrier": "c", "hard_negative": ""},
        {"id": "b", "label": "attack", "technique": "t", "carrier": "c", "hard_negative": ""},
        {"id": "c", "label": "benign", "technique": "", "carrier": "c", "hard_negative": "policy"},
    ]
    s = toolout.summarise(rows, {"a": "malicious", "b": "benign", "c": "uncertain"})
    assert s["attack_blocked"]["k"] == 1 and s["attack_flagged"]["k"] == 1 and s["misses"] == ["b"]
    assert s["benign_flagged"]["k"] == 1 and s["benign_blocked"]["k"] == 0
    assert "policy" in s["benign_by_kind"]
