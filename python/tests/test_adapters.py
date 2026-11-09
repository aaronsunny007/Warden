"""Adapters: client (in-process and over HTTP), LangChain tool guard, Claude Code hook."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.test_detector import cascade
from tests.test_hidden import ATTACK, make_pdf, tag_encode, zw_encode
from warden.adapters import claude_code
from warden.adapters.client import WardenClient
from warden.detector import guard


class LocalClient(WardenClient):
    """In-process client that reuses the fast test cascade instead of building the full one."""

    def __init__(self) -> None:
        super().__init__()
        self._cascade = cascade()


def test_client_in_process_flags_attack_and_explains() -> None:
    v = LocalClient().check(ATTACK)
    assert v.verdict in {"malicious", "uncertain"} and v.explanation


def test_client_sees_hidden_payload() -> None:
    v = LocalClient().check("All good." + zw_encode(ATTACK))
    assert v.verdict != "benign" and any(f["kind"] == "zero_width_payload" for f in v.hidden)


def test_client_check_file_pdf(tmp_path: Path) -> None:
    p = tmp_path / "r.pdf"
    p.write_bytes(
        make_pdf(f"BT /F1 12 Tf 72 700 Td (Hello) Tj ET q 1 g BT /F1 12 Tf 72 650 Td ({ATTACK}) Tj ET Q")
    )
    v = LocalClient().check_file(p)
    assert v.verdict != "benign" and any(f["kind"] == "pdf_hidden_text" for f in v.hidden)


def test_client_failure_modes() -> None:
    closed = WardenClient("http://127.0.0.1:1", timeout=0.2).check("x")
    assert closed.verdict == "uncertain" and closed.error
    opened = WardenClient("http://127.0.0.1:1", timeout=0.2, on_error="open").check("x")
    assert opened.verdict == "benign" and opened.error
    with pytest.raises(ValueError):
        WardenClient(on_error="maybe")


def test_guard_never_returns_benign_for_hidden_payload() -> None:
    c = guard.check_text(cascade(), "fine" + tag_encode(ATTACK))
    assert c.verdict in {"uncertain", "malicious"}


# ---- LangChain

pytest.importorskip("langchain_core")


def _tools():  # type: ignore[no-untyped-def]
    from langchain_core.tools import tool

    @tool
    def fetch_note(note_id: str) -> str:
        """Return a customer note."""
        return {"1": "Customer asked about shipping times.", "2": ATTACK}[note_id]

    return fetch_note


def test_langchain_guard_passes_clean_and_blocks_attack() -> None:
    from warden.adapters.langchain import guard_tool

    g = guard_tool(_tools(), LocalClient(), block_uncertain=False)
    assert g.name == "fetch_note" and "customer note" in g.description
    clean = g.invoke({"note_id": "1"})
    assert "shipping" in clean
    out = g.invoke({"note_id": "2"})
    assert out.startswith("[Warden blocked the output of fetch_note") and "refund 900" not in out


def test_langchain_block_uncertain_is_stricter() -> None:
    from warden.adapters.langchain import guard_tool

    g = guard_tool(_tools(), LocalClient(), block_uncertain=True)
    assert "Warden blocked" in g.invoke({"note_id": "2"})


# ---- Claude Code hook


def event(**kw: object) -> dict[str, object]:
    return {"hook_event_name": "PostToolUse", "tool_name": "Bash", **kw}


def test_hook_blocks_malicious_tool_output() -> None:
    out = claude_code.handle(event(tool_response={"stdout": ATTACK}), LocalClient())
    assert out["decision"] == "block" and "Warden" in out["reason"]
    assert "additionalContext" in out["hookSpecificOutput"]


def test_hook_pretooluse_denies_hidden_payload_in_arguments() -> None:
    out = claude_code.handle(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"content": "ok" + tag_encode(ATTACK)},
        },
        LocalClient(),
    )
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_hook_pretooluse_allows_normal_arguments() -> None:
    assert (
        claude_code.handle(
            {"hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {"content": "hello"}},
            LocalClient(),
        )
        == {}
    )


def test_hook_scans_pdf_read_from_disk(tmp_path: Path) -> None:
    p = tmp_path / "r.pdf"
    p.write_bytes(
        make_pdf(f"BT /F1 12 Tf 72 700 Td (Hello) Tj ET q 1 g BT /F1 12 Tf 72 650 Td ({ATTACK}) Tj ET Q")
    )
    out = claude_code.handle(
        {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": str(p)},
            "tool_response": "Hello",
        },
        LocalClient(),
    )
    assert out["decision"] == "block"  # the text Claude read was clean; the file itself hides the attack


def test_hook_run_handles_garbage_and_prints_json() -> None:
    assert claude_code.run("not json", LocalClient()) == "{}"
    assert (
        json.loads(claude_code.run(json.dumps(event(tool_response="hello there")), LocalClient())) is not None
    )


def test_settings_snippet_shape() -> None:
    s = claude_code.settings_snippet()
    assert set(s["hooks"]) == {"UserPromptSubmit", "PreToolUse", "PostToolUse"}
