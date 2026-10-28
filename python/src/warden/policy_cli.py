"""Thin wrapper over the TypeScript `warden-policy` CLI.

Python never re-implements the compiler, the rule hash or the signer: there is one trusted
implementation, and the gate, the loop and the evaluation harness all call it.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from warden.settings import get_settings


class PolicyCliError(RuntimeError):
    pass


def cli_path() -> list[str]:
    s = get_settings()
    path = Path(s.policy_cli) if s.policy_cli else s.repo_root / "packages" / "policy-ir" / "dist" / "cli.js"
    if not path.exists():
        raise PolicyCliError(f"warden-policy CLI not found at {path}; run `pnpm build`")
    node = shutil.which("node")
    if not node:
        raise PolicyCliError("node is not installed")
    return [node, str(path)]


def _run(args: list[str], stdin: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        [*cli_path(), *args], input=stdin, capture_output=True, text=True, timeout=300, check=False
    )
    if check and proc.returncode not in (0, 1):
        raise PolicyCliError(
            f"warden-policy {args[0]} failed ({proc.returncode}): {proc.stderr.strip()[:2000]}"
        )
    return proc


def _tmp_json(obj: Any, suffix: str = ".json") -> Path:
    f = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False)  # noqa: SIM115 - path outlives the handle
    json.dump(obj, f)
    f.close()
    return Path(f.name)


def lint(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """G1: compile each rule with the trusted compiler; returns per-rule ok/errors/hash."""
    p = _tmp_json(rules)
    try:
        out: list[dict[str, Any]] = json.loads(_run(["lint", str(p)]).stdout)
        return out
    finally:
        p.unlink(missing_ok=True)


def hashes(rules: list[dict[str, Any]]) -> dict[str, str]:
    p = _tmp_json(rules)
    try:
        doc = json.loads(_run(["hash", str(p)]).stdout)
        return {h["id"]: h["hash"] for h in doc["hashes"]}
    finally:
        p.unlink(missing_ok=True)


def replay(
    rules: list[dict[str, Any]], messages: list[dict[str, Any]], force_mode: str | None = "enforce"
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Evaluate rules over recorded messages ({id, ctx, label}). Returns per-message decisions and a summary."""
    rp = _tmp_json(rules)
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        for m in messages:
            f.write(json.dumps(m) + "\n")
        cp = Path(f.name)
    try:
        args = ["replay", "--rules", str(rp), "--corpus", str(cp)]
        if force_mode:
            args += ["--force-mode", force_mode]
        proc = _run(args, check=False)
        if proc.returncode != 0:
            raise PolicyCliError(f"replay failed: {proc.stderr.strip()[:2000]}")
        rows = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
        summary = json.loads(proc.stderr.strip().splitlines()[-1]) if proc.stderr.strip() else {}
        return rows, summary
    finally:
        rp.unlink(missing_ok=True)
        cp.unlink(missing_ok=True)


def keygen(directory: Path, key_id: str) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    _run(["keygen", "--key-id", key_id, "--out-dir", str(directory)])
    return directory / f"{key_id}.key.pem", directory / f"{key_id}.pub.pem"


def build_bundle(
    rules: list[dict[str, Any]],
    approvals: list[dict[str, Any]],
    bundle_id: str,
    allow_machine_approval: bool = False,
) -> dict[str, Any]:
    """Assemble an unsigned bundle. Machine approvals for enforce are for lab and CI bundles only."""
    rp, ap = _tmp_json(rules), _tmp_json(approvals)
    out = Path(tempfile.mkdtemp()) / "bundle.json"
    try:
        args = ["bundle", "--rules", str(rp), "--approvals", str(ap), "--id", bundle_id, "--out", str(out)]
        if allow_machine_approval:
            args.append("--allow-machine-approval")
        proc = _run(args, check=False)
        if proc.returncode != 0:
            raise PolicyCliError(f"bundle rejected: {proc.stderr.strip()[:4000]}")
        doc: dict[str, Any] = json.loads(out.read_text())
        return doc
    finally:
        rp.unlink(missing_ok=True)
        ap.unlink(missing_ok=True)


def sign(bundle: dict[str, Any], key_path: Path, key_id: str) -> dict[str, Any]:
    bp = _tmp_json(bundle)
    out = Path(tempfile.mkdtemp()) / "signed.json"
    try:
        _run(["sign", "--bundle", str(bp), "--key", str(key_path), "--key-id", key_id, "--out", str(out)])
        doc: dict[str, Any] = json.loads(out.read_text())
        return doc
    finally:
        bp.unlink(missing_ok=True)


def verify(bundle_path: Path, pub_path: Path) -> dict[str, Any]:
    proc = _run(["verify", "--bundle", str(bundle_path), "--pub", str(pub_path)], check=False)
    doc: dict[str, Any] = json.loads(proc.stdout)
    return doc
