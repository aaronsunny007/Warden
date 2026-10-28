"""Brings up the lab, detection services and one gateway per baseline as local processes.

Baselines (design section 9):
  B0  no defence: the agent talks to the lab servers directly
  B1  spotlighting only (gateway with pins off and no rules)
  B2  a classifier on tool outputs only (detector in l2only mode; PromptGuard 2 when available)
  B3  static Warden: pins, all layers, taint tracking, the baseline ruleset
  B4  B3 plus rules promoted by the gated loop
  B5  B3 plus rules from an ungated loop (RQ2 only)
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from warden import policy_cli
from warden.settings import get_settings

CORE_SERVERS = ["email", "customers", "files", "web", "tickets", "payments", "weather"]
MCP_SERVERS = [*CORE_SERVERS, "facts", "audit"]
TRUSTED = {"email", "customers", "files", "tickets", "payments"}
TAINT_SOURCES = {"email": ["read_email", "search_email"], "tickets": ["get_ticket"], "files": ["read_file"]}

B2_RULE: dict[str, Any] = {
    "id": "B2-CLASSIFIER",
    "version": 1,
    "description": "Baseline B2: block tool output the classifier scores as an injection.",
    "mode": "enforce",
    "severity": "high",
    "action": {"type": "block", "message": "classifier flagged the output"},
    "scope": {"channels": ["output"]},
    "match": {"kind": "detector", "layer": "L2", "gte": 0.5},
    "owasp": ["ASI01"],
    "provenance": {"author": "human", "note": "LlamaFirewall-style PromptGuard on tool outputs"},
}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait_http(url: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        try:
            if httpx.get(url, timeout=1.0).status_code < 500:
                return
        except httpx.HTTPError as e:
            last = str(e)
        time.sleep(0.2)
    raise TimeoutError(f"{url} not ready: {last}")


@dataclass
class Proc:
    name: str
    popen: subprocess.Popen[bytes]
    url: str
    log: Path

    def stop(self) -> None:
        if self.popen.poll() is None:
            self.popen.terminate()
            try:
                self.popen.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.popen.kill()


@dataclass
class Stack(AbstractContextManager["Stack"]):
    """Lab + detectors + one gateway per requested id ("B3-core", "B3-mcp", ...).

    "core" gateways front the Acme servers; "mcp" gateways also front the malicious servers,
    for the tool-poisoning and shadowing cases."""

    baselines: list[str]
    extra_rules: dict[str, list[dict[str, Any]]] = field(default_factory=dict)  # B4/B5 promoted rules
    record_messages: bool = True
    # Optional upstream server configs per server set ("core"/"mcp"), e.g. AgentDojo suites.
    server_configs: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    workdir: Path = field(default_factory=lambda: Path(tempfile.mkdtemp(prefix="warden-eval-")))
    procs: dict[str, Proc] = field(default_factory=dict)
    key: Path = field(default_factory=Path)
    pub: Path = field(default_factory=Path)
    key_id: str = "eval"

    def _spawn(
        self, name: str, cmd: list[str], url: str, health: str, env: dict[str, str] | None = None
    ) -> Proc:
        log = self.workdir / f"{name}.log"
        fh = log.open("wb")
        p = subprocess.Popen(
            cmd,
            stdout=fh,
            stderr=subprocess.STDOUT,
            env={**os.environ, **(env or {})},
            cwd=get_settings().repo_root,
        )
        proc = Proc(name, p, url, log)
        self.procs[name] = proc
        try:
            wait_http(f"{url}{health}")
        except TimeoutError as e:
            raise RuntimeError(f"{name} failed to start; see {log}:\n{log.read_text()[-2000:]}") from e
        return proc

    @property
    def lab_url(self) -> str:
        return self.procs["lab"].url

    def gateway_url(self, baseline: str) -> str | None:
        p = self.procs.get(f"gateway-{baseline}")
        return p.url if p else None

    def _rules_for(self, gid: str) -> list[dict[str, Any]]:
        baseline = gid.split("-")[0]
        repo = get_settings().repo_root
        base: list[dict[str, Any]] = json.loads((repo / "policies" / "baseline.rules.json").read_text())
        if baseline in {"B0", "B1"}:
            return []
        if baseline == "B2":
            return [B2_RULE]
        return base + self.extra_rules.get(gid, [])

    def _bundle(self, baseline: str, key: Path, key_id: str) -> Path:
        rules = self._rules_for(baseline)
        hashes = policy_cli.hashes(rules) if rules else {}
        approvals = [
            {
                "ruleId": r["id"],
                "version": r["version"],
                "ruleHash": hashes[r["id"]],
                "stage": "enforce",
                "gateReport": "0" * 64,
                "approvedBy": "eval-harness",
                "human": False,
                "approvedAt": "2026-01-01T00:00:00Z",
            }
            for r in rules
        ]
        bundle = policy_cli.sign(
            policy_cli.build_bundle(rules, approvals, f"eval-{baseline}", allow_machine_approval=True),
            key,
            key_id,
        )
        path = self.workdir / f"bundle-{baseline}.json"
        path.write_text(json.dumps(bundle))
        return path

    def _gateway_config(
        self, gid: str, port: int, bundle: Path, pub: Path, key_id: str, detector_url: str
    ) -> Path:
        baseline = gid.split("-")[0]
        pins = baseline not in {"B0", "B1", "B2"}
        servers: list[dict[str, Any]] = list(self.server_configs.get(gid.split("-", 1)[1], []))
        for s in [] if servers else (MCP_SERVERS if gid.endswith("-mcp") else CORE_SERVERS):
            servers.append(
                {
                    "name": s,
                    "transport": {"type": "http", "url": f"{self.lab_url}/mcp/{s}"},
                    "trust": "trusted" if s in TRUSTED else "untrusted",
                    "taintSources": TAINT_SOURCES.get(s, []),
                }
            )
        cfg = {
            "listen": {"host": "127.0.0.1", "port": port},
            "admin": {"token": "eval"},
            "servers": servers,
            "policy": {
                "bundle": str(bundle),
                "trustedKeys": {key_id: str(pub)},
                "requireHumanApproval": False,
                "watch": False,
            },
            "pins": {"enabled": pins, "store": "memory", "autoApproveClean": True, "refreshSeconds": 0},
            "detector": {
                "url": detector_url,
                "timeoutMs": 2000,
                "channels": ["description", "output"],
                "cacheTtlSeconds": 0,
            },
            "events": {"ringSize": 200000, "recordMessages": self.record_messages},
            "spotlight": {"enabled": baseline != "B2"},
        }
        path = self.workdir / f"gateway-{gid}.yaml"
        path.write_text(json.dumps(cfg))  # JSON is valid YAML
        return path

    def __enter__(self) -> Stack:
        s = get_settings()
        repo = s.repo_root
        node = shutil.which("node") or "node"
        lab_port = free_port()
        self._spawn(
            "lab",
            [node, str(repo / "packages/lab-servers/dist/cli.js"), "http", "--port", str(lab_port)],
            f"http://127.0.0.1:{lab_port}",
            "/healthz",
        )
        key_id = "eval"
        key, pub = policy_cli.keygen(self.workdir / "keys", key_id)
        self.key, self.pub, self.key_id = key, pub, key_id
        detectors: dict[str, str] = {}
        bases = {g.split("-")[0] for g in self.baselines}
        for mode, needed in (("full", bool(bases & {"B3", "B4", "B5"})), ("l2only", "B2" in bases)):
            if not needed:
                continue
            port = free_port()
            self._spawn(
                f"detector-{mode}",
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "warden.detector.service:create_app",
                    "--factory",
                    "--port",
                    str(port),
                    "--log-level",
                    "warning",
                ],
                f"http://127.0.0.1:{port}",
                "/healthz",
                env={"WARDEN_CASCADE": mode},
            )
            detectors[mode] = f"http://127.0.0.1:{port}"
        for b in self.baselines:
            base = b.split("-")[0]
            if base == "B0":
                continue
            port = free_port()
            det = detectors.get("l2only" if base == "B2" else "full", "") if base != "B1" else ""
            cfg = self._gateway_config(b, port, self._bundle(b, key, key_id), pub, key_id, det)
            self._spawn(
                f"gateway-{b}",
                [node, str(repo / "packages/gateway/dist/cli.js"), "serve", "--config", str(cfg)],
                f"http://127.0.0.1:{port}",
                "/healthz",
                env={"LOG_LEVEL": "warn"},
            )
        return self

    def __exit__(self, *exc: object) -> None:
        for p in reversed(list(self.procs.values())):
            p.stop()

    def put_policy(self, gid: str, bundle: dict[str, Any]) -> dict[str, Any]:
        url = self.gateway_url(gid)
        if not url:
            raise KeyError(gid)
        r = httpx.put(
            f"{url}/api/v1/policy", json=bundle, headers={"authorization": "Bearer eval"}, timeout=30
        )
        if r.status_code != 200:
            raise RuntimeError(f"gateway {gid} rejected bundle: {r.text[:2000]}")
        out: dict[str, Any] = r.json()
        return out

    def admin(self, baseline: str, path: str) -> Any:
        url = self.gateway_url(baseline)
        if not url:
            return None
        r = httpx.get(f"{url}/api/v1{path}", headers={"authorization": "Bearer eval"}, timeout=30)
        r.raise_for_status()
        return r.json()
