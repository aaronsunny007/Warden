"""A small client for the detection service, with an in-process mode that needs no server.

    client = WardenClient()                           # in-process: offline hashing embedder + lite classifier
    client = WardenClient("http://localhost:8000")    # talk to a running `warden detector serve`
    v = client.check("tool output text")              # -> Outcome
    v = client.check_file("report.pdf")

If the service cannot be reached, `on_error` decides: "closed" (default) treats the content as
`uncertain` so callers do not silently trust it; "open" lets it through.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx


@dataclass
class Outcome:
    verdict: str  # benign | uncertain | malicious
    score: float
    explanation: str
    hidden: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""

    @property
    def malicious(self) -> bool:
        return self.verdict == "malicious"


class WardenClient:
    def __init__(
        self,
        url: str | None = None,
        *,
        token: str = "",
        timeout: float = 5.0,
        on_error: str = "closed",
    ) -> None:
        if on_error not in {"open", "closed"}:
            raise ValueError("on_error must be 'open' or 'closed'")
        self.url = url.rstrip("/") if url else None
        self.token = token
        self.timeout = timeout
        self.on_error = on_error
        self._cascade: Any = None

    # -- in-process

    def _local(self) -> Any:
        if self._cascade is None:
            from warden.detector.service import build_cascade
            from warden.settings import get_settings

            self._cascade = build_cascade(get_settings())
        return self._cascade

    def _failed(self, why: str) -> Outcome:
        if self.on_error == "open":
            return Outcome(
                "benign", 0.0, f"Warden unavailable ({why}); allowed because on_error='open'.", error=why
            )
        return Outcome("uncertain", 0.5, f"Warden unavailable ({why}); treated as unverified.", error=why)

    def _post(self, path: str, body: dict[str, Any]) -> Outcome:
        headers = {"authorization": f"Bearer {self.token}"} if self.token else {}
        try:
            r = httpx.post(f"{self.url}{path}", json=body, headers=headers, timeout=self.timeout)
            r.raise_for_status()
            j = r.json()
        except (httpx.HTTPError, ValueError) as e:
            return self._failed(type(e).__name__)
        return Outcome(j["verdict"], j["score"], j.get("explanation", ""), j.get("hidden", []))

    # -- API

    def check(self, text: str, channel: str = "output", risk_tier: str = "read_only") -> Outcome:
        if self.url:
            return self._post(
                "/v1/detect", {"text": text[:65536], "channel": channel, "risk_tier": risk_tier}
            )
        from warden.detector.guard import check_text

        c = check_text(self._local(), text[:65536], channel, risk_tier)
        return Outcome(c.verdict, c.score, c.explanation, [f.__dict__ for f in c.report.findings])

    def check_bytes(self, data: bytes, kind: str = "auto", channel: str = "output") -> Outcome:
        if self.url:
            body = {"kind": kind, "content_base64": base64.b64encode(data).decode(), "channel": channel}
            return self._post("/v1/scan", body)
        from warden.detector.guard import check_bytes

        try:
            c = check_bytes(self._local(), data, kind, channel)
        except ImportError:
            return self._failed("file scanning needs the 'files' extra")
        out = Outcome(c.verdict, c.score, c.explanation, [f.__dict__ for f in c.report.findings])
        return out

    def check_file(self, path: str | Path, kind: str = "auto", channel: str = "output") -> Outcome:
        return self.check_bytes(Path(path).read_bytes(), kind, channel)
