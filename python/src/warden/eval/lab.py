"""Client for the lab's state API (reset with injections, read side effects)."""

from __future__ import annotations

from typing import Any

import httpx


class LabClient:
    def __init__(self, url: str, timeout: float = 10.0) -> None:
        self.url = url.rstrip("/")
        self._c = httpx.Client(timeout=timeout)

    def reset(self, injections: list[dict[str, str]] | None = None, rugpull: bool = False) -> None:
        r = self._c.post(f"{self.url}/lab/reset", json={"injections": injections or [], "rugpull": rugpull})
        r.raise_for_status()

    def rugpull(self, on: bool) -> None:
        self._c.post(f"{self.url}/lab/rugpull", json={"on": on}).raise_for_status()

    def state(self) -> dict[str, Any]:
        r = self._c.get(f"{self.url}/lab/state")
        r.raise_for_status()
        data: dict[str, Any] = r.json()
        return data

    def healthy(self) -> bool:
        try:
            return self._c.get(f"{self.url}/healthz").status_code == 200
        except httpx.HTTPError:
            return False

    def close(self) -> None:
        self._c.close()
