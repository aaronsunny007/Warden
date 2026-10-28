from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


def built() -> bool:
    return (
        (REPO / "packages/policy-ir/dist/cli.js").exists()
        and (REPO / "packages/gateway/dist/cli.js").exists()
        and shutil.which("node") is not None
    )


needs_node = pytest.mark.skipif(not built(), reason="needs `pnpm build` and node")
needs_db = pytest.mark.skipif(
    not os.environ.get("WARDEN_TEST_DATABASE_URL"),
    reason="set WARDEN_TEST_DATABASE_URL (Postgres with pgvector)",
)
