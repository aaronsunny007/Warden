"""Vector indexes for L1: in-memory (numpy) or PostgreSQL with pgvector."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import numpy as np


@dataclass(frozen=True)
class Neighbour:
    id: str
    label: str
    family: str
    similarity: float


class VectorIndex(Protocol):
    def add(
        self, ids: list[str], texts: list[str], labels: list[str], families: list[str], vectors: np.ndarray
    ) -> None: ...

    def search(self, vector: np.ndarray, k: int) -> list[Neighbour]: ...

    def __len__(self) -> int: ...


class MemoryIndex:
    def __init__(self, dim: int) -> None:
        self.dim = dim
        self._v = np.zeros((0, dim), dtype=np.float32)
        self._ids: list[str] = []
        self._labels: list[str] = []
        self._fam: list[str] = []

    def add(
        self, ids: list[str], texts: list[str], labels: list[str], families: list[str], vectors: np.ndarray
    ) -> None:
        _ = texts
        self._v = np.vstack([self._v, vectors.astype(np.float32)])
        self._ids += ids
        self._labels += labels
        self._fam += families

    def search(self, vector: np.ndarray, k: int) -> list[Neighbour]:
        if not self._ids:
            return []
        sims = self._v @ vector.astype(np.float32)
        top = np.argsort(-sims)[:k]
        return [Neighbour(self._ids[i], self._labels[i], self._fam[i], float(sims[i])) for i in top]

    def __len__(self) -> int:
        return len(self._ids)


class PgVectorIndex:
    """Stores corpus embeddings in the `corpus` table; cosine distance with pgvector's <=> operator."""

    def __init__(self, database_url: str, dim: int) -> None:
        from sqlalchemy import create_engine

        self.dim = dim
        self._engine = create_engine(database_url, pool_pre_ping=True)

    def add(
        self, ids: list[str], texts: list[str], labels: list[str], families: list[str], vectors: np.ndarray
    ) -> None:
        from sqlalchemy import text

        stmt = text(
            "INSERT INTO corpus (id, text, label, family, split, source, channel, embedding) "
            "VALUES (:id, :text, :label, :family, 'dev', 'detector', 'output', CAST(:v AS vector)) "
            "ON CONFLICT (id) DO UPDATE SET embedding = EXCLUDED.embedding"
        )
        with self._engine.begin() as c:
            for i, t, lab, fam, v in zip(ids, texts, labels, families, vectors, strict=True):
                c.execute(
                    stmt,
                    {
                        "id": i,
                        "text": t,
                        "label": lab,
                        "family": fam,
                        "v": "[" + ",".join(f"{x:.6f}" for x in v) + "]",
                    },
                )

    def search(self, vector: np.ndarray, k: int) -> list[Neighbour]:
        from sqlalchemy import text

        with self._engine.connect() as c:
            rows = c.execute(
                text(
                    "SELECT id, label, family, 1 - (embedding <=> CAST(:v AS vector)) AS sim FROM corpus "
                    "WHERE embedding IS NOT NULL AND split = 'dev' ORDER BY embedding <=> CAST(:v AS vector) LIMIT :k"
                ),
                {"v": "[" + ",".join(f"{x:.6f}" for x in vector) + "]", "k": k},
            ).all()
        return [Neighbour(r[0], r[1], r[2] or "", float(r[3])) for r in rows]

    def __len__(self) -> int:
        from sqlalchemy import text

        with self._engine.connect() as c:
            return int(
                c.execute(text("SELECT count(*) FROM corpus WHERE embedding IS NOT NULL")).scalar_one()
            )
