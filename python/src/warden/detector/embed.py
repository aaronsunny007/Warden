"""Embedders for L1. Offline default: signed feature hashing over character and word n-grams."""

from __future__ import annotations

import hashlib
import logging
import re
from itertools import pairwise
from typing import Protocol

import numpy as np

from warden.detector.text import normalize

_WORD = re.compile(r"[a-z0-9@._%+-]+|[^\sa-z0-9]", re.IGNORECASE)


class Embedder(Protocol):
    name: str
    dim: int

    def embed(self, texts: list[str]) -> np.ndarray: ...


def _h(token: str, dim: int) -> tuple[int, float]:
    d = hashlib.blake2b(token.encode(), digest_size=8).digest()
    v = int.from_bytes(d, "little")
    return v % dim, 1.0 if (v >> 63) & 1 else -1.0


def features(text: str) -> list[str]:
    t = normalize(text).lower()
    words = _WORD.findall(t)
    feats = [f"w:{w}" for w in words]
    feats += [f"b:{a} {b}" for a, b in pairwise(words)]
    padded = f" {t} "
    for n in (3, 4, 5):
        feats += [f"c{n}:{padded[i : i + n]}" for i in range(max(0, len(padded) - n + 1))]
    return feats


class HashingEmbedder:
    """Deterministic, dependency-free embedding. Good at near-duplicates and paraphrase variants."""

    def __init__(self, dim: int = 2048) -> None:
        self.dim = dim
        self.name = f"hashing-ngram-{dim}"

    def embed(self, texts: list[str]) -> np.ndarray:
        out = np.zeros((len(texts), self.dim), dtype=np.float32)
        for i, text in enumerate(texts):
            counts: dict[int, float] = {}
            for f in features(text):
                j, s = _h(f, self.dim)
                counts[j] = counts.get(j, 0.0) + s
            for j, c in counts.items():
                out[i, j] = np.sign(c) * np.log1p(abs(c))
            n = np.linalg.norm(out[i])
            if n > 0:
                out[i] /= n
        return out


class SentenceTransformerEmbedder:
    """A small open embedding model (e.g. all-MiniLM-L6-v2), when installed and downloaded."""

    def __init__(self, model: str) -> None:
        from sentence_transformers import SentenceTransformer

        self._m = SentenceTransformer(model, device="cpu")
        self.dim = int(self._m.get_sentence_embedding_dimension())
        self.name = model

    def embed(self, texts: list[str]) -> np.ndarray:
        v = self._m.encode([normalize(t) for t in texts], normalize_embeddings=True, convert_to_numpy=True)
        return np.asarray(v, dtype=np.float32)


def make_embedder(model: str) -> Embedder:
    if model:
        try:
            return SentenceTransformerEmbedder(model)
        except Exception as e:  # noqa: BLE001 - fall back to the offline embedder; /v1/info shows which is live
            logging.getLogger("warden.detector").warning(
                "embedding model %s unavailable (%s); using hashing embedder", model, e
            )
    return HashingEmbedder()
