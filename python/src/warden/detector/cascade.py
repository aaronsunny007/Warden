"""The detection cascade. Cheapest layer first; escalate only uncertain cases.

L1  embedding kNN vote over the labelled dev corpus      escalates when the vote is uncertain
L2  classifier (lite or fine-tuned ONNX)                 escalates when uncertain AND the sink is high-risk
L3  local LLM judge                                      final verdict, budget-capped

Tool outputs and descriptions feed the model that controls every tool, so they are treated
as high-risk sinks; tool-call arguments use the tool's own risk tier.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

import numpy as np

from warden.corpus import Example
from warden.detector.classifier import Classifier
from warden.detector.embed import Embedder
from warden.detector.index import VectorIndex
from warden.detector.judge import OllamaJudge

HIGH_RISK = {"external_send", "financial_destructive"}


@dataclass
class LayerScore:
    layer: str
    score: float
    latency_ms: float
    label: str = ""
    detail: str = ""


@dataclass
class Detection:
    verdict: str  # benign | malicious | uncertain
    score: float
    layers: list[LayerScore] = field(default_factory=list)
    span: tuple[int, int] | None = None  # character span of the window that decided, for long texts


@dataclass
class Thresholds:
    k: int = 7
    floor: float = 0.22
    low: float = 0.30
    high: float = 0.80
    min_words: int = 8
    # Long texts (documents, emails, tool dumps) are read in overlapping windows so one instruction is not
    # diluted by pages of ordinary prose. 0 turns it off. Texts shorter than 2 windows are scored whole.
    window_words: int = 0
    max_windows: int = 48
    # L1 only gets to call something malicious when the nearest known text is at least this similar. Farther
    # than that the vote is a guess about text the corpus has never seen, so it is pulled to "uncertain".
    ood_sim: float = 0.0


_TOKEN = re.compile(r"\S+")


def windows(text: str, size: int, max_windows: int) -> list[tuple[int, int]]:
    """Overlapping word windows (half-window stride) as character spans. The window grows for very long texts
    so the count stays bounded and every part of the text is still covered."""
    toks = [m.span() for m in _TOKEN.finditer(text)]
    n = len(toks)
    if size <= 0 or n <= 2 * size:
        return [(0, len(text))]
    size = max(size, -(-2 * n // max_windows))
    stride = max(1, size // 2)
    out = []
    i = 0
    while True:
        j = min(i + size, n)
        out.append((toks[i][0], toks[j - 1][1]))
        if j >= n:
            break
        i += stride
    return out


def band(score: float, t: Thresholds) -> str:
    if score >= t.high:
        return "malicious"
    if score < t.low:
        return "benign"
    return "uncertain"


class Cascade:
    def __init__(
        self,
        embedder: Embedder,
        index: VectorIndex,
        classifier: Classifier | None,
        judge: OllamaJudge | None,
        thresholds: Thresholds | None = None,
        mode: str = "full",
    ) -> None:
        self.embedder, self.index, self.classifier, self.judge = embedder, index, classifier, judge
        self.t = thresholds or Thresholds()
        self.mode = mode

    def load_corpus(self, examples: list[Example]) -> None:
        if not examples:
            return
        vecs = self.embedder.embed([e.text for e in examples])
        self.index.add(
            [e.id for e in examples],
            [e.text for e in examples],
            [e.label for e in examples],
            [e.family for e in examples],
            vecs,
        )

    def l1(self, text: str) -> LayerScore:
        start = time.perf_counter()
        v = self.embedder.embed([text])[0]
        nn = self.index.search(v, self.t.k)
        top = max((n.similarity for n in nn), default=0.0)
        weights = np.array([max(n.similarity, 0.0) ** 2 for n in nn])
        attack = np.array([1.0 if n.label == "attack" else 0.0 for n in nn])
        vote = float((weights * attack).sum() / weights.sum()) if weights.sum() > 0 else 0.5
        # Far from everything we know, or too short to carry much signal: the vote means little,
        # so pull it into the uncertain band and let L2 (and L3) decide.
        words = len(text.split())
        known = top >= max(self.t.floor, self.t.ood_sim) and words >= self.t.min_words
        score = vote if known else 0.5 * vote + 0.25
        nearest = nn[0] if nn else None
        detail = f"top_sim={top:.3f} nearest={nearest.family if nearest else '-'}"
        return LayerScore(
            "L1", round(score, 4), (time.perf_counter() - start) * 1000, band(score, self.t), detail
        )

    def l2(self, text: str) -> LayerScore | None:
        if self.classifier is None:
            return None
        start = time.perf_counter()
        s = float(self.classifier.score([text])[0])
        return LayerScore(
            "L2", round(s, 4), (time.perf_counter() - start) * 1000, band(s, self.t), self.classifier.name
        )

    def l3(self, text: str) -> LayerScore | None:
        if self.judge is None:
            return None
        start = time.perf_counter()
        r = self.judge.judge(text)
        if not r.available:
            return LayerScore("L3", 0.5, (time.perf_counter() - start) * 1000, "unavailable", r.reason)
        return LayerScore(
            "L3", round(r.score, 4), (time.perf_counter() - start) * 1000, band(r.score, self.t), r.reason
        )

    def _cascade(self, text: str, high_risk: bool) -> Detection:
        layers: list[LayerScore] = []
        s1 = self.l1(text)
        layers.append(s1)
        current = s1
        if s1.label == "uncertain":
            s2 = self.l2(text)
            if s2 is not None:
                layers.append(s2)
                current = s2
            if current.label == "uncertain" and high_risk:
                s3 = self.l3(text)
                if s3 is not None:
                    layers.append(s3)
                    if s3.label != "unavailable":
                        current = s3
        return Detection(verdict=band(current.score, self.t), score=current.score, layers=layers)

    def detect(self, text: str, channel: str = "output", risk_tier: str = "read_only") -> Detection:
        high_risk = channel in {"output", "description"} or risk_tier in HIGH_RISK
        if self.mode == "l2only":
            s2 = self.l2(text)
            if s2 is None:
                return Detection("uncertain", 0.5, [])
            return Detection(band(s2.score, self.t), s2.score, [s2])
        spans = windows(text, self.t.window_words, self.t.max_windows)
        if len(spans) == 1:
            return self._cascade(text, high_risk)
        # Long text: run the cheap layers on every window, then give the single worst window to the
        # expensive layer (L3). The verdict is the most severe window's.
        rank = {"benign": 0, "uncertain": 1, "malicious": 2}
        best: Detection | None = None
        best_span = spans[0]
        for a, b in spans:
            d = self._cascade(text[a:b], False)
            if best is None or (rank[d.verdict], d.score) > (rank[best.verdict], best.score):
                best, best_span = d, (a, b)
        assert best is not None
        if best.verdict == "uncertain" and high_risk and self.judge is not None:
            d = self._cascade(text[best_span[0] : best_span[1]], True)
            best = d
        best.span = best_span
        return best
