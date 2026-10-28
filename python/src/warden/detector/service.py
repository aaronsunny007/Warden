"""FastAPI detection service consumed by the gateway (POST /v1/detect)."""

from __future__ import annotations

import hmac
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pydantic import BaseModel, Field

from warden import __version__
from warden.corpus import load
from warden.detector.cascade import Cascade, Thresholds
from warden.detector.classifier import Classifier, LiteClassifier, OnnxClassifier
from warden.detector.embed import make_embedder
from warden.detector.index import MemoryIndex, PgVectorIndex, VectorIndex
from warden.detector.judge import Budget, OllamaJudge
from warden.settings import Settings, get_settings

LAT = Histogram(
    "warden_detector_seconds",
    "Detection latency by deepest layer",
    ["layer"],
    buckets=(0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
)
VERDICTS = Counter("warden_detector_verdicts_total", "Detector verdicts", ["verdict", "channel"])


class DetectRequest(BaseModel):
    text: str = Field(max_length=65536)
    channel: str = "output"
    risk_tier: str = "read_only"
    session_id: str = ""
    tool: str = ""


class LayerOut(BaseModel):
    layer: str
    score: float
    latency_ms: float
    label: str
    detail: str


class DetectResponse(BaseModel):
    verdict: str
    score: float
    layers: list[LayerOut]


class CorpusAdd(BaseModel):
    items: list[dict[str, str]]


def build_cascade(s: Settings) -> Cascade:
    embedder = make_embedder(s.embed_model)
    index: VectorIndex = (
        PgVectorIndex(s.database_url, embedder.dim)
        if s.index == "pgvector" and s.database_url
        else MemoryIndex(embedder.dim)
    )
    dev = load(["dev"])
    classifier: Classifier | None = None
    if s.l2_mode == "onnx" and s.l2_onnx_dir:
        classifier = OnnxClassifier(s.l2_onnx_dir)
    elif s.l2_mode == "lite":
        classifier = LiteClassifier().fit(
            [e.text for e in dev], [1 if e.label == "attack" else 0 for e in dev]
        )
    judge = (
        OllamaJudge(
            s.ollama_url,
            s.judge_model,
            s.judge_timeout_s,
            Budget(s.judge_calls_per_hour, s.judge_tokens_per_hour),
        )
        if s.judge_model
        else None
    )
    cascade = Cascade(
        embedder,
        index,
        classifier,
        judge,
        Thresholds(s.l1_k, s.l1_floor, s.band_low, s.band_high),
        mode=s.cascade,
    )
    if isinstance(index, MemoryIndex) or len(index) == 0:
        cascade.load_corpus(dev)
    return cascade


def create_app(settings: Settings | None = None, cascade: Cascade | None = None) -> FastAPI:
    s = settings or get_settings()
    state: dict[str, Any] = {}

    @asynccontextmanager
    async def lifespan(_: FastAPI):  # type: ignore[no-untyped-def]
        state["cascade"] = cascade or build_cascade(s)
        yield

    app = FastAPI(title="Warden detection service", version=__version__, lifespan=lifespan)

    def cas() -> Cascade:
        c: Cascade = state["cascade"]
        return c

    @app.get("/healthz")
    def healthz() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/v1/info")
    def info() -> dict[str, Any]:
        c = cas()
        return {
            "version": __version__,
            "embedder": c.embedder.name,
            "index_size": len(c.index),
            "classifier": c.classifier.name if c.classifier else None,
            "judge": c.judge.name if c.judge else None,
            "thresholds": c.t.__dict__,
            "mode": c.mode,
        }

    @app.post("/v1/detect", response_model=DetectResponse)
    def detect(req: DetectRequest) -> DetectResponse:
        start = time.perf_counter()
        d = cas().detect(req.text, req.channel, req.risk_tier)
        LAT.labels(d.layers[-1].layer if d.layers else "none").observe(time.perf_counter() - start)
        VERDICTS.labels(d.verdict, req.channel).inc()
        return DetectResponse(
            verdict=d.verdict, score=d.score, layers=[LayerOut(**layer.__dict__) for layer in d.layers]
        )

    @app.post("/v1/corpus")
    def add_corpus(body: CorpusAdd, authorization: str = Header(default="")) -> dict[str, int]:
        # Changing the L1 corpus changes enforcement, so it is closed unless explicitly enabled (dev only).
        if not s.allow_corpus_writes:
            raise HTTPException(
                403, "corpus writes are disabled; corpus changes go through the validation gate"
            )
        if s.service_token and not hmac.compare_digest(authorization, f"Bearer {s.service_token}"):
            raise HTTPException(401, "unauthorized")
        from warden.corpus import Example

        items = [
            Example(
                id=i["id"], text=i["text"], label=i["label"], family=i.get("family", "added"), split="dev"
            )
            for i in body.items
        ]
        cas().load_corpus(items)
        return {"added": len(items)}

    @app.get("/metrics")
    def metrics() -> PlainTextResponse:
        return PlainTextResponse(generate_latest().decode(), media_type=CONTENT_TYPE_LATEST)

    return app
