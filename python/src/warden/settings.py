"""Runtime settings from the environment (prefix WARDEN_)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="WARDEN_", env_file=".env", extra="ignore")

    repo_root: Path = REPO_ROOT
    data_dir: Path = REPO_ROOT / "data"
    database_url: str = ""
    redis_url: str = ""

    # Detection cascade
    embed_model: str = ""  # e.g. sentence-transformers/all-MiniLM-L6-v2; empty = offline hashing embedder
    l2_onnx_dir: str = ""  # directory with model.onnx + tokenizer.json (+ labels.json)
    l2_mode: str = "lite"  # lite | onnx | off
    l2_extra_train: str = (
        ""  # optional JSONL of {"text", "label": 0|1} added to the lite classifier's training data
    )
    ollama_url: str = "http://127.0.0.1:11434"
    judge_model: str = ""  # e.g. qwen2.5:7b; empty disables L3
    judge_timeout_s: float = 8.0
    judge_calls_per_hour: int = 600
    judge_tokens_per_hour: int = 400_000
    l1_k: int = 7
    l1_floor: float = 0.22
    band_low: float = 0.30
    band_high: float = 0.80
    window_words: int = 64  # long texts are read in windows of this many words; 0 reads them whole
    max_windows: int = 48
    l1_ood_sim: float = 0.0
    # Fitted lite-L2 weights (scripts/train_lite_v2.py). Empty = models/lite-l2-docs.npz when it exists, "none" =
    # fit on the project corpus at start-up like before.
    l2_lite_weights: str = ""
    index: str = "memory"  # memory | pgvector
    cascade: str = "full"  # full | l2only (baseline B2: a classifier on outputs, nothing else)
    allow_corpus_writes: bool = False
    miss_log: str = (
        ""  # JSONL path; when set, POST /v1/miss appends reported misses (the learn-from-mistakes input)
    )
    service_token: str = ""

    # Gateway / control plane
    gateway_url: str = "http://127.0.0.1:8787"
    gateway_admin_token: str = ""
    control_token: str = ""  # bearer token for the control plane /v1 API; empty = open (dev only)
    lab_url: str = "http://127.0.0.1:8790"
    policy_cli: str = ""  # path to warden-policy CLI (dist/cli.js); auto-detected if empty
    signing_key: str = ""  # path to the Ed25519 private key PEM used to sign approved bundles
    signing_key_id: str = "warden-control-plane"

    # Budgets (as in AEGIS)
    max_rules_per_hour: int = 6
    max_llm_calls_per_hour: int = 120
    max_llm_tokens_per_hour: int = 200_000

    # Learning-loop LLM (blue team / red-team paraphrase); empty = templates only
    loop_model: str = ""


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
