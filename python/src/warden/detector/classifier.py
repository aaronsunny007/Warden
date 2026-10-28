"""L2 classifiers.

- LiteClassifier: logistic regression on hashed n-gram features, trained in numpy on the dev split.
  Always available; a transparent baseline, not a substitute for a fine-tuned model.
- OnnxClassifier: a fine-tuned DeBERTa-class model (training/train_l2.py) or Meta's PromptGuard 2,
  exported to ONNX and run on CPU with onnxruntime.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

import numpy as np

from warden.detector.embed import HashingEmbedder
from warden.detector.text import normalize


class Classifier(Protocol):
    name: str

    def score(self, texts: list[str]) -> np.ndarray:
        """Probability that each text is an injection."""
        ...


class LiteClassifier:
    def __init__(self, dim: int = 4096, l2: float = 1e-3, epochs: int = 300, lr: float = 0.5) -> None:
        self._emb = HashingEmbedder(dim)
        self.dim = dim
        self.l2, self.epochs, self.lr = l2, epochs, lr
        self.w = np.zeros(dim, dtype=np.float64)
        self.b = 0.0
        self.name = f"lite-logreg-{dim}"

    def fit(self, texts: list[str], labels: list[int], seed: int = 0) -> LiteClassifier:
        x = self._emb.embed(texts).astype(np.float64)
        y = np.asarray(labels, dtype=np.float64)
        # Balance classes so a skewed corpus does not bias the intercept.
        pos = max(1.0, float(y.sum()))
        neg = max(1.0, float(len(y) - y.sum()))
        sw = np.where(y == 1, len(y) / (2 * pos), len(y) / (2 * neg))
        rng = np.random.default_rng(seed)
        self.w = rng.normal(0, 0.01, self.dim)
        self.b = 0.0
        for _ in range(self.epochs):
            p = 1 / (1 + np.exp(-(x @ self.w + self.b)))
            g = (p - y) * sw
            self.w -= self.lr * (x.T @ g / len(y) + self.l2 * self.w)
            self.b -= self.lr * float(g.mean())
        return self

    def score(self, texts: list[str]) -> np.ndarray:
        x = self._emb.embed(texts).astype(np.float64)
        return np.asarray(1 / (1 + np.exp(-(x @ self.w + self.b))), dtype=np.float64)

    def save(self, path: Path) -> None:
        np.savez(path, w=self.w, b=np.array([self.b]), dim=np.array([self.dim]))

    @classmethod
    def load(cls, path: Path) -> LiteClassifier:
        d = np.load(path)
        c = cls(dim=int(d["dim"][0]))
        c.w = d["w"]
        c.b = float(d["b"][0])
        return c


class OnnxClassifier:
    """Sequence classifier exported to ONNX. Directory: model.onnx, tokenizer.json, labels.json."""

    def __init__(self, directory: str, max_len: int = 512) -> None:
        import onnxruntime as ort
        from tokenizers import Tokenizer

        d = Path(directory)
        self._sess = ort.InferenceSession(str(d / "model.onnx"), providers=["CPUExecutionProvider"])
        self._tok = Tokenizer.from_file(str(d / "tokenizer.json"))
        self._tok.enable_truncation(max_len)
        self._tok.enable_padding()
        labels = (
            json.loads((d / "labels.json").read_text())
            if (d / "labels.json").exists()
            else ["benign", "injection"]
        )
        bad = {"injection", "malicious", "jailbreak", "unsafe", "label_1"}
        self._bad = [i for i, lab in enumerate(labels) if str(lab).lower() in bad] or [len(labels) - 1]
        self._inputs = {i.name for i in self._sess.get_inputs()}
        self.name = f"onnx:{d.name}"

    def score(self, texts: list[str]) -> np.ndarray:
        enc = self._tok.encode_batch([normalize(t) for t in texts])
        feed = {
            "input_ids": np.array([e.ids for e in enc], dtype=np.int64),
            "attention_mask": np.array([e.attention_mask for e in enc], dtype=np.int64),
        }
        if "token_type_ids" in self._inputs:
            feed["token_type_ids"] = np.zeros_like(feed["input_ids"])
        logits = self._sess.run(None, {k: v for k, v in feed.items() if k in self._inputs})[0]
        e = np.exp(logits - logits.max(axis=1, keepdims=True))
        probs = e / e.sum(axis=1, keepdims=True)
        return np.asarray(probs[:, self._bad].sum(axis=1), dtype=np.float64)
