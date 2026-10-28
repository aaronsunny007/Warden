"""Train a small L2 injection classifier from scratch in PyTorch and export it to ONNX.

This is the no-download counterpart of train_l2.py. It needs neither a Hugging Face base model nor
network access: the tokenizer is trained on the dev split and the model is a tiny Transformer
encoder. It produces exactly the directory the gateway's OnnxClassifier loads (model.onnx,
tokenizer.json, labels.json), so it exercises the full train -> export -> serve path.

It will not match a fine-tuned DeBERTa or PromptGuard 2 on out-of-distribution text: it only ever
sees this project's synthetic dev split. Treat it as a working, reproducible L2 and a test of the
ONNX serving path, not as a state-of-the-art detector.

Training uses ONLY the dev split (the test splits stay locked by corpus.py). Metrics are reported on
a stratified hold-out slice of dev, next to the always-available lite-logreg L2 on the same slice.

    uv pip install torch onnx onnxruntime onnxscript tokenizers scikit-learn
    python training/train_l2_scratch.py --out models/l2-scratch
    export WARDEN_L2_MODE=onnx WARDEN_L2_ONNX_DIR=$(pwd)/models/l2-scratch
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

LABELS = ["benign", "injection"]  # index 1 ("injection") is the "bad" class the cascade reads.
PAD, UNK = "[PAD]", "[UNK]"


def _load_dev() -> tuple[list[str], list[int]]:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python" / "src"))
    from warden.corpus import load

    examples = load(splits=("dev",), labels=("attack", "benign"))
    if not examples:
        raise SystemExit("no dev examples found; build the corpus first (python/scripts/build_corpus.py)")
    return [e.text for e in examples], [1 if e.label == "attack" else 0 for e in examples]


def _metrics(y_true: list[int], y_pred: list[int]) -> dict[str, float]:
    pairs = list(zip(y_true, y_pred, strict=True))
    tp = sum(1 for t, p in pairs if t == 1 and p == 1)
    fp = sum(1 for t, p in pairs if t == 0 and p == 1)
    fn = sum(1 for t, p in pairs if t == 1 and p == 0)
    tn = sum(1 for t, p in pairs if t == 0 and p == 0)
    n = max(1, len(y_true))
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {
        "accuracy": (tp + tn) / n,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
    }


def _train_tokenizer(texts: list[str], vocab_size: int, out: Path):  # type: ignore[no-untyped-def]
    from tokenizers import Tokenizer, models, normalizers, pre_tokenizers, trainers

    tok = Tokenizer(models.WordPiece(unk_token=UNK))
    tok.normalizer = normalizers.Sequence([normalizers.NFKC(), normalizers.Lowercase()])
    tok.pre_tokenizer = pre_tokenizers.BertPreTokenizer()
    trainer = trainers.WordPieceTrainer(vocab_size=vocab_size, special_tokens=[PAD, UNK], min_frequency=2)
    tok.train_from_iterator(texts, trainer)
    tok.save(str(out / "tokenizer.json"))
    return tok


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="models/l2-scratch")
    ap.add_argument("--epochs", type=int, default=12)
    ap.add_argument("--batch-size", type=int, default=32)
    ap.add_argument("--lr", type=float, default=2e-3)
    ap.add_argument("--max-len", type=int, default=160)
    ap.add_argument("--vocab", type=int, default=6000)
    ap.add_argument("--dim", type=int, default=96)
    ap.add_argument("--layers", type=int, default=2)
    ap.add_argument("--val-frac", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--opset", type=int, default=17)
    a = ap.parse_args()

    try:
        import numpy as np
        import torch
        from sklearn.model_selection import train_test_split
        from torch import nn
    except ImportError as e:
        raise SystemExit(f"missing dependency ({e}); see the install line in this file's docstring") from e

    torch.manual_seed(a.seed)
    texts, labels = _load_dev()
    tr_x, va_x, tr_y, va_y = train_test_split(
        texts, labels, test_size=a.val_frac, random_state=a.seed, stratify=labels
    )
    print(f"dev examples: {len(texts)}  (train {len(tr_x)}, hold-out {len(va_x)}; test splits untouched)")

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    tok = _train_tokenizer(tr_x, a.vocab, out)  # the tokenizer never sees the hold-out slice
    pad_id = tok.token_to_id(PAD)
    tok.enable_truncation(a.max_len)
    tok.enable_padding(pad_id=pad_id, pad_token=PAD)

    def encode(batch: list[str]):  # type: ignore[no-untyped-def]
        enc = tok.encode_batch(batch)
        ids = torch.tensor([e.ids for e in enc], dtype=torch.long)
        mask = torch.tensor([e.attention_mask for e in enc], dtype=torch.long)
        return ids, mask

    class Classifier(nn.Module):  # type: ignore[misc]
        def __init__(self) -> None:
            super().__init__()
            self.emb = nn.Embedding(tok.get_vocab_size(), a.dim, padding_idx=pad_id)
            self.pos = nn.Embedding(a.max_len, a.dim)
            layer = nn.TransformerEncoderLayer(
                d_model=a.dim,
                nhead=4,
                dim_feedforward=a.dim * 2,
                dropout=0.1,
                batch_first=True,
                norm_first=True,
            )
            self.enc = nn.TransformerEncoder(layer, num_layers=a.layers, enable_nested_tensor=False)
            self.norm = nn.LayerNorm(a.dim)
            self.head = nn.Linear(a.dim, 2)

        def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
            pos = torch.arange(input_ids.shape[1], device=input_ids.device).unsqueeze(0)
            h = self.emb(input_ids) + self.pos(pos)
            h = self.enc(h, src_key_padding_mask=attention_mask == 0)
            m = attention_mask.unsqueeze(-1).to(h.dtype)
            pooled = (self.norm(h) * m).sum(1) / m.sum(1).clamp(min=1.0)  # masked mean pool
            return self.head(pooled)

    model = Classifier()
    y_all = torch.tensor(tr_y)
    weights = torch.tensor(
        [len(tr_y) / (2 * max(1, (y_all == c).sum().item())) for c in (0, 1)], dtype=torch.float
    )
    loss_fn = nn.CrossEntropyLoss(weight=weights)
    opt = torch.optim.AdamW(model.parameters(), lr=a.lr, weight_decay=0.01)
    steps = a.epochs * ((len(tr_x) + a.batch_size - 1) // a.batch_size)
    sched = torch.optim.lr_scheduler.OneCycleLR(opt, max_lr=a.lr, total_steps=steps)

    def predict(xs: list[str]) -> np.ndarray:
        model.eval()
        probs = []
        with torch.no_grad():
            for i in range(0, len(xs), 128):
                ids, mask = encode(xs[i : i + 128])
                probs.append(torch.softmax(model(ids, mask), dim=-1)[:, 1].numpy())
        return np.concatenate(probs)

    g = torch.Generator().manual_seed(a.seed)
    for epoch in range(a.epochs):
        model.train()
        order = torch.randperm(len(tr_x), generator=g).tolist()
        total = 0.0
        for i in range(0, len(order), a.batch_size):
            idx = order[i : i + a.batch_size]
            ids, mask = encode([tr_x[j] for j in idx])
            loss = loss_fn(model(ids, mask), torch.tensor([tr_y[j] for j in idx]))
            opt.zero_grad()
            loss.backward()
            opt.step()
            sched.step()
            total += loss.item() * len(idx)
        va = _metrics(va_y, (predict(va_x) >= 0.5).astype(int).tolist())
        print(
            f"epoch {epoch + 1:>2}/{a.epochs}  train_loss={total / len(tr_x):.4f}  holdout_f1={va['f1']:.4f}"
        )

    # --- hold-out metrics, next to the always-available lite-logreg on the same slice -----------
    nn_m = _metrics(va_y, (predict(va_x) >= 0.5).astype(int).tolist())
    from warden.detector.classifier import LiteClassifier

    lite = LiteClassifier().fit(tr_x, tr_y)
    lite_m = _metrics(va_y, (lite.score(va_x) >= 0.5).astype(int).tolist())

    # --- export, then prove the served model agrees with the trained one ------------------------
    model.eval()
    ids, mask = encode(["export probe " + va_x[0], va_x[1]])
    from torch.export import Dim

    batch, seq = Dim("batch", min=1, max=1024), Dim("seq", min=2, max=a.max_len)
    # The dynamo exporter keeps batch and sequence length dynamic; the legacy tracer bakes the
    # example's sequence length into the attention reshape and breaks on any other length.
    torch.onnx.export(
        model,
        (ids, mask),
        str(out / "model.onnx"),
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_shapes={"input_ids": {0: batch, 1: seq}, "attention_mask": {0: batch, 1: seq}},
        opset_version=a.opset,
        dynamo=True,
    )
    (out / "labels.json").write_text(json.dumps(LABELS))

    from warden.detector.classifier import OnnxClassifier

    served = OnnxClassifier(str(out)).score(va_x)
    drift = float(np.abs(served - predict(va_x)).max())
    served_m = _metrics(va_y, (served >= 0.5).astype(int).tolist())

    report = {
        "note": "metrics are on a stratified hold-out slice of the DEV split, not the locked test set",
        "holdout_size": len(va_x),
        "scratch_transformer_torch": nn_m,
        "scratch_transformer_onnx_served": served_m,
        "lite_logreg_same_slice": lite_m,
        "max_torch_vs_onnx_probability_drift": drift,
        "config": {k: getattr(a, k) for k in ("epochs", "lr", "max_len", "vocab", "dim", "layers", "seed")},
    }
    (out / "report.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    if drift > 1e-3:
        print(f"WARNING: torch vs ONNX drift {drift:.2e} exceeds 1e-3", file=sys.stderr)
        return 1
    print(f"\nwrote {out}/ (model.onnx, tokenizer.json, labels.json, report.json)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
