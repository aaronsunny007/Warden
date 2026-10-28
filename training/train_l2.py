"""Fine-tune the L2 injection classifier and export it to ONNX for the detection cascade.

This produces the directory the gateway's OnnxClassifier loads (model.onnx, tokenizer.json,
labels.json) when WARDEN_L2_MODE=onnx and WARDEN_L2_ONNX_DIR points at it. The L2 layer is only
the middle of the cascade (L0 rules → L1 kNN → L2 classifier → L3 judge); a strong L2 lowers how
often the expensive L3 judge is consulted, it does not replace the rest.

Training uses ONLY the dev split (the test splits stay locked by corpus.py). It reports honest
held-out metrics on a stratified validation slice of dev — not on the locked test set, which is
scored once, later, by the evaluation harness.

Install the training extra first:  uv pip install -e 'python[train]'   (torch, transformers, ...)

    python training/train_l2.py --model microsoft/deberta-v3-xsmall --epochs 3 --out models/l2-onnx

Then point the detector at it:
    export WARDEN_L2_MODE=onnx WARDEN_L2_ONNX_DIR=$(pwd)/models/l2-onnx
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

LABELS = ["benign", "injection"]  # index 1 ("injection") is the "bad" class the cascade reads.


def _load_dev() -> tuple[list[str], list[int]]:
    """Dev-split texts and 0/1 labels, from the repo corpus (test splits stay locked)."""
    # Import lazily so --help works without the warden package importable.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python" / "src"))
    from warden.corpus import load

    examples = load(splits=("dev",), labels=("attack", "benign"))
    if not examples:
        raise SystemExit("no dev examples found; build the corpus first (python/scripts/build_corpus.py)")
    texts = [e.text for e in examples]
    labels = [1 if e.label == "attack" else 0 for e in examples]
    return texts, labels


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
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {"accuracy": (tp + tn) / n, "precision": prec, "recall": rec, "f1": f1, "fpr": fpr}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", default="microsoft/deberta-v3-xsmall", help="HF base model to fine-tune")
    ap.add_argument("--out", default="models/l2-onnx", help="output directory for the ONNX bundle")
    ap.add_argument("--epochs", type=float, default=3.0)
    ap.add_argument("--batch-size", type=int, default=16)
    ap.add_argument("--lr", type=float, default=2e-5)
    ap.add_argument("--max-len", type=int, default=256)
    ap.add_argument("--val-frac", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--opset", type=int, default=17)
    a = ap.parse_args()

    try:
        import torch
        from sklearn.model_selection import train_test_split
        from torch.utils.data import DataLoader, Dataset
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
    except ImportError as e:  # pragma: no cover - depends on the optional train extra
        raise SystemExit(
            f"missing training dependency ({e}); install with: uv pip install -e 'python[train]'"
        ) from e

    torch.manual_seed(a.seed)
    texts, labels = _load_dev()
    x_tr, x_val, y_tr, y_val = train_test_split(
        texts, labels, test_size=a.val_frac, random_state=a.seed, stratify=labels
    )
    print(f"dev: {len(texts)} examples ({sum(labels)} injection); train={len(x_tr)} val={len(x_val)}")

    tok = AutoTokenizer.from_pretrained(a.model)
    model = AutoModelForSequenceClassification.from_pretrained(
        a.model,
        num_labels=2,
        id2label=dict(enumerate(LABELS)),
        label2id={name: i for i, name in enumerate(LABELS)},
    )
    device = "cuda" if torch.cuda.is_available() else "cpu"
    model.to(device)

    class DS(Dataset):  # type: ignore[misc]
        def __init__(self, xs: list[str], ys: list[int]) -> None:
            self.enc = tok(xs, truncation=True, max_length=a.max_len, padding="max_length")
            self.ys = ys

        def __len__(self) -> int:
            return len(self.ys)

        def __getitem__(self, i: int) -> dict[str, torch.Tensor]:
            item = {k: torch.tensor(v[i]) for k, v in self.enc.items()}
            item["labels"] = torch.tensor(self.ys[i])
            return item

    train_dl = DataLoader(DS(x_tr, y_tr), batch_size=a.batch_size, shuffle=True)
    opt = torch.optim.AdamW(model.parameters(), lr=a.lr)

    steps = max(1, int(a.epochs * len(train_dl)))
    model.train()
    step = 0
    for _epoch in range(int(a.epochs) + 1):
        for batch in train_dl:
            if step >= steps:
                break
            batch = {k: v.to(device) for k, v in batch.items()}
            opt.zero_grad()
            out = model(**batch)
            out.loss.backward()
            opt.step()
            if step % 20 == 0:
                print(f"  step {step}/{steps} loss={out.loss.item():.4f}")
            step += 1

    # Held-out validation (dev slice only; the locked test set is scored later by the harness).
    model.eval()
    preds: list[int] = []
    with torch.no_grad():
        for i in range(0, len(x_val), a.batch_size):
            chunk = x_val[i : i + a.batch_size]
            enc = tok(chunk, truncation=True, max_length=a.max_len, padding=True, return_tensors="pt")
            enc = {k: v.to(device) for k, v in enc.items()}
            logits = model(**enc).logits
            preds.extend(logits.argmax(-1).cpu().tolist())
    m = _metrics(y_val, preds)
    print("validation (dev hold-out): " + json.dumps({k: round(v, 4) for k, v in m.items()}))

    # Export to ONNX. The cascade's OnnxClassifier feeds input_ids + attention_mask and reads the
    # softmax probability of the "injection" class, so we export exactly those inputs.
    out_dir = Path(a.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    model.cpu().eval()
    dummy = tok(["export sample"], truncation=True, max_length=a.max_len, padding="max_length", return_tensors="pt")
    torch.onnx.export(
        model,
        (dummy["input_ids"], dummy["attention_mask"]),
        str(out_dir / "model.onnx"),
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch", 1: "seq"},
            "attention_mask": {0: "batch", 1: "seq"},
            "logits": {0: "batch"},
        },
        opset_version=a.opset,
        do_constant_folding=True,
    )
    # The cascade loads tokenizer.json with the `tokenizers` library, so save the fast backend.
    tok.backend_tokenizer.save(str(out_dir / "tokenizer.json"))
    (out_dir / "labels.json").write_text(json.dumps(LABELS))
    (out_dir / "metrics.json").write_text(json.dumps({"base_model": a.model, "val": m}, indent=2))

    try:
        import onnx

        onnx.checker.check_model(str(out_dir / "model.onnx"))
        print("onnx.checker: model is well-formed")
    except ImportError:
        pass
    print(f"wrote {out_dir}/ (model.onnx, tokenizer.json, labels.json, metrics.json)")
    print("point the detector at it: WARDEN_L2_MODE=onnx WARDEN_L2_ONNX_DIR=" + str(out_dir.resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
