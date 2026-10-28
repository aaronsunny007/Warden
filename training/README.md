# L2 classifier training (PyTorch → ONNX)

`train_l2.py` fine-tunes a small transformer to detect prompt-injection text and exports it to the
ONNX bundle the detection cascade loads (`model.onnx`, `tokenizer.json`, `labels.json`). L2 is the
middle of the cascade — **L0 rules → L1 embedding kNN → L2 classifier → L3 LLM judge**. A stronger
L2 lowers how often the expensive L3 judge is consulted; it does not replace the other layers.

## Honesty / leakage

- Training uses **only the dev split**. The `test_iid` / `test_ood` splits stay locked by
  `warden.corpus` (they need `WARDEN_UNLOCK_TEST=1`), so this script cannot train on them.
- Metrics printed here are on a **stratified hold-out slice of dev**, clearly labelled as such.
  The locked test set is scored once, later, by the evaluation harness — not here.

## Run

```bash
uv pip install -e 'python[train]'        # torch, transformers, datasets, scikit-learn, onnx
python training/train_l2.py --model microsoft/deberta-v3-xsmall --epochs 3 --out models/l2-onnx

# wire it into the detector
export WARDEN_L2_MODE=onnx WARDEN_L2_ONNX_DIR=$(pwd)/models/l2-onnx
```

Any Hugging Face sequence-classification base works (`--model`); `deberta-v3-xsmall` is a good CPU
default. Meta's **PromptGuard 2**, exported to the same three-file layout, is a drop-in alternative
(the cascade's `OnnxClassifier` already recognises its label names).

> `train_l2.py` downloads a base model from Hugging Face, so it needs network access to it and the
> `train` extra; it is run by you, not in CI. Without an ONNX bundle the cascade falls back to the
> always-available `lite-logreg` L2, so nothing here is required to run Warden.

## No-download path: `train_l2_scratch.py`

Where Hugging Face is unreachable (air-gapped, or a restrictive egress policy), `train_l2_scratch.py`
trains a tiny 2-layer Transformer encoder from scratch in PyTorch, with a WordPiece tokenizer trained
on the dev split, and exports the same three-file ONNX bundle:

```bash
uv pip install torch onnx onnxruntime onnxscript tokenizers scikit-learn
python training/train_l2_scratch.py --out models/l2-scratch
export WARDEN_L2_MODE=onnx WARDEN_L2_ONNX_DIR=$(pwd)/models/l2-scratch
```

It checks its own export: the ONNX model is loaded back through the gateway's real `OnnxClassifier`
and compared with the PyTorch model on the hold-out slice (the script fails if probabilities drift
by more than 1e-3). The dynamo exporter is used because the legacy tracer bakes the example
sequence length into the attention reshape, which broke the first attempt at any other length.

**Measured (one run, seed 0; stratified hold-out of the DEV split, n=56, synthetic data):**

| L2 model | accuracy | precision | recall | F1 | FPR |
| --- | --- | --- | --- | --- | --- |
| scratch Transformer (PyTorch) | 0.964 | 0.960 | 0.960 | 0.960 | 0.032 |
| scratch Transformer (ONNX, served) | 0.964 | 0.960 | 0.960 | 0.960 | 0.032 |
| lite-logreg (same slice) | 0.982 | 0.962 | 1.000 | 0.980 | 0.032 |

Torch-vs-ONNX maximum probability drift: 1.8e-7. **The scratch model does not beat lite-logreg**
(the difference is one example in 56, i.e. noise), and it has only ever seen this project's synthetic
dev text, so it says nothing about out-of-distribution robustness. Its purpose is a working,
reproducible train → export → serve path. A fine-tuned `deberta-v3-xsmall` or PromptGuard 2 is the
route to a genuinely stronger L2.
