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

> This script downloads a base model and needs the `train` extra, so it is run offline by you, not
> in CI; it is syntax- and lint-clean in this repo. Without the ONNX bundle the cascade falls back
> to the always-available `lite-logreg` L2, so nothing here is required to run Warden.
