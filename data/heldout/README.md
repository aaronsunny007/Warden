# Public held-out split

A second locked split, added after the synthetic `test_iid` / `test_ood` splits were scored (and so
spent). Those splits were written by the same hands as the training data. This one is **public data
written by other people**, so it is a fairer out-of-distribution check.

| | |
| --- | --- |
| Source | [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections), the dataset's own **test** file |
| Revision | `4f61ecb038e9c3fb77e21034b22511b523772cdd` (parquet sha256 `39ac797c…b246e`) |
| Licence | Apache-2.0 (attribution in `NOTICE.md`) |
| Size | 116 prompts: 60 attack, 56 benign; mixed English and German |
| Overlap check | 0 exact (whitespace/case-normalised) matches against the 405 texts in `data/corpus/`, 0 internal duplicates |
| Commitment | `LOCKED.sha256`, the hash of the sorted example ids, committed **before** any model was scored on it |

Rebuild it with `build_public_split.py`; the pinned source hash makes the build fail loudly if the upstream
file ever changes.

## Protocol (fixed before scoring)

- Channel is `output` for every example (the corpus default and ~95% of the existing corpus).
- Variants scored: the lite L2 cascade, plus the scratch ONNX and DeBERTa ONNX L2 bundles. Each is scored as the
  full cascade and as L2-only, exactly as `eval locked` does.
- Metrics: attack blocked / flagged and benign blocked / flagged, with Wilson 95% intervals.
- Scored once with `WARDEN_UNLOCK_PUBLIC_HELDOUT=1 warden eval locked-public`. The output file is write-once.
  Re-scoring after seeing a result needs deleting that file, which is a visible act in the git history.
- No threshold, rule, model or training choice is tuned against these numbers.

## What this does and does not show

- Only the dev split of the synthetic corpus is used for training. This split is never trained on.
- 116 examples gives wide intervals. A low score here is a real finding about the detector, not a bug to fix by
  tuning on this split.
- The prompts are user-style requests and role-play framings, not tool-output injections, so this measures
  generalisation of the text classifier, not end-to-end agent safety. Do not read it as a victim-agent result.
