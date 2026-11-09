# Fresh locked test splits (round 2)

The synthetic splits and the first public split (`../public_deepset_test.jsonl`, deepset test) are spent. This
directory holds two new test splits, built and hash-committed **before any model is trained on the new data**.
Round 1 showed the detector generalises poorly beyond the 405-example hand-written corpus; round 2 tests whether
training on much more varied public data fixes that.

| Split | Source (test file only) | Rows | Why it is in the protocol |
| --- | --- | --- | --- |
| `neuralchemy_test.jsonl` | [neuralchemy/Prompt-injection-dataset](https://huggingface.co/datasets/neuralchemy/Prompt-injection-dataset) `core/test`, rev `7d70432` | 942 (552 attack, 390 benign) | same collection as part of the training data: how well it learns what it is shown |
| `jackhhao_test.jsonl` | [jackhhao/jailbreak-classification](https://huggingface.co/datasets/jackhhao/jailbreak-classification) `default` test, rev `2f2ceeb` | 393 (137 attack, 256 benign) | **never trained on, different collection and style (long jailbreak prompts)**: the cross-dataset check |

Both Apache-2.0 (attribution in `NOTICE.md`). Rebuild with `../build_fresh_splits.py`; source hashes are pinned.
Build-time guards: exact (whitespace/case-normalised) duplicates inside a split, and any row that also appears in a
training source or in the spent deepset test, are dropped (jackhhao: 1 duplicate and 6 train overlaps dropped;
neuralchemy: none). Commitment: `LOCKED.sha256`, one line per split (hash of sorted ids).

## Protocol (fixed before training)

- **Training pool:** the project's dev corpus + deepset `train` + neuralchemy `core/train`. Nothing from
  jackhhao is trained on. The deepset **test** file is never trained on and is not used to choose anything.
- **Tuning and model selection:** neuralchemy `core/validation` and a hold-out of the dev corpus only. The two fresh
  test splits are not looked at until the end.
- **Variants:** (a) *before*: the current dev-corpus-only lite classifier and DeBERTa bundle; (b) *after*: lite
  classifier and DeBERTa-xsmall retrained on the pool (DeBERTa settings fixed now: `--max-len 96 --epochs 3 --lr 5e-5`,
  pinned torch 2.8.0 / transformers 4.56.2, no NaN allowed). Each scored as full cascade and L2-only, channel `output`,
  same cascade configuration as round 1 (L1 and L3 off).
- **Metrics:** attack blocked / flagged and benign blocked / flagged with Wilson 95% intervals, per split.
- Each split is scored once with a write-once output file. No threshold, rule, model or training choice is changed
  after seeing these numbers; a worse result is reported as it is.

## Caveats stated in advance

- Most public data is user-style prompts and jailbreaks, not tool-output injections: this measures the text
  classifier, not end-to-end agent safety and not a simulated-victim result.
- neuralchemy contains obfuscated and templated text and is partly derived from other benchmarks (e.g. HackAPrompt), so a
  high `neuralchemy_test` score is expected and says little about unseen styles. `jackhhao_test` is the honest check.
- English only here; the round-1 deepset data had German.
