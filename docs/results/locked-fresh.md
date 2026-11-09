# Round 2: fresh public test splits (each scored once)

Raw numbers: `locked-fresh-neuralchemy_test.json`, `locked-fresh-jackhhao_test.json` (write-once; do not edit or re-run).
Protocol, training pool and caveats, committed before training: `data/heldout/fresh/README.md`.
**Real, public prompts. Not simulated-victim (RQ2/RQ3) numbers.** Cascade configuration as in round 1 (L1 and L3 off),
channel `output`. Wilson 95% intervals in the JSON; point estimates here.

"Before" = classifiers trained on the 405-example corpus only. "After" = the same recipes retrained on the corpus plus
~4.9k public training rows (deepset train, neuralchemy train). The "before" DeBERTa is the healthy local retrain
(6 epochs, max-len 96), not the CI bundle. "After" DeBERTa: 3 epochs, max-len 96, no NaN, served-vs-torch drift 4.2e-7,
F1 0.975 on neuralchemy validation.

## neuralchemy test (942: 552 attack, 390 benign). Same collection as part of the training pool

| Classifier (full cascade) | Attacks blocked | Attacks flagged | Benign blocked | Benign flagged |
| --- | --- | --- | --- | --- |
| Lite, before | 8.0% | 42.2% | 1.5% | 36.7% |
| Lite, after | 24.6% | 91.5% | 1.5% | 39.0% |
| DeBERTa, before | 8.2% | 18.1% | 1.5% | 2.3% |
| DeBERTa, after | 88.9% | 90.0% | 5.6% | 5.9% |
| DeBERTa, after, L2 only | 97.3% | 98.4% | 5.1% | 5.6% |

## jackhhao test (393: 137 attack, 256 benign). Never trained on; different collection and style (long jailbreak and persona prompts)

| Classifier (full cascade) | Attacks blocked | Attacks flagged | Benign blocked | Benign flagged |
| --- | --- | --- | --- | --- |
| Lite, before | 70.1% | 98.5% | 16.4% | 86.3% |
| Lite, after | 70.1% | 100% | 16.4% | 97.3% |
| DeBERTa, before | 70.1% | 94.9% | 16.4% | 38.7% |
| DeBERTa, after | 99.3% | 100% | **75.8%** | **84.0%** |
| DeBERTa, after, L2 only | 99.3% | 100% | 71.1% | 84.0% |

## What this says

- **In-collection, training on more varied public data fixed recall.** The DeBERTa now blocks 89% of neuralchemy attacks
  (before: 8%) at 5.6% benign blocked. Expect this to be flattering: neuralchemy is partly templated and obfuscated and
  shares a source with its own training split.
- **It did not fix generalisation, and it made the cross-dataset false-positive rate much worse.** On jackhhao (never
  trained on) the retrained DeBERTa catches almost every attack but also blocks 76% and flags 84% of benign prompts,
  up from 16% blocked and 39% flagged. At that rate it would be unusable. The lite classifier flags 86 to 97% of
  benign prompts before and after. This model should not be promoted to the default.
- The L0 rules alone block 16.4% of jackhhao's benign prompts in every cascade variant (and about 70% of its attacks):
  long role-play and persona text trips them regardless of L2. That is a rules precision problem as well.
- jackhhao's "benign" class is long, persona-heavy instruction text, close in style to what the classifier learned to call
  an attack. Label noise cannot be ruled out, but the size of the shift is not explained by it alone.

## Caveats and deviations

- Train/serve mismatch: the DeBERTa models were trained with a 96-token cutoff but the gateway's `OnnxClassifier`
  serves up to 512 tokens by default. Round 1 had the same setting, and the protocol fixed the serving configuration
  before scoring, so it was not changed. It may well contribute to the long-prompt behaviour above; this has not been
  isolated. It can be tested on validation data (and on jackhhao's *train* file, which was never used), not on these test splits.
- The scratch variant was not run (export problem, see `data/heldout/README.md`).
- No threshold, rule, model or training choice was changed after seeing these numbers.
- Both splits are now spent. Any follow-up fix needs a new fresh cross-dataset test split.
