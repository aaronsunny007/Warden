# Public held-out split: result (scored once)

Raw numbers: `locked-public.json` (write-once; do not edit or re-run). Split, protocol and commitment:
`data/heldout/README.md`. **Real, public, human-written prompts. This is not a simulated-victim (RQ2/RQ3) number.**

116 prompts from the `deepset/prompt-injections` test file (60 attack, 56 benign, mixed English and German),
never trained on, channel `output`. Configuration is the same as the earlier locked run: no embedder (L1 off),
no judge (L3 off), so "cascade" here is L0 rules plus L2. Wilson 95% intervals.

| Variant | Attack blocked | Attack flagged | Benign blocked | Benign flagged |
| --- | --- | --- | --- | --- |
| Cascade, lite L2 | 5/60 = 8.3% [3.6, 18.1] | 27/60 = 45.0% [33.1, 57.5] | 0/56 [0, 6.4] | 7/56 = 12.5% [6.2, 23.6] |
| L2 only, lite | 0/60 [0, 6.0] | 27/60 = 45.0% [33.1, 57.5] | 0/56 [0, 6.4] | 7/56 = 12.5% [6.2, 23.6] |
| Cascade, DeBERTa ONNX L2 | 5/60 = 8.3% [3.6, 18.1] | 12/60 = 20.0% [11.8, 31.8] | 0/56 [0, 6.4] | 0/56 [0, 6.4] |
| L2 only, DeBERTa ONNX | 0/60 [0, 6.0] | 9/60 = 15.0% [8.1, 26.1] | 0/56 [0, 6.4] | 0/56 [0, 6.4] |

## Reading it

- **The detector generalises poorly to this data.** Even the best variant flags under half of the attacks and
  blocks at most 8%. Every block comes from the L0 rules; no L2 variant blocks anything alone.
- The DeBERTa bundle is conservative: no benign flags, but it flags fewer attacks (15 to 20%) than the lite L2 (45%),
  which pays for it with 12.5% benign flags.
- This is consistent with the synthetic corpus being written by the same hands as the training data. The
  98%-class numbers on the synthetic splits do not carry over to other people's prompts, and the earlier OOD gap (see
  `locked-test.json`) understated the problem.
- The prompts are user-style instructions and role-play framings, not tool-output injections, and the cascade ran
  with L1 and L3 off. Treat this as a measure of the text classifier's generalisation, not of end-to-end safety.
- n = 116, so intervals are wide, but the gap to the synthetic numbers is far outside them.

## Provenance and deviations

- The DeBERTa bundle was trained locally under the pinned stack (torch 2.8.0, transformers 4.56.2) with the CI settings
  and reproduced the committed dev result exactly (F1 0.9796, no NaN). It is the healthy counterpart of the diverged
  model behind the committed `locked-test.json` DeBERTa rows, not that model.
- The from-scratch ONNX variant was not scored: its export fails on the pinned toolchain (recorded in the held-out README
  before scoring). No numbers exist for it on this split.
- Nothing was tuned against these numbers.
