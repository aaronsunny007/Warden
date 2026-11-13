# Public round 3

A public test set the detector had never seen, and one more public training source.

- **Test**: `jayavibhav/prompt-injection`, official *test* file only (`a5bd986`). Rows whose normalised text appears in any
  training source or in a spent test split are dropped (235 rows), then 500 attacks and 500 benign are drawn with a fixed seed.
- **Train**: `xTRam1/safe-guard-prompt-injection`, official *train* file only (`a3a877d`), deduplicated against the test file.
  Its test file is not used anywhere.
- Upstream licences are not stated, so the texts are not committed: this folder holds the builder, `SOURCES.sha256`, the test
  `ids.txt` and `LOCKED.sha256` (SHA-256 of `ids.txt`, committed before any score). `warden eval heldout3` rebuilds the test file from
  the pinned download and refuses to run if the ids differ.

## Read this before quoting a number

- The two datasets look related: their first benign rows are identical and 235 test rows were exact duplicates of training rows.
  The benign side is therefore close to in-distribution. The attack side (different generated injections) is the cross-dataset question.
- Short prompts, not tool outputs. Windowing and the document-aware training do not apply; this tests the text classifier.
- The shipped lite classifier was **not** trained on xTRam1 (adding the public pool to the lite model made documents much worse, see
  the CHANGELOG). The pooled DeBERTa was trained on it, so DeBERTa's score here is "same family of data", lite's is not.
- Scored once, never tuned against.
