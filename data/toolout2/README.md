# Tool-output injection set v2 (independent)

Why this exists: the v1 set (`data/toolout`) was written by the same project as the detector, scored once and is spent.
v2 is assembled mostly from material this project did not write.

| part | source | who wrote the text |
|---|---|---|
| attacks | InjecAgent (Zhan et al., 2024; `uiuc-kang-lab/InjecAgent`), 4 test-case files, pinned by SHA-256 in `SOURCES.sha256` | third party: 62 distinct attacker instructions inside many tool-response templates (reviews, emails, notes, files...), plus an "enhanced" variant with an override prefix |
| encoded attacks | the same attacker instructions put into the same templates as base64, zero-width bits or Unicode tag characters | this project's `encode()`, so the encodings are mine, the instructions are not |
| benign documents | README / CHANGELOG text of the npm packages pinned in `pnpm-lock.yaml` (windows of up to ~1500 characters) | third party |
| benign tool outputs | the same InjecAgent templates, with the attacker slot filled by an ordinary README paragraph | third party template + third party prose |
| hard negatives | 33 templates (requests to a human, tickets, advisories that quote attacks, setup steps, meeting notes, chat, policy, logs, reviews), filled from small name lists | **this project**; reported separately (`hard-*`) |

## Splits

Everything is assigned to **train / dev / test** (40 / 20 / 40) by hash of its *group*, so nothing is shared across splits:
an attacker instruction (and every template variant of it) lives in one split only, and so does an npm package. Hard-negative
templates are spread by position (2 in 5 train, 1 dev, 2 test). Train may fit a model, dev is what changes were developed
against, **test is hash-committed in `LOCKED.sha256` before it was scored and is scored once**.

The third-party text is not committed. The repo holds the builder (`build_toolout2.py`), the source hashes and
`manifest.<split>.txt` (an id and a SHA-256 per item). `warden eval heldout3` rebuilds the test items and refuses to run if
a single hash differs. The documents need `pnpm install --frozen-lockfile` so the packages match the lockfile.

## What a score on this set means, and does not

- It measures how the detector handles **attacker instructions, packages and templates it has not seen**, inside the same
  families it was trained on. The InjecAgent instructions share one style (a polite request to use a tool for the user), so a
  good score does not mean "robust to any injection".
- The benign documents are developer documentation, not emails or tickets, and the train and test packages come from the same
  kind of source. The false-block rate on documents is therefore an in-distribution estimate for READMEs. The `hard-*` rows
  are the only emails/tickets/chat-style benign text, and I wrote them.
- 62 instructions is small: the test split has about 25 of them, each in many templates, so attacks are far from independent.
  Wilson intervals treat them as independent and are too narrow.
- Training on the train split is how the shipped lite classifier (`models/lite-l2-docs.npz`) and the pooled DeBERTa were
  fitted. Dev decided window size (64 words), the lite hyper-parameters, and that the L1 out-of-distribution gate stays off.

## Protocol

1. `python data/toolout2/build_toolout2.py --lock` writes the splits and `LOCKED.sha256` (commitment to the test ids and to the
   per-item hash manifest). It was committed before any score existed.
2. `WARDEN_UNLOCK_HELDOUT3=1 warden eval heldout3` verifies the commitment, scores three variants once and refuses to overwrite
   `docs/results/heldout3.{json,md}`.
3. Nothing is tuned against the result. A different test set would be a new set with a new commitment.
