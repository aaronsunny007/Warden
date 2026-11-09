# Tool-output injection set

720 items (360 attacks, 360 benign) shaped like what an agent actually reads back from tools: emails, support
tickets, CRM JSON records, CSV rows, chat logs, calendar entries, READMEs, log lines, search results, PDF text and
web pages. Public prompt-injection datasets are mostly user prompts; this set is about *tool outputs*.

## What it is not

It is **synthetic and written by the same project that wrote the detector**. It is not independent, it was not
collected from real incidents, and the templates share vocabulary with the detector's own training corpus. A good
score here means "handles these templates", never "works in the wild". It is released so others can run their own
detector on it, extend the generator and find the gaps.

## Contents

- Attacks: 6 goals (exfiltration, payments, policy change, prompt leak, destructive actions, tool pivots) dressed
  in 12 plain-text techniques (override, fake authority, fake role tags, polite P.S., compliance pressure, delayed
  trigger, zero-width and Unicode-tag smuggling, base64, other languages, markdown-image exfiltration) and 5
  HTML-hiding techniques (`display:none`, comment, white text, 1px text, off-screen).
- Benign: ordinary business content plus **hard negatives** that look risky but are fine: security advisories that
  quote attack strings, emails that tell a *human* to forward an invoice, setup instructions, policy text, and
  legitimate refund requests.
- Fields: `id, text, label, carrier, technique, goal, format (text|html), hard_negative`.

## Protocol (fixed before any score exists)

1. `python build_toolout.py` is deterministic (seeded) and writes `toolout.jsonl` and `LOCKED.sha256` (id
   commitment and file hash). Both are committed before scoring.
2. `WARDEN_UNLOCK_TOOLOUT=1 warden eval toolout` verifies the lock, scores the default stack once and refuses to
   overwrite its output (`docs/results/toolout.{json,md}`). Nothing is tuned against it afterwards; if the set is
   regenerated with changes it is a new set with a new commitment.
3. Two views are reported: the cascade on the raw text, and the full pipeline (hidden-content scan first, so HTML
   hidden text and invisible-character payloads are decoded before the cascade reads them).
4. The rules layer (L0, TypeScript) is not part of this score; this measures the Python cascade and the hidden scan.
5. Every number is reported with its failures, including by technique and by hard-negative kind.
