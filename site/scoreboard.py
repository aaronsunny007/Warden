"""The scoreboard page: every scored result in the repo, the rules they were scored under, and a check, run
at build time from the committed files, that each locked test set still matches the commitment made before it
was scored. Standard library only, so the Pages build does not need the Python package.

A row is only as good as the set behind it, and the page says which sets are the project's own writing.
"""

from __future__ import annotations

import hashlib
import html
import json
from pathlib import Path
from typing import Any

SPENT = "scored once; spent, never tuned against"


def _ids(path: Path, only_test: bool = False) -> list[str]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            if not only_test or str(r["split"]).startswith("test"):
                out.append(r["id"])
    return out


def _digest(ids: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(ids)).encode()).hexdigest()


def _committed(lock: Path, name: str | None = None) -> str:
    for line in lock.read_text().splitlines():
        parts = line.split()
        if parts and (name is None or (len(parts) > 1 and parts[1] == name)):
            return parts[0]
    return ""


def checks(root: Path) -> list[dict[str, str]]:
    """Recompute each commitment from the committed data. Returns one row per locked set."""
    d = root / "data"
    rows: list[tuple[str, str, str, str]] = []
    try:
        corpus = _digest(_ids(d / "corpus" / "attacks.jsonl", True) + _ids(d / "corpus" / "benign.jsonl", True))
        rows.append(("Project corpus test split (iid + OOD)", "synthetic, written by this project", corpus, _committed(d / "corpus" / "LOCKED.sha256")))
        rows.append(("deepset/prompt-injections test", "public dataset", _digest(_ids(d / "heldout" / "public_deepset_test.jsonl")), _committed(d / "heldout" / "LOCKED.sha256")))
        for split, label in (("neuralchemy_test", "neuralchemy/Prompt-injection-dataset test"), ("jackhhao_test", "jackhhao/jailbreak-classification test")):
            rows.append((label, "public dataset", _digest(_ids(d / "heldout" / "fresh" / f"{split}.jsonl")), _committed(d / "heldout" / "fresh" / "LOCKED.sha256", split)))
        rows.append(("Tool-output injection set (ids)", "synthetic, written by this project", _digest(_ids(d / "toolout" / "toolout.jsonl")), _committed(d / "toolout" / "LOCKED.sha256", "ids")))
        rows.append(("Tool-output injection set (file)", "synthetic, written by this project", hashlib.sha256((d / "toolout" / "toolout.jsonl").read_bytes()).hexdigest(), _committed(d / "toolout" / "LOCKED.sha256", "toolout.jsonl")))
    except (OSError, ValueError, KeyError) as e:
        return [{"set": "verification", "author": "", "status": f"could not run: {type(e).__name__}", "digest": ""}]
    return [{"set": s, "author": a, "status": "match" if got == want and want else "MISMATCH", "digest": want} for s, a, got, want in rows]


def _rate(x: dict[str, Any] | None) -> tuple[float, float, float, int, int] | None:
    if not x or x.get("n") in (None, 0):
        return None
    lo, hi = (x["ci95"] if "ci95" in x else (x["low"], x["high"]))
    return x["rate"], lo, hi, x.get("hits", x.get("k", 0)), x["n"]


def friendly(key: str) -> str:
    """Readable names for the detector configurations that appear in the result files."""
    if key.startswith("label:"):
        return key[6:]
    head, _, tail = key.replace(":", "+", 1).partition("+")
    base = {"cascade_full": "Cascade (L1 + L2)", "l2_only": "L2 classifier alone"}.get(head, head)
    extra = {
        "": "lite L2",
        "lite": "lite L2",
        "lite+pool": "lite L2 + public pool",
        "scratch": "scratch-trained L2",
        "deberta": "DeBERTa L2 (diverged run, ignore)",
        "onnx+before": "DeBERTa L2, project data only",
        "onnx+after": "DeBERTa L2 + public pool (not the default)",
    }.get(tail, tail)
    return f"{base}, {extra}"


def _cell(x: dict[str, Any] | None, bad_high: bool) -> str:
    r = _rate(x)
    if r is None:
        return "<td>n/a</td>"
    rate, lo, hi, k, n = r
    worse = (rate >= 0.15) if bad_high else (rate < 0.5)
    cls = ' class="bad"' if worse else ""
    bar = f'<span class="bar"><i style="width:{rate * 100:.0f}%"></i></span>'
    return f"<td{cls}>{bar}{rate * 100:.1f}% <small>[{lo * 100:.1f}, {hi * 100:.1f}] {k}/{n}</small></td>"


def scores(root: Path) -> list[tuple[str, str, dict[str, Any], dict[str, Any] | None]]:
    """(set, detector, metrics, ood_metrics) for every committed result file."""
    res = root / "docs" / "results"
    out: list[tuple[str, str, dict[str, Any], dict[str, Any] | None]] = []

    def load(name: str) -> dict[str, Any] | None:
        p = res / name
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None

    if (d := load("locked-test.json")):
        for k, v in d.items():
            if isinstance(v, dict) and "test_iid" in v:
                out.append(("Project corpus (iid)", k, v["test_iid"], v.get("test_ood")))
    for fname, label in (("locked-public.json", "deepset (public)"), ("locked-fresh-neuralchemy_test.json", "neuralchemy (public)"), ("locked-fresh-jackhhao_test.json", "jackhhao (public)")):
        if (d := load(fname)):
            for k, v in d.items():
                if isinstance(v, dict) and "attack_blocked" in v:
                    out.append((label, k, v, None))
    if (d := load("toolout.json")):
        for k, label in (("raw_cascade", "cascade on raw text"), ("full_pipeline", "hidden scan + cascade")):
            if k in d:
                out.append(("Tool outputs (synthetic)", f"label:{label}", d[k], None))
    return out


CSS = """
.bar{display:inline-block;width:56px;height:8px;background:var(--line);border-radius:4px;margin-right:6px;vertical-align:middle;overflow:hidden}
.bar i{display:block;height:100%;background:var(--accent)} td.bad .bar i{background:#c0392b}
td.bad{background:color-mix(in srgb,#c0392b 10%,transparent)} small{color:var(--muted)}
.ok{color:#1e7e34;font-weight:600} .no{color:#c0392b;font-weight:700}
"""


def build(root: Path) -> str:
    ck = checks(root)
    ver = "".join(
        f"<tr><td>{html.escape(c['set'])}</td><td>{html.escape(c['author'])}</td>"
        f"<td class=\"{'ok' if c['status'] == 'match' else 'no'}\">{'✔ ' if c['status'] == 'match' else '✘ '}{html.escape(c['status'])}</td>"
        f"<td><code>{html.escape(c['digest'][:16])}</code></td></tr>"
        for c in ck
    )
    rows = ""
    for s, det, m, ood in scores(root):
        rows += (
            f"<tr><td>{html.escape(s)}</td><td>{html.escape(friendly(det))}</td>{_cell(m.get('attack_blocked'), False)}"
            f"{_cell(m.get('attack_flagged'), False)}{_cell(m.get('benign_blocked'), True)}{_cell(m.get('benign_flagged'), True)}</tr>"
        )
        if ood:
            rows += (
                f"<tr><td>{html.escape(s.replace("(iid)", "(out of distribution)"))}</td><td>{html.escape(friendly(det))}</td>{_cell(ood.get('attack_blocked'), False)}"
                f"{_cell(ood.get('attack_flagged'), False)}<td>n/a</td><td>n/a</td></tr>"
            )
    all_ok = bool(ck) and all(c["status"] == "match" for c in ck)
    verdict = (
        '<p class="ok">All locked sets match the commitments made before they were scored.</p>'
        if all_ok
        else '<p class="no">At least one locked set does not match its commitment. Do not trust the rows below until that is explained.</p>'
    )
    return f"""<style>{CSS}</style>
<h1>Scoreboard</h1>
<p>Every result Warden has produced on a held-out set, with the rules it was produced under. Bad numbers are shaded.
Nothing here is edited by hand: this page is generated from <code>docs/results/*.json</code> when the site is built,
and the table below is recomputed from the committed data at the same moment.</p>
<h2>The rules</h2>
<ol>
<li>Each test set's ids are hashed and the hash is committed <strong>before</strong> any training or scoring.</li>
<li>Scoring needs an unlock environment variable, refuses to overwrite its output, and happens once.</li>
<li>After it is scored a set is <strong>spent</strong>: it is never tuned against. Fixing a weakness needs a new set.</li>
<li>The protocol is written in the repository before the first score exists.</li>
<li>Sets that this project wrote itself are labelled so. They show how the detector handles those templates, not the wild.</li>
<li>Numbers for a simulated victim agent are labelled simulated everywhere they appear. None are on this page.</li>
</ol>
<h2>Do the commitments still hold?</h2>{verdict}
<table><tr><th>Set</th><th>Who wrote it</th><th>Recomputed vs committed</th><th>Committed hash</th></tr>{ver}</table>
<h2>Scores</h2>
<table><tr><th>Set</th><th>Detector</th><th>Attacks blocked</th><th>Attacks blocked or flagged</th><th>Benign wrongly blocked</th><th>Benign wrongly blocked or flagged</th></tr>{rows}</table>
<p><small>Wilson 95% intervals. "Flagged" means the verdict was suspicious or malicious. Rows differ in detector (lite or DeBERTa
classifier, with or without the public training pool), so read the detector column before comparing them. The earlier
DeBERTa row on the project corpus came from a model that failed to train; the report says so.</small></p>
<h2>What the numbers say</h2>
<ul>
<li>The detector separates attacks from benign text well on the project's own corpus and much worse on prompts from outside it.</li>
<li>Retraining on public data helped inside one collection and did not carry over to another; the DeBERTa model trained on the pool wrongly blocks about three quarters of benign prompts on one external set, so it is not the default.</li>
<li>On tool-output templates the default stack blocks about two thirds of attacks and wrongly blocks about a quarter of benign outputs.</li>
</ul>
<h2>Try your own detector</h2>
<p>The sets are public. <code>data/toolout/toolout.jsonl</code> and the splits under <code>data/heldout</code> are plain JSONL
(<code>id, text, label</code>); score any detector against them, report attacks blocked and benign wrongly blocked with
intervals, and say which set you used and its hash from the table above. There is no automatic submission service; results
sent as a pull request are reviewed by hand before they are listed.</p>"""
