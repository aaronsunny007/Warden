"""Build the static documentation site published to GitHub Pages.

    python site/build_site.py <out_dir> [path/to/report.pdf]

Renders README and docs/*.md to HTML, summarises the locked-test result from docs/results, and copies the
compiled report. It is a documentation site, not a deployment of the gateway.
"""

from __future__ import annotations

import html
import json
import shutil
import sys
from pathlib import Path

import markdown

ROOT = Path(__file__).resolve().parent.parent
PAGES = [
    ("README.md", "index-readme", "Overview"),
    ("docs/DESIGN.md", "design", "Design"),
    ("docs/THREAT_MODEL.md", "threat-model", "Threat model"),
    ("docs/OWASP_MAPPING.md", "owasp-mapping", "OWASP mapping"),
    ("docs/DECISIONS.md", "decisions", "Decisions (ADRs)"),
    ("docs/results/rq1-simulated.md", "rq1-simulated", "RQ1 results (simulated victim)"),
]
CSS = """
:root{color-scheme:light dark;--bg:#fff;--fg:#1d2127;--muted:#5c6773;--line:#d8dde3;--accent:#0b5cad;--warn:#fff4d6;--warnfg:#5a4300}
@media (prefers-color-scheme:dark){:root{--bg:#14171b;--fg:#e4e8ec;--muted:#9aa5b1;--line:#2d343c;--accent:#6db3ff;--warn:#3a2f10;--warnfg:#f3deaa}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 system-ui,sans-serif}
header,main{max-width:60rem;margin:0 auto;padding:0 16px}
header{padding-top:16px;padding-bottom:8px;border-bottom:1px solid var(--line)}
nav a{margin-right:14px;color:var(--accent);text-decoration:none;white-space:nowrap;display:inline-block}
.banner{background:var(--warn);color:var(--warnfg);padding:10px 14px;border-radius:6px;margin:16px 0}
table{border-collapse:collapse;display:block;overflow-x:auto}th,td{border:1px solid var(--line);padding:4px 8px;text-align:left}
pre{overflow-x:auto;padding:10px;border:1px solid var(--line);border-radius:6px}code{font-size:.92em}
a{color:var(--accent)}img{max-width:100%}
"""
BANNER = (
    '<div class="banner"><strong>Documentation site, not a deployment.</strong> Warden is a gateway you run '
    "yourself; nothing here is a hosted service. Attack-success numbers use a <strong>simulated victim agent</strong>, "
    "not a real language model.</div>"
)


def shell(title: str, body: str, nav: str) -> str:
    return (
        f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
        f'<meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)}</title>'
        f"<style>{CSS}</style></head><body><header><strong>Warden</strong><br><nav>{nav}</nav></header>"
        f"<main>{BANNER}{body}</main></body></html>"
    )


def locked_summary() -> str:
    src = ROOT / "docs/results/locked-test.json"
    if not src.exists():
        return "<p>The locked test split has not been scored yet.</p>"
    d = json.loads(src.read_text())
    names = {
        "cascade_full": "Cascade, lite L2",
        "cascade_full+scratch": "Cascade + scratch L2",
        "l2_only+scratch": "Scratch L2 alone",
        "cascade_full+deberta": "Cascade + DeBERTa L2",
        "l2_only+deberta": "DeBERTa L2 alone",
    }

    def cell(m: dict) -> str:
        lo, hi = m["ci95"]
        return f"{m['rate'] * 100:.1f}% [{lo * 100:.1f}, {hi * 100:.1f}] ({m['hits']}/{m['n']})"

    rows = "".join(
        f"<tr><td>{n}</td><td>{cell(d[k]['test_iid']['attack_blocked'])}</td>"
        f"<td>{cell(d[k]['test_iid']['benign_blocked'])}</td><td>{cell(d[k]['test_ood']['attack_blocked'])}</td></tr>"
        for k, n in names.items()
        if k in d
    )
    return (
        "<h2>Locked test split (scored once)</h2><table><tr><th>Detector</th><th>iid attacks blocked</th>"
        f"<th>iid benign blocked</th><th>OOD attacks blocked</th></tr>{rows}</table>"
        "<p>Wilson 95% intervals. The DeBERTa fine-tune in this run failed to train; see the report.</p>"
    )


def main() -> int:
    out = Path(sys.argv[1])
    pdf = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    out.mkdir(parents=True, exist_ok=True)
    nav = '<a href="./">Home</a>' + "".join(
        f'<a href="{slug}.html">{label}</a>' for _, slug, label in PAGES if slug != "index-readme"
    )
    if pdf and pdf.exists():
        shutil.copy(pdf, out / "warden-report.pdf")
        nav += '<a href="warden-report.pdf">Report (PDF)</a>'
    for src, slug, label in PAGES:
        text = (ROOT / src).read_text()
        for s_, slug_, _ in PAGES:  # point links between the rendered pages at the site's own files
            text = text.replace(f"]({s_})", f"]({slug_}.html)").replace(f"]({s_.split('/')[-1]})", f"]({slug_}.html)")
        body = markdown.markdown(text, extensions=["tables", "fenced_code"])
        (out / f"{slug}.html").write_text(shell(label, body, nav))
    home = (
        "<h1>Warden</h1><p>A validation-gated, self-improving security gateway between AI agents and MCP tool "
        "servers.</p><ul><li><a href=\"warden-report.pdf\">The report (PDF)</a></li>"
        "<li><a href=\"design.html\">Design</a> · <a href=\"threat-model.html\">Threat model</a> · "
        "<a href=\"decisions.html\">Decisions</a> · <a href=\"owasp-mapping.html\">OWASP mapping</a></li>"
        "<li><a href=\"index-readme.html\">Full README</a></li>"
        '<li><a href="https://github.com/aaronsunny007/Warden">Source on GitHub</a></li></ul>'
        + locked_summary()
    )
    (out / "index.html").write_text(shell("Warden", home, nav))
    (out / ".nojekyll").write_text("")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
