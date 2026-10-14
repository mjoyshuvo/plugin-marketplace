#!/usr/bin/env python3
"""Render findings (from scan.py or plugin_intake.py) into Markdown and a self-contained HTML page.

Usage:
    python render_report.py findings.json --md SECURITY-AUDIT.md --html security-audit.html \
        [--overrides overrides.json]

Every open finding shows where it lives: the file, the line numbers, the code block with
the hit lines marked, and (when known) the code to add. Snippets arrive already masked.

Reviewer answers and false-positive calls go in --overrides, a JSON map of check title (or
title prefix) to {"status": ..., "evidence": ...}. They are applied on every render, so
they survive a re-scan instead of being lost when findings.json is rewritten.

The HTML uses the house style from the teal-applegreen-offwhite-slide-deck skill: its
:root tokens, Plus Jakarta Sans + JetBrains Mono, and its building-block classes.
"""

import argparse
import html
import json
import os

ORDER = {"FAIL": 0, "WARN": 1, "MANUAL": 2, "PASS": 3, "NA": 4}
LABEL = {
    "FAIL": "FAIL",
    "WARN": "WARN",
    "PASS": "PASS",
    "MANUAL": "NEEDS ANSWER",
    "NA": "N/A",
}
MD_ICON = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌", "MANUAL": "📝", "NA": "➖"}
# Fixes that stop an active leak or compromise come first.
URGENT = (
    "hardcoded secret",
    ".env files committed",
    "literal secret",
    "hidden unicode",
    "bypass",
    "public registry",
    "check the author",
    "auto-approve",
    "privileged",
    "force push",
    "approval required",
    "hook",
    "new hooks",
)
LANG = {
    ".py": "python",
    ".json": "json",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".sh": "bash",
    ".md": "markdown",
    ".js": "javascript",
    ".ts": "typescript",
    ".toml": "toml",
    ".txt": "text",
}


def apply_overrides(r, path):
    if not path or not os.path.isfile(path):
        return r
    with open(path, encoding="utf-8") as fh:
        ov = json.load(fh)
    for c in r["categories"]:
        for x in c["checks"]:
            hit = ov.get(x["title"]) or next(
                (v for k, v in ov.items() if x["title"].startswith(k)), None
            )
            if hit:
                x.update(
                    {
                        k: v
                        for k, v in hit.items()
                        if k in ("status", "evidence", "fix", "suggestion")
                    }
                )
    return r


def recompute(r):
    order = {"FAIL": 4, "WARN": 3, "MANUAL": 2, "PASS": 1, "NA": 0}
    allc = []
    for c in r["categories"]:
        cs = c["checks"]
        for x in cs:
            x.setdefault("locations", [])
            x.setdefault("suggestion", "")
        auto = [x for x in cs if x["status"] in ("PASS", "WARN", "FAIL")]
        st = max((x["status"] for x in cs), key=lambda s: order[s], default="NA")
        c["status"] = "PASS" if st == "MANUAL" and auto else st
        c["score"] = (
            round(
                100
                * sum(
                    1 if x["status"] == "PASS" else 0.5 if x["status"] == "WARN" else 0
                    for x in auto
                )
                / len(auto)
            )
            if auto
            else None
        )
        c["counts"] = {s: sum(1 for x in cs if x["status"] == s) for s in order}
        allc += cs
    auto = [x for x in allc if x["status"] in ("PASS", "WARN", "FAIL")]
    r["overall_score"] = (
        round(
            100
            * sum(
                1 if x["status"] == "PASS" else 0.5 if x["status"] == "WARN" else 0
                for x in auto
            )
            / len(auto)
        )
        if auto
        else 0
    )
    r["totals"] = {
        s: sum(1 for x in allc if x["status"] == s)
        for s in ("PASS", "WARN", "FAIL", "MANUAL", "NA")
    }
    return r


def grade(score):
    return (
        "A"
        if score >= 90
        else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "E"
    )


def is_intake(r):
    return r.get("kind") == "Plugin intake"


def verdict(r):
    t = r["totals"]
    if t["FAIL"]:
        return (
            "Blocked",
            f"{t['FAIL']} finding(s) must be fixed before this plugin can enter the marketplace.",
        )
    if t["WARN"] or t["MANUAL"]:
        return (
            "Needs review",
            "No blockers. A reviewer must read the warnings below, then run approve.",
        )
    return (
        "Ready to approve",
        "No findings. Run approve to pin the hashes and sign the record.",
    )


def fixes(r):
    def key(pair):
        c, x = pair
        t = x["title"].lower()
        return (
            ORDER[x["status"]],
            next((i for i, k in enumerate(URGENT) if k in t), len(URGENT)),
            c["id"],
        )

    out = [
        (c, x)
        for c in r["categories"]
        for x in c["checks"]
        if x["status"] in ("FAIL", "WARN")
    ]
    return sorted(out, key=key)


def where(x):
    """'file:12, 14' for the first location, for one-line summaries."""
    if not x["locations"]:
        return ""
    lo = x["locations"][0]
    more = f" (+{len(x['locations']) - 1} more)" if len(x["locations"]) > 1 else ""
    return (
        lo["file"]
        + (":" + ", ".join(map(str, lo["lines"][:4])) if lo["lines"] else "")
        + more
    )


# --------------------------------------------------------------------------- markdown
def md_location(lo):
    head = f"`{lo['file']}`" + (
        f" line {', '.join(map(str, lo['lines']))}" if lo["lines"] else ""
    )
    if lo.get("note"):
        head += f" — {lo['note']}"
    if not lo["snippet"]:
        return [f"  - {head}"]
    lang = LANG.get(os.path.splitext(lo["file"])[1], "")
    hits = set(lo["lines"])
    body = [
        ("   ⋮" if n is None else f"{'>' if n in hits else ' '}{n:>4} │ {t}")
        for n, t in lo["snippet"]
    ]
    return [f"  - {head}", f"    ```{lang}"] + [f"    {b}" for b in body] + ["    ```"]


def md(r):
    t = r["totals"]
    title = "Plugin intake" if is_intake(r) else "Agentic AI Security Audit"
    L = [
        f"# {title} — {r['repo']}",
        "",
        f"Scanned {r['scanned_at']} · Path: `{r['path']}`",
        "",
    ]
    if is_intake(r):
        v, why = verdict(r)
        L += [f"**Verdict: {v}.** {why}", ""]
    else:
        L += [
            f"**Score: {r['overall_score']}/100 (grade {grade(r['overall_score'])})** — "
            f"❌ {t['FAIL']} fail · ⚠️ {t['WARN']} warn · ✅ {t['PASS']} pass · 📝 {t['MANUAL']} need an answer",
            "",
        ]
    L += [
        "## Scorecard",
        "",
        "| # | Category | Status | Score | Fail | Warn | Manual |",
        "|---|---|---|---|---|---|---|",
    ]
    for c in r["categories"]:
        n = c["counts"]
        L.append(
            f"| {c['id']} | {c['name']} | {MD_ICON[c['status']]} {c['status']} | "
            f"{'' if c['score'] is None else c['score']} | {n['FAIL']} | {n['WARN']} | {n['MANUAL']} |"
        )
    L += ["", "## Top fixes (do these first)", ""]
    for i, (c, x) in enumerate(fixes(r)[:10], 1):
        w = where(x)
        L.append(
            f"{i}. {MD_ICON[x['status']]} **[{c['id']}] {x['title']}**"
            + (f" — `{w}`" if w else "")
            + f" — {x['fix'] or x['evidence']}"
        )
    if not fixes(r):
        L.append("No automated failures or warnings.")
    L += ["", "## Details by category", ""]
    for c in r["categories"]:
        L += [f"### {c['id']}. {c['name']} — {MD_ICON[c['status']]} {c['status']}", ""]
        for x in sorted(c["checks"], key=lambda x: ORDER[x["status"]]):
            L.append(f"- {MD_ICON[x['status']]} **{x['title']}** — {x['evidence']}")
            if x["status"] in ("FAIL", "WARN"):
                if x["fix"]:
                    L.append(
                        f"  - Fix: {x['fix']}"
                        + (
                            f" (template: `{x['template']}`)"
                            if x.get("template")
                            else ""
                        )
                    )
                for lo in x["locations"]:
                    L += md_location(lo)
                if x["suggestion"]:
                    L += (
                        ["  - Add this:", "    ```"]
                        + [f"    {s}" for s in x["suggestion"].splitlines()]
                        + ["    ```"]
                    )
        L.append("")
    manual = [
        (c, x) for c in r["categories"] for x in c["checks"] if x["status"] == "MANUAL"
    ]
    if manual:
        L += ["## Questions for the team (not visible in the files)", ""]
        L += [f"- [ ] [{c['id']}] {x['title']} — {x['fix']}" for c, x in manual]
        L.append("")
    return "\n".join(L)


# --------------------------------------------------------------------------- html
CSS = """
:root{
  --page:#E7EEEA;--board:#F4F6F3;--card:#FFFFFF;--soft:#EDF3F0;--band:#EAF1EE;--line:#D5DFDA;
  --ink:#10211F;--text:#131C1A;--text-2:#16211E;--muted:#3A4744;--teal:#0A6A62;--teal-deep:#0B6E66;
  --caution:#5A3706;
  --sans:'Plus Jakarta Sans',system-ui,sans-serif;--mono:'JetBrains Mono',ui-monospace,monospace;
}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--text);font-family:var(--sans);-webkit-font-smoothing:antialiased}
a{color:var(--teal)}a:hover{color:var(--teal-deep)}
.wrap{max-width:1600px;margin:0 auto;padding:24px 16px 64px}
.board{background:var(--board);border:1px solid var(--line);border-radius:8px;padding:48px 56px;
  display:flex;flex-direction:column;gap:26px;box-shadow:0 2px 4px rgba(16,33,31,.05),0 20px 50px rgba(16,33,31,.12)}
h1{margin:0;font-size:56px;font-weight:800;letter-spacing:-.035em;line-height:1.04;color:var(--ink)}
h2{margin:18px 0 0;font-size:34px;font-weight:800;letter-spacing:-.03em;line-height:1.1;color:var(--ink)}
h3{margin:0;font-size:20px;font-weight:700;letter-spacing:-.015em;color:var(--ink)}
p{margin:0}
.eyebrow{font-family:var(--mono);font-size:11px;font-weight:700;letter-spacing:.18em;text-transform:uppercase;
  color:var(--teal-deep);margin:0 0 10px}
.lead{max-width:1150px;font-size:18px;line-height:1.5;color:var(--text-2);margin-top:12px}
.label{font-size:13px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
.small{font-size:15px;line-height:1.5;color:var(--muted)}
.row{display:flex;gap:20px;align-items:stretch;flex-wrap:wrap}
.grow{flex-grow:1}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:22px 24px;
  display:flex;flex-direction:column;gap:10px}
.card.accent{border-color:var(--teal)}
.card p,.card .body{margin:0;font-size:16px;line-height:1.5;color:var(--text-2)}
.code{margin:0;background:var(--soft);border:1px solid var(--line);border-radius:10px;padding:14px 0;
  font-family:var(--mono);font-size:12.5px;line-height:1.65;color:#0F1917;white-space:pre-wrap;overflow-x:auto}
.code .l{display:block;padding:0 18px 0 0;border-left:3px solid transparent}
.code .l.hit{background:var(--card);border-left-color:var(--teal);font-weight:700}
.code .n{display:inline-block;width:58px;padding-right:14px;text-align:right;color:var(--muted);user-select:none}
.code .gap{color:var(--muted);padding-left:44px}
.code.add{padding:14px 18px}
.mono{font-family:var(--mono);font-size:12.5px;font-weight:700;color:var(--teal-deep);
  background:var(--soft);padding:2px 6px;border-radius:4px;overflow-wrap:anywhere}
.filename{font-family:var(--mono);font-size:13px;font-weight:700;color:var(--teal);overflow-wrap:anywhere}
.note{background:var(--band);border:1px solid var(--line);border-left:3px solid var(--teal);
  border-radius:0 12px 12px 0;padding:18px 22px;font-size:16px;line-height:1.6;color:var(--text-2)}
.note b{color:var(--ink)}
.deftable{display:flex;flex-direction:column;margin:0}
.deftable div{display:flex;gap:16px;padding:10px 0;border-bottom:1px solid var(--line)}
.deftable div:last-child{border-bottom:0}
.deftable dt{flex-grow:1;margin:0;font-size:15.5px;line-height:1.45;color:var(--text-2)}
.deftable dd{width:220px;margin:0;font-size:15.5px;font-weight:600;color:var(--ink);text-align:right}

/* status chips: the one accent (teal) plus the template's ink and caution brown */
.pill{font-family:var(--mono);font-size:11px;font-weight:700;letter-spacing:.08em;padding:4px 9px;border-radius:999px;
  border:1px solid var(--line);white-space:nowrap}
.FAIL{background:var(--ink);color:#FFFFFF;border-color:var(--ink)}
.WARN{background:var(--band);color:var(--caution);border-color:var(--caution)}
.PASS{background:var(--soft);color:var(--teal-deep);border-color:var(--teal)}
.MANUAL{background:var(--card);color:var(--muted);border-style:dashed;border-color:var(--muted)}
.NA{background:var(--card);color:var(--muted)}
.score{font-size:88px;font-weight:800;letter-spacing:-.04em;line-height:1;color:var(--ink)}
.score small{font-size:28px;color:var(--muted);font-weight:700}
.meter{display:block;height:8px;background:var(--line);border-radius:999px;overflow:hidden}
.meter i{display:block;height:100%;background:var(--teal)}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:14px}
.tile{font:inherit;color:inherit;text-align:left;cursor:pointer;background:var(--card);border:1px solid var(--line);
  border-radius:14px;padding:16px 18px;display:flex;flex-direction:column;gap:8px}
.tile:hover{border-color:var(--teal)}
.tile.s-FAIL{border-left:4px solid var(--ink)}.tile.s-WARN{border-left:4px solid var(--caution)}
.tile.s-PASS{border-left:4px solid var(--teal)}
.tile .n{font-family:var(--mono);font-size:11px;color:var(--muted)}
.tile .t{font-weight:700;color:var(--ink);font-size:16px}
.fix{display:grid;grid-template-columns:44px minmax(0,1fr);gap:16px;align-items:start}
.fix .num{font-family:var(--mono);font-size:22px;font-weight:700;color:var(--teal)}
.stack{display:flex;flex-direction:column;gap:10px;min-width:0}
.list{display:flex;flex-direction:column;gap:14px}
.head{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
details.cat{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:0 24px}
details.cat>summary{cursor:pointer;list-style:none;padding:18px 0;display:flex;gap:12px;align-items:center;flex-wrap:wrap}
details.cat>summary::-webkit-details-marker{display:none}
details.cat>summary h3{flex-grow:1}
.chk{border-top:1px solid var(--line);padding:18px 0;display:flex;flex-direction:column;gap:10px}
.chk .ev{font-size:15px;line-height:1.5;color:var(--muted);overflow-wrap:anywhere}
.chk .fx{font-size:15.5px;line-height:1.5;color:var(--text-2)}
.filters{display:flex;gap:8px;flex-wrap:wrap}
.btn{font-family:inherit;font-size:14px;font-weight:600;color:var(--teal-deep);background:var(--card);
  border:1px solid var(--line);border-radius:8px;padding:8px 14px;cursor:pointer}
.btn:hover{background:var(--soft);border-color:var(--teal)}
.btn.on{background:var(--teal);color:#FFFFFF;border-color:var(--teal)}
@media (max-width:900px){.board{padding:28px 18px}h1{font-size:36px}h2{font-size:26px}.score{font-size:60px}
  .code .n{width:40px;padding-right:8px}.fix{grid-template-columns:1fr}.deftable dd{width:auto}}
"""

JS = """
const fb=[...document.querySelectorAll('.filters .btn')];
fb.forEach(b=>b.addEventListener('click',()=>{fb.forEach(x=>x.classList.remove('on'));b.classList.add('on');
const f=b.dataset.f;document.querySelectorAll('.chk').forEach(c=>c.hidden=!(f==='ALL'||c.dataset.s===f));
document.querySelectorAll('details.cat').forEach(d=>{const any=[...d.querySelectorAll('.chk')].some(c=>!c.hidden);
d.hidden=!any;if(f!=='ALL')d.open=any;});}));
document.querySelectorAll('.tile').forEach(t=>t.addEventListener('click',()=>{
const d=document.getElementById('c'+t.dataset.id);d.open=true;d.scrollIntoView({behavior:'smooth',block:'start'});}));
"""


def h(s):
    return html.escape(str(s))


def pill(status):
    return f'<span class="pill {status}">{LABEL[status]}</span>'


def html_location(lo):
    lines = (
        f' <span class="small">line {", ".join(map(str, lo["lines"]))}</span>'
        if lo["lines"]
        else ""
    )
    note = f' <span class="small">— {h(lo["note"])}</span>' if lo.get("note") else ""
    out = f'<div class="filename">{h(lo["file"])}{lines}{note}</div>'
    if lo["snippet"]:
        hits = set(lo["lines"])
        rows = "".join(
            (
                '<span class="l gap">⋮</span>'
                if n is None
                else f'<span class="l{" hit" if n in hits else ""}"><span class="n">{n}</span>{h(t)}</span>'
            )
            for n, t in lo["snippet"]
        )
        out += f'<pre class="code">{rows}</pre>'
    return out


def html_check(x):
    body = f'<div class="head">{pill(x["status"])}<h3>{h(x["title"])}</h3></div><div class="ev">{h(x["evidence"])}</div>'
    if x["status"] in ("FAIL", "WARN", "MANUAL") and x["fix"]:
        tpl = (
            f' <span class="mono">{h(x["template"])}</span>'
            if x.get("template")
            else ""
        )
        body += f'<div class="fx"><b>Fix:</b> {h(x["fix"])}{tpl}</div>'
    if x["status"] in ("FAIL", "WARN"):
        body += "".join(html_location(lo) for lo in x["locations"])
        if x["suggestion"]:
            body += f'<div class="label">Add this</div><pre class="code add">{h(x["suggestion"])}</pre>'
    return f'<div class="chk" data-s="{x["status"]}">{body}</div>'


def page(r):
    t = r["totals"]
    intake = is_intake(r)
    if intake:
        v, why = verdict(r)
        hero = (
            f'<div class="card accent grow"><div class="label" style="color:var(--teal)">Verdict</div>'
            f'<div class="score" style="font-size:56px">{h(v)}</div><p>{h(why)}</p></div>'
        )
    else:
        hero = (
            f'<div class="card accent" style="min-width:280px"><div class="label" style="color:var(--teal)">Score</div>'
            f'<div class="score">{r["overall_score"]}<small>/100 · {grade(r["overall_score"])}</small></div>'
            f'<span class="meter"><i style="width:{r["overall_score"]}%"></i></span></div>'
        )
    counts = "".join(
        f"<div><dt>{pill(s)}</dt><dd>{t[s]}</dd></div>"
        for s in ("FAIL", "WARN", "PASS", "MANUAL")
    )
    hero += (
        f'<div class="card grow"><div class="label">Findings</div><dl class="deftable">{counts}</dl>'
        f'<p class="small">Score counts automated checks only: pass = 1, warn = ½, fail = 0. '
        f'"Needs answer" items are questions a person must answer; they are left out of the score.</p></div>'
    )
    tiles = "".join(
        f'<button class="tile s-{c["status"]}" data-id="{c["id"]}"><span class="n">{c["id"]:02d}</span>'
        f'<span class="t">{h(c["name"])}</span><span class="head">{pill(c["status"])}'
        f'<span class="small">{"" if c["score"] is None else str(c["score"]) + "/100"}</span></span>'
        f'<span class="meter"><i style="width:{c["score"] or 0}%"></i></span></button>'
        for c in r["categories"]
    )
    top = ""
    for i, (c, x) in enumerate(fixes(r)[:10], 1):
        lo = x["locations"][0] if x["locations"] else None
        more = len(x["locations"]) - 1
        top += (
            f'<div class="card"><div class="fix"><div class="num">{i:02d}</div><div class="stack">'
            f'<div class="head">{pill(x["status"])}<span class="label">{c["id"]:02d} · {h(c["name"])}</span></div>'
            f'<h3>{h(x["title"])}</h3><p class="body">{h(x["fix"] or x["evidence"])}</p>'
            + (html_location({**lo, "snippet": lo["snippet"][:9]}) if lo else "")
            + (
                f'<p class="small">+{more} more location(s) under All checks.</p>'
                if more > 0
                else ""
            )
            + "</div></div></div>"
        )
    top = top or '<div class="note"><b>No automated failures or warnings.</b></div>'
    det = "".join(
        f'<details class="cat" id="c{c["id"]}"{" open" if c["status"] == "FAIL" else ""}><summary>'
        f'<span class="mono">{c["id"]:02d}</span><h3>{h(c["name"])}</h3>{pill(c["status"])}</summary>'
        + "".join(
            html_check(x) for x in sorted(c["checks"], key=lambda x: ORDER[x["status"]])
        )
        + "</details>"
        for c in r["categories"]
    )
    title = "Plugin intake" if intake else "Agentic AI security audit"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{h(title)}: {h(r['repo'])}</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap">
<style>{CSS}</style></head><body><div class="wrap"><div class="board">
<div><p class="eyebrow">{h(title)} · {h(r['scanned_at'])}</p><h1>{h(r['repo'])}</h1>
<p class="lead">Every open finding names the file, the line numbers and the code block. Hit lines have a teal
edge. Secrets in snippets are masked.</p></div>
<div class="row">{hero}</div>
<div><p class="eyebrow">Scorecard</p><h2>By category</h2></div><div class="tiles">{tiles}</div>
<div><p class="eyebrow">Start here</p><h2>Top fixes</h2></div><div class="list">{top}</div>
<div><p class="eyebrow">Everything</p><h2>All checks</h2></div>
<div class="filters"><button class="btn on" data-f="ALL">All</button><button class="btn" data-f="FAIL">Fail</button>
<button class="btn" data-f="WARN">Warn</button><button class="btn" data-f="MANUAL">Needs answer</button>
<button class="btn" data-f="PASS">Pass</button></div>
<div class="list">{det}</div>
<p class="small">Path scanned: <span class="mono">{h(r['path'])}</span></p>
</div></div><script>{JS}</script></body></html>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("findings")
    ap.add_argument("--md", default="SECURITY-AUDIT.md")
    ap.add_argument("--html", default="security-audit.html")
    ap.add_argument(
        "--overrides", help="JSON map: check title (or prefix) -> {status, evidence}"
    )
    a = ap.parse_args()
    with open(a.findings, encoding="utf-8") as fh:
        r = recompute(apply_overrides(json.load(fh), a.overrides))
    with open(a.md, "w", encoding="utf-8") as fh:
        fh.write(md(r))
    with open(a.html, "w", encoding="utf-8") as fh:
        fh.write(page(r))
    print(f"Wrote {a.md} and {a.html} (score {r['overall_score']})")


if __name__ == "__main__":
    main()
