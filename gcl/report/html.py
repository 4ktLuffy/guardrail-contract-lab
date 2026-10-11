"""Static, self-contained HTML view of a result document.

Every value from rules, cases or engines is escaped — rule files and test texts are
exactly the kind of input that contains markup and injection strings. No scripts, no
external assets; it opens from disk and can be attached to a ticket.
"""

from __future__ import annotations

import html
import json

from ..coverage import lang_name
from .terminal import show

CSS = """
:root{--bg:#fbfbfa;--fg:#1d1d1b;--mute:#6b6b66;--line:#e4e3de;--card:#fff;
--err:#b42318;--warn:#b54708;--ok:#067647;--note:#175cd3;--code:#f2f1ed}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--fg:#ecebe6;--mute:#9d9c96;
--line:#2c2c29;--card:#1c1c1a;--err:#f97066;--warn:#fdb022;--ok:#47cd89;--note:#84adff;--code:#252522}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1080px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:36px 0 10px}
.sub{color:var(--mute);margin:0 0 20px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.tile b{display:block;font-size:26px;font-variant-numeric:tabular-nums}
.tile span{color:var(--mute);font-size:13px}
.tile.bad b{color:var(--err)}.tile.good b{color:var(--ok)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);
border-radius:10px;overflow:hidden;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--mute)}
tr:last-child td{border-bottom:0}
code,.w{font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--code);
padding:1px 5px;border-radius:5px;word-break:break-all}
td:nth-child(2) code{word-break:normal;white-space:nowrap}
.lv{font-weight:600;font-size:12px;text-transform:uppercase}
.error{color:var(--err)}.warning{color:var(--warn)}.note{color:var(--note)}.okc{color:var(--ok)}
.banner{border:1px solid var(--err);color:var(--err);border-radius:10px;padding:10px 14px;margin:12px 0}
.matrix td,.matrix th{text-align:center}.matrix td:first-child,.matrix th:first-child{text-align:left}
.cell{font-variant-numeric:tabular-nums;border-radius:6px;padding:2px 6px}
details{margin-top:6px}summary{cursor:pointer;color:var(--mute)}
.scroll{overflow-x:auto}
footer{margin-top:40px;color:var(--mute);font-size:13px}
.part{margin-top:48px;padding-top:8px;border-top:2px solid var(--line)}
.part-title{font-size:22px;margin:18px 0 4px}.lead{max-width:760px;margin:0 0 8px}
.hero{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin:18px 0 8px}
.hero div{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.hero b{display:block;font-size:30px;line-height:1.1;font-variant-numeric:tabular-nums}
.hero span{color:var(--mute);font-size:14px}
"""


def e(x) -> str:
    return html.escape("" if x is None else str(x), quote=True)


def _tile(n, label, bad_if_nonzero=True, total=None):
    cls = "bad" if (bad_if_nonzero and n) else ("good" if bad_if_nonzero else "")
    tot = f"<small> / {e(total)}</small>" if total is not None else ""
    return f'<div class="tile {cls}"><b>{e(n)}{tot}</b><span>{e(label)}</span></div>'


def _check(sec: dict) -> str:
    s = sec["summary"]
    rules = sec["rules"]
    out = ["<h2>Rule portability and behaviour</h2>"]
    eng = ", ".join(f"{e(n)} {e(m.get('version', 'MISSING'))}" for n, m in sec["engines"].items())
    out.append(f'<p class="sub">{e(s["rules"])} rules from <code>{e(sec["ruleset"]["path"])}</code> '
               f'(sha256 {e(sec["ruleset"]["sha256"][:12])}…) · engines: {eng} · '
               f'{e(sec["stats"]["texts"])} texts ({e(sec["stats"]["benign_texts"])} benign)</p>')
    if not sec["complete"]:
        out.append('<div class="banner">Incomplete run: a requested engine is missing. '
                   'This is not a pass.</div>')
    out.append('<div class="tiles">'
               + _tile(s["compile_split"], "don't compile everywhere", total=s["rules"])
               + _tile(s["match_split"], "engines disagree", total=s["rules"])
               + _tile(s.get("line_split", 0), "disagree on line terminators", total=s["rules"])
               + _tile(s["benign_hit"], "fire on ordinary text", total=s["rules"])
               + _tile(s["timeout"], "hang on long input", total=s["rules"])
               + _tile(s["slow"], "superlinear / slow", total=s["rules"])
               + _tile(s["hazards"], "static hazards", bad_if_nonzero=False)
               + "</div>")
    if sec["findings"]:
        out.append("<h2>Findings</h2><div class='scroll'><table><tr><th>Level</th><th>Rule</th>"
                   "<th>What happens</th><th>Witness</th></tr>")
        for f in sec["findings"]:
            r = rules.get(f["rule_id"], {})
            where = f'line {e(r["line"])}' if r.get("line") else ""
            pat = (f'<details><summary>pattern</summary><code>{e(r.get("pattern"))}</code></details>'
                   if r.get("pattern") else "")
            verdict = ""
            if f.get("engines") and all(isinstance(v, bool) for v in f["engines"].values()):
                verdict = "<br>" + " · ".join(
                    f'{e(n)}: <span class="{"okc" if v else "error"}">{"match" if v else "no match"}</span>'
                    for n, v in f["engines"].items())
            elif f.get("engines"):
                verdict = "<br>" + " · ".join(f"{e(n)}: <code>{e(v)}</code>" for n, v in f["engines"].items())
            w = "—"
            if f.get("witness") is not None:
                lab = "<small>input that hangs</small><br>" if f["kind"] == "timeout" else ""
                w = f'{lab}<span class="w">{e(show(f["witness"]))}</span>' 
            out.append(f'<tr><td class="lv {e(f["level"])}">{e(f["level"])}</td>'
                       f'<td><code>{e(f["rule_id"])}</code><br><small>{where}</small></td>'
                       f'<td><b>{e(f["title"])}</b><br>{e(f["detail"])}{verdict}{pat}</td>'
                       f"<td>{w}</td></tr>")
        out.append("</table></div>")
    if sec["hazards"]:
        out.append("<h2>Static hazards</h2><div class='scroll'><table><tr><th>Code</th><th>Level</th>"
                   "<th>Rule</th><th>Why it matters</th></tr>")
        for h in sec["hazards"]:
            out.append(f'<tr><td><code>{e(h["code"])}</code></td><td class="lv {e(h["level"])}">'
                       f'{e(h["level"])}</td><td><code>{e(h["rule_id"])}</code></td>'
                       f'<td><b>{e(h["title"])}</b> — {e(h["detail"])}</td></tr>')
        out.append("</table></div>")
    return "\n".join(out)


def _heat(v):
    """Background for a recall cell: transparent → green as recall rises."""
    if v is None:
        return ""
    return f' style="background:rgba(6,118,71,{0.08 + 0.5 * v:.2f})"'


def _coverage(sec: dict) -> str:
    out = ["<h2>Coverage by language</h2>"]
    if not sec.get("complete", True):
        out.append('<div class="banner">Incomplete run: some cases have no answer '
                   f'({e(sec["aggregate"].get("unanswered", "?"))} unanswered) or some rules did not '
                   'run. Rates below are over answered cases only. This is not a pass.</div>')
    out.append(f'<p class="sub">Detector: <code>{e(sec["detector"])}</code> · cases: '
               f'<code>{e(sec["cases"]["path"])}</code> ({e(sec["cases"]["n"])} rows). '
               f'{e(sec.get("note", ""))}</p>')
    a = sec["aggregate"]
    out.append('<div class="tiles">'
               + _tile(f'{a["recall_pct"]}%', f'recall, all languages ({a["caught"]}/{a["attacks"]})',
                       bad_if_nonzero=False)
               + _tile(f'{sec["worst"]["recall_pct"]}%', f'recall in {lang_name(sec["worst"]["lang"])} (worst)',
                       bad_if_nonzero=False)
               + _tile(f'{a["fp_pct"]}%', f'false positives ({a["flagged_benign"]}/{a["benign"]})',
                       bad_if_nonzero=False)
               + "</div>")
    out.append("<div class='scroll'><table><tr><th>Language</th><th>Recall</th><th>95% CI</th>"
               "<th>False positives</th><th>Hard-negative FP</th></tr>")
    for lg, row in sec["by_lang"].items():
        ci = (f'{e(row["ci_low_pct"])}–{e(row["ci_high_pct"])}%'
              if row["ci_low_pct"] is not None else "—")
        out.append(f'<tr><td><b>{e(lg)}</b></td><td><span class="cell"{_heat(row["recall"])}>'
                   f'{e(row["recall_pct"])}% ({e(row["caught"])}/{e(row["attacks"])})</span></td>'
                   f'<td>{ci}</td>'
                   f'<td>{e(row["fp_pct"])}% ({e(row["flagged_benign"])}/{e(row["benign"])})</td>'
                   f'<td>{e(row["hn_fp_pct"])}% ({e(row["hn_flagged"])}/{e(row["hn"])})</td></tr>')
    out.append("</table></div>")
    for d in sec.get("drivers", []):
        out.append(f'<p class="sub warning">Note: {e(d)}</p>')
    out.append(_compare(sec))
    if sec.get("fixtures_note"):
        out.append(f'<p class="sub">{e(sec["fixtures_note"])}</p>')
    ho = sec.get("heldout") or {}
    if ho.get("heldout", {}).get("attacks"):
        out.append(f'<p class="sub">Held-out cases only: recall {e(ho["heldout"]["recall_pct"])}% '
                   f'({ho["heldout"]["caught"]}/{ho["heldout"]["attacks"]}); fit cases '
                   f'{e(ho["fit"]["recall_pct"])}% ({ho["fit"]["caught"]}/{ho["fit"]["attacks"]})</p>')
    if ho.get("note"):
        out.append(f'<p class="warning">{e(ho["note"])}</p>')
    intents = sec.get("matrix", {})
    if intents:
        langs = list(sec["by_lang"])
        out.append("<h2>Intent × language</h2><div class='scroll'><table class='matrix'><tr><th>Intent</th>"
                   + "".join(f"<th>{e(lg)}</th>" for lg in langs) + "</tr>")
        for intent, row in intents.items():
            cells = []
            for lg in langs:
                v = row.get(lg)  # [caught, answered, unknown] or None
                if not v:
                    mark, cls = "—", ""
                elif len(v) > 2 and v[2]:
                    mark, cls = f"{v[0]}/{v[1]} +{v[2]}?", "warning"
                elif v[1] == 0:
                    mark, cls = "?", "warning"
                elif v[0] == v[1]:
                    mark, cls = ("✓" if v[1] == 1 else f"✓ {v[0]}/{v[1]}"), "okc"
                elif v[0] == 0:
                    mark, cls = ("✗" if v[1] == 1 else f"✗ 0/{v[1]}"), "error"
                else:
                    mark, cls = f"{v[0]}/{v[1]}", "warning"
                cells.append(f'<td class="{cls}">{mark}</td>')
            out.append(f"<tr><td>{e(intent)}</td>{''.join(cells)}</tr>")
        out.append("</table></div>")
    return "\n".join(out)


def _probe(sec: dict) -> str:
    out = ["<h2>Failure contract</h2>"]
    out.append(f'<p class="sub">Adapter: <code>{e(sec["adapter"])}</code> · contract: '
               f'<code>{e(sec["contract"])}</code></p>')
    v = sec["summary"]
    out.append('<div class="tiles">'
               + _tile(v["violations"], "contract violations", total=v["scenarios"])
               + _tile(v["unverified"], "enforcement unverified")
               + _tile(v["held"], "held", bad_if_nonzero=False)
               + "</div>")
    out.append("<div class='scroll'><table><tr><th>Scenario</th><th>Expected</th><th>Observed</th>"
               "<th>Verdict</th><th>Evidence</th></tr>")
    for s in sec["scenarios"]:
        cls = {"held": "okc", "violated": "error", "unverified": "warning"}[s["verdict"]]
        out.append(f'<tr><td><b>{e(s["name"])}</b><br><small>{e(s["fault"])}</small></td>'
                   f'<td>{e(s["expect"])}</td><td>{e(s["observed"])}</td>'
                   f'<td class="lv {cls}">{e(s["verdict"])}</td>'
                   f'<td><small>{e(s["evidence"])}</small></td></tr>')
    out.append("</table></div>")
    return "\n".join(out)


def _receipt(rc: dict) -> str:
    if not rc:
        return ""
    g = rc.get("gcl") or {}
    head = (f'<p class="sub">Run <code>{e(rc.get("run_id"))}</code> · gcl {e(g.get("version"))} '
            f'<code>{e((g.get("commit") or "not a git checkout")[:12])}</code></p>')
    probs = "".join(f"<li>{e(p)}</li>" for p in rc.get("problems") or [])
    return head + (f'<div class="warning"><b>Receipt problems</b><ul>{probs}</ul></div>' if probs else "")


def _sweep(sw: dict) -> str:
    if not sw:
        return ""
    rows = "".join(
        f"<tr><td>{e(x['id'])}</td><td>{e(x['stage'])}</td><td>{e(x['mode'])}</td><td>{e(x['lang'])}</td><td>"
        + "<br>".join(f"{e(k)} s: {e(v['observed'])} / {e(v['policy'])}" for k, v in x["by_latency"].items())
        + "</td></tr>" for x in sw["stability"] if not x["stable"])
    head = (f'<p class="{"warning" if sw["unstable"] else "sub"}"><b>Guard latency sweep</b> '
            f'{e(sw["latencies"])} s: {sw["unstable"]} result(s) change with timing. The table below '
            "shows the slowest run; every run is in the JSON record.</p>")
    return head + (f"<div class='scroll'><table><tr><th>Id</th><th>Stage</th><th>Scanner</th><th>Lang</th>"
                   f"<th>By latency</th></tr>{rows}</table></div>" if rows else "")


def _enforce(sec: dict) -> str:
    i = sec["integration"]
    versions = ", ".join(f"{k} {v}" for k, v in i["versions"].items() if v)
    sm = sec["summary"]
    out = ["<h2>Enforcement contract</h2>",
           (f'<p class="sub"><b>{e(i["integration"])}</b> ({e(i["profile"])}) · {e(versions)} · '
           f'config <code>{e(json.dumps(i["config"], ensure_ascii=False))}</code></p>'),
           '<div class="tiles">'
           + _tile(sm["policy_violated"], "policy violations", total=sm["scenarios"])
           + _tile(sm["documented_deviates"], "deviations from its own docs")
           + _tile(sm["unverified"], "unverified")
           + _tile(sm["policy_held"], "held", bad_if_nonzero=False)
           + _tile(sm.get("guessed", 0), "rest on a guessed stand-in")
           + "</div>",
           _doc_source(i.get("documented_source") or {}),
           _receipt(sec.get("receipt") or {}),
           _sweep(sec.get("latency_sweep") or {}),
           ("<div class='scroll'><table><tr><th>Stage</th><th>Scanner</th><th>Lang</th>"
           "<th>Expected</th><th>Observed</th><th>Policy</th><th>Docs</th><th>Evidence</th></tr>")]
    cls = {"held": "okc", "violated": "error", "unverified": "warning", "conforms": "okc",
           "deviates": "error", "unspecified": ""}
    for r in sec["results"]:
        s, ev = r["scenario"], r["evidence"]
        if s["mode"] == "surface":
            continue  # their own table below
        notes = "".join(f"<br><small>{e(n)}</small>" for n in r["notes"])
        evidence = (f"client {e(ev['client_status'])} · model requests {e(ev['model_requests'])} · "
                    f"scanner calls {e(ev['scanner_consulted_stage'])}")
        out.append(f"<tr><td>{e(s['stage'])}{' (control)' if s['control'] else ''}</td>"
                   f"<td><code>{e(s['mode'])}</code></td><td>{e(s['lang'])}</td>"
                   f"<td>{e(r['policy_expect'])}</td><td><b>{e(r['observed'])}</b></td>"
                   f'<td class="lv {cls[r["policy"]]}">{e(r["policy"])}'
                   f'{"<br><small>guessed stand-in</small>" if ev.get("confidence") == "guessed" else ""}</td>'
                   f'<td class="lv {cls[r["documented"]]}">{e(r["documented"])}</td>'
                   f"<td><small>{evidence}</small>{notes}</td></tr>")
    out.append("</table></div>")
    out.append(_surfaces(sec))
    return "\n".join(out)


def _surfaces(sec: dict) -> str:
    """MCP surfaces (`--extra mcp`): one row per surface, from its carry control and its attack."""
    if not sec.get("mcp_surfaces"):
        return ""
    rows: dict = {}
    for r in sec["results"]:
        sc = r["scenario"]
        if sc["mode"] == "surface":
            rows.setdefault(sc["surface"]["id"], {})["control" if sc["role"] else "attack"] = r
    sm = sec["mcp_surfaces"]["summary"]
    out = [(f"<h3>MCP surfaces</h3><p class='sub'>Protocol {e(sec['mcp_surfaces']['protocol'])}: "
           f"{sm['held']} held, {sm['violated']} violated, {sm['unverified']} unverified, "
           f"{sm['n/a']} not carried, of {sm['surfaces']} surfaces. Each surface is run twice: a benign "
           "marker that must arrive (carry control), then an attack marker the stand-in blocks.</p>"),
           ("<div class='scroll'><table><tr><th>Id</th><th>Surface</th><th>Direction</th><th>Carried</th>"
            "<th>Scanner shown</th><th>Outcome</th><th>Policy</th><th>OWASP</th></tr>")]
    cls = {"held": "okc", "violated": "error", "unverified": "warning", "n/a": ""}
    for sid, row in rows.items():
        a, ctl = row.get("attack"), row.get("control")
        if a is None:
            continue
        sf = a["scenario"]["surface"]
        carried = ("yes" if ctl["policy"] == "held" else "no" if ctl["policy"] == "n/a" else "?") if ctl else "?"
        shown = "-" if carried != "yes" else ("yes" if a["evidence"].get("scanner_shown") else "no")
        notes = "".join(f"<br><small>{e(n)}</small>" for n in a["notes"])
        out.append(f"<tr><td><code>{e(sid)}</code></td><td>{e(sf['name'])}<br><small>{e(sf['description'])}</small></td>"
                   f"<td>{e(sf['direction'])}</td><td>{carried}</td><td>{shown}</td><td><b>{e(a['observed'])}</b></td>"
                   f'<td class="lv {cls[a["policy"]]}">{e(a["policy"])}{notes}</td>'
                   f"<td><small>{e(', '.join(a['evidence'].get('owasp') or []))}</small></td></tr>")
    out.append("</table></div>")
    return "".join(out)


def _doc_source(src: dict) -> str:
    if not src:
        return ""
    return (f'<p class="sub">Documented expectations from <code>{e(src.get("source", ""))}</code>, '
            f'read for {e(src.get("read_for", ""))}: “{e(src.get("passage", ""))}”</p>')


def _hero(items) -> str:
    if not items:
        return ""
    return '<div class="hero">' + "".join(
        f"<div><b>{e(h['value'])}</b><span>{e(h['label'])}</span></div>" for h in items) + "</div>"


def _compare(sec: dict) -> str:
    rows = sec.get("compare") or []
    if len(rows) < 2:
        return ""
    langs = list(rows[0]["by_lang"])
    out = ["<h2>Same rules, different runtime</h2><div class='scroll'><table class='matrix'><tr><th>Runtime</th>"
           + "".join(f"<th>{e(lg)}</th>" for lg in langs) + "<th>All</th></tr>"]
    ref = rows[0]["by_lang"]
    for r in rows:
        def cell(lg, r=r):
            v = r["by_lang"].get(lg)
            lower = v is not None and ref.get(lg) is not None and v < ref[lg]
            return f'<td class="{"error" if lower else ""}">{e(v)}%</td>'
        out.append(f"<tr><td>{e(r['detector'])}<br><small>{e(r.get('note') or '')}</small></td>"
                   + "".join(cell(lg) for lg in langs)
                   + f"<td><b>{e(r['aggregate']['recall_pct'])}%</b></td></tr>")
    out.append("</table></div>")
    return "".join(out)


def render_html(doc: dict) -> str:
    parts = []
    if "check" in doc:
        parts.append(_check(doc["check"]))
    if "coverage" in doc:
        parts.append(_coverage(doc["coverage"]))
    if "probe" in doc:
        parts.append(_probe(doc["probe"]))
    if "enforce" in doc:
        parts.append(_enforce(doc["enforce"]))
    for extra in doc.get("sections", []):
        parts.append(f'<section class="part"><h2 class="part-title">{e(extra.get("title", ""))}</h2>')
        if extra.get("lead"):
            parts.append(f'<p class="lead">{e(extra["lead"])}</p>')
        if "check" in extra:
            parts.append(_check(extra["check"]))
        if "coverage" in extra:
            parts.append(_coverage(extra["coverage"]))
        if "probe" in extra:
            parts.append(_probe(extra["probe"]))
        if "enforce" in extra:
            parts.append(_enforce(extra["enforce"]))
        parts.append("</section>")
    meta = {k: doc[k] for k in ("command", "version", "generated_at", "host", "inputs") if k in doc}
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Guardrail Contract Lab report</title><style>{CSS}</style></head><body><main>
<h1>{e(doc.get("title", "Guardrail Contract Lab"))}</h1>
<p class="sub">{e(doc.get("subtitle", "Does the guardrail do what its config says?"))} ·
<code>gcl {e(doc.get("command"))}</code> · {e(doc.get("generated_at"))}</p>
{_hero(doc.get("hero"))}
{"".join(parts)}
<footer><details><summary>Run metadata</summary>
<pre class="w">{e(json.dumps(meta, ensure_ascii=False, indent=2))}</pre></details>
Generated by guardrail-contract-lab {e(doc.get("version"))}.
The JSON report is the record; this page is a view of it.</footer>
</main></body></html>"""
