"""Plain terminal rendering. No colour library: output stays readable when piped
into CI logs, and colour is only added when stdout is a terminal."""

from __future__ import annotations

import sys

_COLOR = {"error": "31", "warning": "33", "note": "36", "ok": "32", "dim": "2"}


def c(text: str, kind: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"\033[{_COLOR[kind]}m{text}\033[0m"


def show(s: str) -> str:
    """Make a witness visible: quote it and escape control/invisible characters."""
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\n":
            out.append("\\n")
        elif o < 32 or 0x200B <= o <= 0x200F or 0x202A <= o <= 0x202E or 0x2066 <= o <= 0x2069 \
                or o == 0xFEFF:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def render_check(sec: dict) -> str:
    lines = []
    eng = ", ".join(
        f"{n} {m.get('version', '')}".strip() if not m.get("missing") else f"{n} (MISSING)"
        for n, m in sec["engines"].items())
    s = sec["summary"]
    lines.append(f"Rules: {s['rules']} from {sec['ruleset']['path']}   Engines: {eng}")
    lines.append(f"Checked on {sec['stats']['texts']} texts "
                 f"({sec['stats']['benign_texts']} benign, {sec['stats']['case_texts']} cases, "
                 f"the rest generated from the rules)")
    if not sec["complete"]:
        lines.append(c("INCOMPLETE: a requested engine is missing or rule entries could not be "
                       "read; this is not a pass.", "error"))
    lines.append("")
    rows = [
        ("Does not compile in every engine", s["compile_split"]),
        ("Engines disagree on a match", s["match_split"]),
        ("Disagree only on line terminators (\\r, U+2028)", s.get("line_split", 0)),
        ("Fires on ordinary text", s["benign_hit"]),
        ("Hangs (catastrophic backtracking)", s["timeout"]),
        ("Slow or superlinear on long input", s["slow"]),
    ]
    for label, n in rows:
        mark = c(f"{n:>4}", "error" if n else "ok")
        lines.append(f"  {mark} / {s['rules']} rules   {label}")
    by = {}
    for h in sec["hazards"]:
        by[h["level"]] = by.get(h["level"], 0) + 1
    split = ", ".join(f"{by[lv]} {lv}" for lv in ("error", "warning", "note") if by.get(lv))
    lines.append(f"  {s['hazards']:>4} static hazards (engine-dependent syntax)"
                 + (f": {split}" if split else ""))
    lines.append("")
    rules = sec["rules"]
    for f in sec["findings"]:
        r = rules.get(f["rule_id"], {})
        loc = f"{sec['ruleset']['path']}:{r['line']}" if r.get("line") else f["rule_id"]
        lines.append(c(f"[{f['level']}] {f['title']}", f["level"]) + f"  {f['rule_id']}  ({loc})")
        lines.append(f"    {f['detail']}")
        if f.get("witness") is not None:
            label = "input that hangs" if f["kind"] == "timeout" else "minimal witness"
            w = f["witness"] if len(f["witness"]) <= 160 else f["witness"][:157] + "..."
            lines.append(f"    {label}: {show(w)}  {_verdicts(f)}")
        if r.get("pattern"):
            p = r["pattern"]
            lines.append(c(f"    pattern: {p if len(p) < 110 else p[:107] + '...'}", "dim"))
    if sec["hazards"]:
        lines.append("")
        lines.append("Static hazards:")
        by_code: dict[str, list] = {}
        for h in sec["hazards"]:
            by_code.setdefault((h["code"], h["level"], h["title"]), []).append(h["rule_id"])
        for (code, level, title), ids in sorted(by_code.items()):
            shown = ", ".join(ids[:6]) + (f" +{len(ids) - 6} more" if len(ids) > 6 else "")
            lines.append(f"  {c(code, level)} {title}: {len(ids)} rule(s) — {shown}")
    return "\n".join(lines)


def _verdicts(f: dict) -> str:
    e = f.get("engines") or {}
    if all(isinstance(v, bool) for v in e.values()) and e:
        return "(" + ", ".join(f"{n}: {'match' if v else 'no match'}" for n, v in e.items()) + ")"
    return ""


def render_coverage(sec: dict) -> str:
    a = sec["aggregate"]
    lines = [f"Detector: {sec['detector']}"]
    if sec.get("note"):
        lines.append(c(f"  note: {sec['note']}", "warning"))
    if not sec.get("complete", True):
        lines.append(c(f"INCOMPLETE: {a.get('unanswered', '?')} cases have no answer or some rules "
                       "did not run; rates are over answered cases only. Not a pass.", "error"))
    def pc(v):
        return "—" if v is None else f"{v}%"

    lines.append(f"All languages: recall {pc(a['recall_pct'])} ({a['caught']}/{a['attacks']}), "
                 f"false positives {pc(a['fp_pct'])} ({a['flagged_benign']}/{a['benign']})")
    ho = sec.get("heldout") or {}
    if ho.get("heldout", {}).get("attacks"):
        lines.append(f"Held-out cases only: recall {pc(ho['heldout']['recall_pct'])} "
                     f"({ho['heldout']['caught']}/{ho['heldout']['attacks']}); fit cases "
                     f"{pc(ho['fit']['recall_pct'])} ({ho['fit']['caught']}/{ho['fit']['attacks']})")
    if ho.get("note"):
        lines.append(c(f"  {ho['note']}", "warning"))
    lines.append("")
    lines.append(f"  {'lang':<9}{'recall':>18}   {'95% CI':>12}   {'FP benign':>12}   {'FP hard-neg':>12}")
    for lg, r in sec["by_lang"].items():
        rec = f"{r['recall_pct']}% ({r['caught']}/{r['attacks']})" if r["attacks"] else "—"
        kind = "ok" if (r["recall"] or 0) >= 0.8 else ("warning" if (r["recall"] or 0) >= 0.4 else "error")
        fp = f"{r['fp_pct']}% ({r['flagged_benign']}/{r['benign']})" if r["benign"] else "—"
        hn = f"{r['hn_fp_pct']}% ({r['hn_flagged']}/{r['hn']})" if r["hn"] else "—"
        ci = (f"{r['ci_low_pct']:>5}–{r['ci_high_pct']:<5}%" if r["ci_low_pct"] is not None
              else f"{'—':>12}")
        lines.append(f"  {lg:<9}{c(f'{rec:>18}', kind)}   {ci}   {fp:>12}   {hn:>12}")
    for cmp in sec.get("compare", [])[1:]:
        lines.append("")
        lines.append(f"Same rules, {cmp['detector']}: recall {cmp['aggregate']['recall_pct']}% "
                     f"({cmp['aggregate']['caught']}/{cmp['aggregate']['attacks']})"
                     + (f" — {cmp['note']}" if cmp.get("note") else ""))
    for d in sec.get("drivers", []):
        lines.append(c(f"  note: {d}", "warning"))
    if sec.get("fixtures_note"):
        lines.append("")
        lines.append(c(sec["fixtures_note"], "dim"))
    return "\n".join(lines)


def render_probe(sec: dict) -> str:
    v = sec["summary"]
    lines = [f"System: {sec.get('name') or sec['adapter']}", f"Contract: {sec['contract']}", ""]
    for s in sec["scenarios"]:
        kind = {"held": "ok", "violated": "error", "unverified": "warning"}[s["verdict"]]
        verdict = f"{s['verdict']:<10}"
        lines.append(f"  {c(verdict, kind)} "
                     f"{s['name']:<28} expected {s['expect']:<5}  observed {s['observed']}")
        lines.append(c(f"             {s['evidence']}", "dim"))
    lines.append("")
    lines.append(f"{v['violations']} violation(s), {v['unverified']} unverified, {v['held']} held "
                 f"of {v['scenarios']} scenarios.")
    return "\n".join(lines)


def render_fix(summary: dict) -> str:
    lines = [(f"Rules: {summary['rules']}   rewritten and verified: {len(summary['rewritten'])}   "
              f"written to {summary['written']}")]
    for x in summary["rewritten"]:
        lines.append(f"  {x['rule_id']}: " + "; ".join(x["changes"]))
    if summary["rejected"]:
        lines.append("Left unchanged (rewrite not verified):")
        for rid, why in summary["rejected"].items():
            lines.append(f"  {rid}: {why}")
    if summary["not_fixable"]:
        lines.append("Not auto-fixable (left as is):")
        for x in summary["not_fixable"]:
            lines.append(f"  {x['rule_id']}: {x['why']}")
    lines.append(f"Verified before writing: each rewritten rule agrees with the original under "
                 f"Python, in {', '.join(summary['engines'])}, on its own samples, those samples "
                 f"next to letters and non-letters of every in-scope script, and "
                 f"{summary['bundled_texts']} bundled texts. Exact within the scripts named per "
                 "rule; next to letters of other scripts it can differ (widen with --scripts).")
    return "\n".join(lines)


def render_enforce(run: dict) -> str:
    i = run["integration"]
    v = ", ".join(f"{k} {val}" for k, val in i["versions"].items() if val)
    lines = [f"Integration: {i['integration']} ({i['profile']})   {v}",
             f"Config: {i['config']}"]
    src = i.get("documented_source") or {}
    if src:
        lines.append(c(f"Docs: {src.get('source')} (read for {src.get('read_for')})", "dim"))
    rc = run.get("receipt") or {}
    if rc:
        g = rc.get("gcl") or {}
        lines.append(c(f"Run {rc.get('run_id')}  gcl {g.get('version')} "
                       f"{(g.get('commit') or 'not a git checkout')[:12]}", "dim"))
        for p in rc.get("problems") or []:
            lines.append(c(f"Receipt: {p}", "warning"))
    lines.append("")
    for r in run["results"]:
        s = r["scenario"]
        pk = {"held": "ok", "violated": "error", "unverified": "warning"}[r["policy"]]
        dk = {"conforms": "ok", "deviates": "error", "unspecified": "dim", "unverified": "warning"}[r["documented"]]
        tag = " (control)" if s["control"] else ""
        if r["evidence"].get("confidence") == "guessed":
            tag += " [guessed stand-in]"
        pol = f"{r['policy']:<10}"
        docv = f"{r['documented']:<11}"
        lines.append(f"  {c(pol, pk)} {c(docv, dk)} "
                     f"{s['stage']:<6} {s['mode']:<15} [{s['lang']}]  expected {r['policy_expect']:<8} "
                     f"observed {r['observed']}{tag}")
        for n in r["notes"]:
            lines.append(c(f"             {n}", "dim"))
    sm = run["summary"]
    lines.append("")
    lines.append(f"Policy: {sm['policy_held']} held, {sm['policy_violated']} violated, {sm['unverified']} unverified "
                 f"of {sm['scenarios']}.  Docs: {sm['documented_deviates']} deviation(s); "
                 f"{sm['documented_unspecified_violations']} violation(s) in behaviour the docs do not cover.")
    if sm.get("guessed"):
        lines.append(c(f"{sm['guessed']} result(s) rest on a guessed stand-in answer "
                       f"({run['integration'].get('stand_in', {}).get('source', '')}): not findings until "
                       "confirmed against a real reply.", "warning"))
    sw = run.get("latency_sweep")
    if sw:
        lines.append(f"Guard latency sweep {sw['latencies']} s: {sw['unstable']} result(s) change with timing"
                     + (" (timing-dependent: a race)" if sw["unstable"] else ""))
        for x in sw["stability"]:
            if not x["stable"]:
                by = ", ".join(f"{k} s: {v['observed']}/{v['policy']}" for k, v in x["by_latency"].items())
                lines.append(c(f"  unstable  {x['id']} {x['stage']} {x['mode']} [{x['lang']}]"
                               f"{' (' + x['role'] + ')' if x['role'] else ''}  {by}", "warning"))
    if run.get("known_issues"):
        refs = sorted(set(run["known_issues"].values()))
        lines.append(c("Known public issues for this integration: " + ", ".join(refs), "dim"))
    return "\n".join(lines)
