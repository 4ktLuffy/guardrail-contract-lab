"""`gcl demo`: the whole argument in one run, on fixtures written for it.

Three ways a guardrail can look configured and not protect anything, each shown
failing and then passing:

  1. rules that half-run — a rule file loaded by Python and by JavaScript, where
     some rules never compile in JS and others silently stop matching; then
     `gcl fix` rewrites them and the same check comes back clean;
  2. coverage that collapses by language — a reasonable English rule set that
     scores well in English and near zero elsewhere;
  3. a scanner that fails open — when the scanner times out or errors, the tool call
     runs anyway; the fail-closed version holds on every fault.
"""

from __future__ import annotations

from pathlib import Path

from . import report as R
from .check import run_check
from .coverage import detect_with_rules, lang_name, summarize
from .fix import run_fix
from .probe import load_contract, load_manifest, probe_section, run_probe
from .rules import load_cases, load_rules

ROOT = Path(__file__).resolve().parent.parent
# Installed wheel: fixtures live in gcl/_examples. Source checkout: ./examples.
EX = (Path(__file__).resolve().parent / "_examples"
      if (Path(__file__).resolve().parent / "_examples").is_dir() else ROOT / "examples")
CASES = Path(__file__).parent / "data" / "cases.multilingual.jsonl"


def run_demo(out: Path, say=print) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    cases = load_cases(CASES)
    benign = [c for c in cases if c.get("label") == 0]
    texts = [c["text"] for c in cases]
    flags = {"python": "IM", "node": "im"}

    say("1/5  check: a rule file loaded by Python and by JavaScript")
    vuln = EX / "portability" / "rules.vulnerable.yaml"
    rs_before = load_rules(vuln)
    rs_before.path = "examples/portability/rules.vulnerable.yaml"  # no local paths in a shared report
    before = R.check_section(run_check(rs_before, ["python", "node"], None, benign,
                                       flags, deadline_s=2.0))

    say("2/5  fix: rewrite, verify against Python, re-check")
    fixed_path = out / "rules.portable.yaml"
    fix_summary = run_fix(vuln, fixed_path, ["python", "node"], flags, texts)
    fix_summary["written"] = fixed_path.name
    rs_after = load_rules(fixed_path)
    rs_after.path = fixed_path.name
    after = R.check_section(run_check(rs_after, ["python", "node"], None, benign,
                                      flags, deadline_s=2.0))

    say("3/5  coverage: an English-only rule set across 12 languages")
    eng = EX / "coverage" / "rules.english-only.yaml"
    secs = [summarize(cases, detect_with_rules(str(eng), e, texts, loader_drops_broken=True))
            for e in ("python", "node")]
    cov = secs[0]
    cov["cases"] = {"path": "gcl/data/cases.multilingual.jsonl", "n": len(cases)}
    cov["fixtures_note"] = ("Fixtures are machine-written and not native-reviewed; "
                            "12 attacks per language, so read the intervals.")
    cov["compare"] = [{"detector": s["detector"], "note": s["note"], "aggregate": s["aggregate"],
                       "by_lang": {lg: r["recall_pct"] for lg, r in s["by_lang"].items()}}
                      for s in secs]

    say("4/5  probe: a tool runner whose scanner fails open")
    contract = EX / "failopen" / "contract.yaml"
    probes = {}
    for pol in ("open", "closed"):
        if pol == "closed":
            say("5/5  probe: the same runner, fail-closed")
        m = load_manifest(EX / "failopen" / f"runner.fail-{pol}.yaml")
        sc = run_probe(m, load_contract(contract))
        probes[pol] = probe_section(f"examples/failopen/runner.fail-{pol}.yaml",
                                    "examples/failopen/contract.yaml", sc)

    s0, s1 = before["summary"], after["summary"]
    split_before = s0["compile_split"] + s0["match_split"]
    en = cov["by_lang"].get("en", {})
    worst = cov["worst"]
    po = probes["open"]["summary"]
    faults_open = po["scenarios"] - 2
    hero = [
        {"value": f"{split_before} of {s0['rules']}",
         "label": "rules that never compile or silently stop matching in JavaScript"},
        {"value": f"{s1['compile_split'] + s1['match_split']}",
         "label": f"after gcl fix — {len(fix_summary['rewritten'])} rules rewritten, each verified "
                  "against the original before it was written"},
        {"value": f"{en.get('recall_pct')}% → {worst['recall_pct']}%",
         "label": f"recall in English vs {lang_name(worst['lang'])} for the same English rule set"},
        {"value": f"{po['violations']} of {faults_open}",
         "label": "scanner faults that still let the tool call run (fail-open)"},
    ]

    doc = R.envelope("demo", {"examples": "examples",
                              "cases": "gcl/data/cases.multilingual.jsonl"})
    doc["title"] = "Guardrail Contract Lab — demo"
    doc["subtitle"] = "Three ways a guardrail looks configured and protects nothing, found and fixed"
    doc["hero"] = hero
    doc["sections"] = [
        {"title": "1 · Rules that half-run",
         "lead": "One rule file, loaded by a Python runtime and a JavaScript runtime. Some rules do "
                 "not compile in JavaScript (and a loader that skips bad rules drops them without "
                 "a word); others compile and quietly stop matching.",
         "check": before},
        {"title": "2 · Fixed by gcl fix, and verified",
         "lead": f"gcl fix rewrote {len(fix_summary['rewritten'])} rules into forms both engines read "
                 "the same way, and wrote each one only after it agreed with the original under Python "
                 "on every tested input, including inputs that put letters of the rule's scripts right "
                 "next to the match. What it cannot fix safely (a rule that hangs, a rule "
                 "keyed on a script) it leaves alone and still reports.",
         "check": after},
        {"title": "3 · Coverage that collapses by language",
         "lead": "A reasonable English rule set. The aggregate hides where it fails.",
         "coverage": cov},
        {"title": "4 · A scanner that fails open",
         "lead": "When the scanner times out, errors or answers garbage, does the tool call still "
                 "run? The receipt file says whether it really did.",
         "probe": probes["open"]},
        {"title": "5 · The same runner, fail-closed",
         "lead": "Same drill, corrected error handling: every fault blocks.",
         "probe": probes["closed"]},
    ]
    doc["fix"] = fix_summary
    R.write_json(doc, out / "report.json")
    from .report.html import render_html

    (out / "report.html").write_text(render_html(doc), encoding="utf-8")
    return doc
