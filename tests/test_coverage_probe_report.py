"""Coverage arithmetic, the failure-contract drill, and report safety."""

import json
import sys

import pytest

from gcl.coverage import Detector, detect_with_adapter, summarize, wilson
from gcl.probe import load_contract, load_manifest, run_probe
from gcl.report.html import render_html

from .conftest import EX, ROOT


# ---------------------------------------------------------------- coverage
def test_wilson_known_values():
    lo, hi = wilson(0, 12)
    assert lo == 0.0 and abs(hi - 0.2425) < 0.001
    lo, hi = wilson(11, 12)
    assert abs(lo - 0.6461) < 0.001 and abs(hi - 0.9851) < 0.001


def test_summarize_splits_by_language_and_kind():
    cases = [
        {"id": "1", "lang": "en", "label": 1, "kind": "intent", "intent": "x", "text": "a"},
        {"id": "2", "lang": "en", "label": 0, "kind": "benign", "text": "b"},
        {"id": "3", "lang": "ar", "label": 1, "kind": "intent", "intent": "x", "text": "c"},
        {"id": "4", "lang": "ar", "label": 0, "kind": "hard_negative", "text": "d"},
    ]
    s = summarize(cases, Detector("t", [True, False, False, True]))
    assert s["by_lang"]["en"]["recall_pct"] == 100.0
    assert s["by_lang"]["ar"]["recall_pct"] == 0.0
    assert s["by_lang"]["ar"]["hn_fp_pct"] == 100.0
    assert s["worst"]["lang"] == "ar"
    assert s["matrix"]["x"] == {"en": [1, 1, 0], "ar": [0, 1, 0]}


def test_adapter_missing_answers_are_incomplete_not_negative(tmp_path):
    # An adapter that answers only the first case.
    script = tmp_path / "half.py"
    script.write_text(
        "import sys, json\n"
        "first = json.loads(sys.stdin.readline())\n"
        "print(json.dumps({'id': first['id'], 'flagged': True}))\n")
    adapter = {"name": "half", "argv": [sys.executable, str(script)], "_dir": str(tmp_path)}
    cases = [{"id": "a", "text": "x"}, {"id": "b", "text": "y"}]
    d = detect_with_adapter(adapter, cases)
    assert d.complete is False and "1 of 2 cases have no valid answer" in d.note
    assert d.flags == [True, None]  # unknown, not "not flagged"
    s = summarize([dict(c, lang="en", label=1, kind="intent") for c in cases], d)
    assert s["by_lang"]["en"]["attacks"] == 1 and s["aggregate"]["unanswered"] == 1


# ---------------------------------------------------------------- probe
def _manifest(policy, **override):
    m = load_manifest(EX / "failopen" / f"runner.fail-{policy}.yaml")
    m.update(override)
    return m


def test_fail_open_runner_violates_the_contract():
    sc = run_probe(_manifest("open"), load_contract(None), ["error", "malformed", "refused"])
    verdicts = {s.fault.split(":")[0]: s.verdict for s in sc}
    assert verdicts["flag"] == "held" and verdicts["clean"] == "held"
    assert verdicts["error"] == verdicts["malformed"] == verdicts["refused"] == "violated"


def test_fail_closed_runner_holds():
    sc = run_probe(_manifest("closed"), load_contract(None),
                   ["error", "malformed", "empty", "wrong_schema", "refused"])
    assert all(s.verdict == "held" for s in sc)


def test_declared_fail_open_contract_is_respected(tmp_path):
    c = tmp_path / "c.yaml"
    c.write_text("default: block\nfaults: {error: allow}\n")
    sc = run_probe(_manifest("open"), load_contract(c), ["error"])
    assert sc[-1].verdict == "held"


def test_unobservable_action_is_unverified_never_held(tmp_path):
    # The system ignores the scanner and never runs the action: no receipt, ever.
    script = tmp_path / "noop.py"
    script.write_text("import sys; sys.stdin.read(); print('did nothing')\n")
    m = _manifest("closed", argv=[sys.executable, str(script)], _dir=str(tmp_path))
    sc = run_probe(m, load_contract(None), ["error"])
    assert sc[1].verdict == "unverified"
    assert sc[-1].verdict == "unverified"


def test_contract_rejects_unknown_expectation(tmp_path):
    c = tmp_path / "c.yaml"
    c.write_text("default: maybe\n")
    with pytest.raises(ValueError):
        load_contract(c)


# ---------------------------------------------------------------- report
def test_html_escapes_rule_and_witness_text():
    evil = "<script>alert(1)</script>"
    doc = {"command": "check", "version": "t", "check": {
        "ruleset": {"path": evil, "sha256": "0" * 64, "rules": 1, "skipped": []},
        "engines": {"python": {"version": "3"}}, "complete": True,
        "stats": {"texts": 1, "benign_texts": 0, "case_texts": 0},
        "summary": {"rules": 1, "compile_split": 0, "match_split": 1, "benign_hit": 0,
                    "timeout": 0, "slow": 0, "hazards": 0},
        "hazards": [],
        "findings": [{"kind": "match_split", "level": "error", "rule_id": evil, "title": evil,
                      "detail": evil, "witness": evil, "engines": {"python": True}}],
        "rules": {evil: {"pattern": evil}}}}
    page = render_html(doc)
    assert "<script>" not in page
    assert "&lt;script&gt;" in page


def test_bundled_cases_are_well_formed():
    path = ROOT / "gcl/data/cases.multilingual.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert len(rows) == 288
    assert len({r["id"] for r in rows}) == 288
    assert all(r["native_reviewed"] is False and r["provenance"] for r in rows)
    langs = {r["lang"] for r in rows}
    assert {"am", "sw", "ar-Latn", "mix"} <= langs


# ---------------------------------------------------------------- command-mode probe, adapter
@pytest.mark.parametrize("policy,expected", [("open", "violated"), ("closed", "held")])
def test_command_mode_probe(policy, expected):
    m = load_manifest(EX / "failopen" / f"cmd.fail-{policy}.yaml")
    sc = run_probe(m, load_contract(None), ["error", "empty", "refused"])
    assert [s.verdict for s in sc[:2]] == ["held", "held"]
    assert {s.verdict for s in sc[2:]} == {expected}


def test_example_adapter_answers_every_case():
    from gcl.coverage import load_adapter
    from gcl.rules import load_cases

    cases = load_cases(ROOT / "gcl/data/cases.multilingual.jsonl")
    d = detect_with_adapter(load_adapter(EX / "coverage" / "adapter.keyword.yaml"), cases)
    assert d.complete and len(d.flags) == len(cases)
    s = summarize(cases, d)
    assert s["by_lang"]["en"]["caught"] > s["by_lang"]["ar"]["caught"]


def test_a_system_the_harness_kills_is_unverified_not_held(tmp_path):
    # Waits 30 s for its scanner, then would fail open. The harness gives up at 3 s:
    # no receipt yet, but that is not a block.
    script = tmp_path / "slow.py"
    script.write_text(
        "import json, os, sys, time, urllib.request\n"
        "sys.stdin.read()\n"
        "try:\n"
        "    req = urllib.request.Request(os.environ['SCANNER_URL'], data=b'{}')\n"
        "    urllib.request.urlopen(req, timeout=30).read()\n"
        "    v = {'flagged': False}\n"
        "except Exception:\n"
        "    v = {'flagged': False}\n"
        "open(os.environ['GCL_RECEIPT'], 'w').write('ran')\n")
    m = _manifest("open", argv=[sys.executable, str(script)], _dir=str(tmp_path), timeout_s=3)
    sc = run_probe(m, load_contract(None), ["timeout"])
    assert sc[-1].observed == "no answer" and sc[-1].verdict == "unverified"


def test_adapter_answers_must_be_booleans_and_unique(tmp_path):
    script = tmp_path / "bad.py"
    script.write_text(
        "import sys, json\n"
        "rows = [json.loads(l) for l in sys.stdin]\n"
        "print(json.dumps({'id': rows[0]['id'], 'flagged': 'false'}))\n"
        "print(json.dumps({'id': rows[1]['id'], 'flagged': True}))\n"
        "print(json.dumps({'id': rows[1]['id'], 'flagged': False}))\n")
    adapter = {"name": "bad", "argv": [sys.executable, str(script)], "_dir": str(tmp_path)}
    d = detect_with_adapter(adapter, [{"id": "a", "text": "x"}, {"id": "b", "text": "y"}])
    assert d.flags == [None, None] and d.complete is False
    assert "not a boolean" in d.note and "duplicate" in d.note


def test_intent_grid_aggregates_repeated_cells():
    cases = [{"id": str(i), "lang": "en", "label": 1, "kind": "intent", "intent": "x", "text": "t"}
             for i in range(2)]
    s = summarize(cases, Detector("t", [True, False]))
    assert s["matrix"]["x"]["en"] == [1, 2, 0]
    s = summarize(cases, Detector("t", [True, None]))
    assert s["matrix"]["x"]["en"] == [1, 1, 1]  # the unknown case is shown, not dropped


def test_broken_rules_make_coverage_incomplete_unless_simulated(tmp_path):
    from gcl.coverage import detect_with_rules

    p = tmp_path / "r.yaml"
    p.write_text("rules:\n  - {id: bad, pattern: '('}\n  - {id: ok, pattern: 'abc'}\n")
    real = detect_with_rules(str(p), "python", ["abc", "zzz"])
    assert real.complete is False
    assert real.flags == [True, None]  # "zzz": the broken rule might have fired — unknown
    sim = detect_with_rules(str(p), "python", ["abc", "zzz"], loader_drops_broken=True)
    assert sim.complete is True and sim.flags == [True, False]


def test_max_fp_gate_counts_hard_negatives(tmp_path):
    from typer.testing import CliRunner

    from gcl.cli import app

    rules = tmp_path / "r.yaml"
    rules.write_text("rules:\n  - {id: r, pattern: 'run'}\n")
    cases = tmp_path / "c.jsonl"
    cases.write_text(
        '{"id":"a","lang":"en","label":1,"kind":"intent","text":"run this"}\n'
        '{"id":"b","lang":"en","label":0,"kind":"benign","text":"hello"}\n'
        '{"id":"c","lang":"en","label":0,"kind":"hard_negative","text":"run the tests"}\n')
    r = CliRunner().invoke(app, ["coverage", "--rules", str(rules), "--cases", str(cases),
                                 "--max-fp", "10"])
    assert r.exit_code == 1


def test_unreadable_rule_entries_make_coverage_incomplete(tmp_path):
    from gcl.coverage import detect_with_rules

    p = tmp_path / "r.yaml"
    p.write_text("rules:\n  - {id: ok, pattern: 'abc'}\n  - {id: broken}\n")
    d = detect_with_rules(str(p), "python", ["abc", "x"])
    assert d.complete is False and "could not be read" in d.note and d.flags == [True, None]


@pytest.mark.parametrize("body,needle", [
    (("import sys, json\nfor l in sys.stdin: print(json.dumps({'id': json.loads(l)['id'], 'flagged': False}))\n"
     "sys.exit(1)\n"), "exited with status 1"),
    ("import sys, json\nfor l in sys.stdin: print(json.dumps({'id': [], 'flagged': False}))\n", "unparseable"),
])
def test_adapter_protocol_violations_are_incomplete_not_crashes(tmp_path, body, needle):
    script = tmp_path / "a.py"
    script.write_text(body)
    adapter = {"name": "a", "argv": [sys.executable, str(script)], "_dir": str(tmp_path)}
    d = detect_with_adapter(adapter, [{"id": "a", "text": "x"}])
    assert d.complete is False and needle in d.note


def test_supervised_output_is_capped_while_reading(tmp_path):
    from gcl.proc import run_supervised

    r = run_supervised([sys.executable, "-c", "import sys; sys.stdout.write('x' * 5_000_000)"],
                       "", timeout_s=20, max_bytes=10_000)
    assert r.truncated and len(r.output) == 10_000 and r.returncode == 0


def test_supervised_kill_takes_the_whole_process_group(tmp_path):
    import time

    from gcl.proc import run_supervised

    marker = tmp_path / "child_alive"
    child = tmp_path / "child.py"
    child.write_text(f"import time\ntime.sleep(3)\nopen({str(marker)!r}, 'w').write('x')\n")
    parent = tmp_path / "parent.py"
    parent.write_text("import subprocess, sys, time\n"
                      f"subprocess.Popen([sys.executable, {str(child)!r}])\n"
                      "time.sleep(60)\n")
    t = time.perf_counter()
    r = run_supervised([sys.executable, str(parent)], "", timeout_s=1)
    assert r.returncode is None and time.perf_counter() - t < 10
    time.sleep(3.5)
    assert not marker.exists()  # the grandchild died with the group
