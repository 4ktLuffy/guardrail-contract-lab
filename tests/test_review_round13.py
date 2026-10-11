"""Regressions for the thirteenth independent review (blind spots, standards, table, new
targets): disclosure covers one scenario on its own versions; a summarised history is not
a hold; a stall release explains only outcomes that came after it; history verdicts rest
on the stand-in; a guard scanning the earlier turn counts as consulted; a refusal given as
a normal answer starts a retry; OWASP tags need a leak; the table says "fails open" only
for a leak; drivers keep the library's own evidence."""

import copy
import json
from pathlib import Path
from types import SimpleNamespace

from gcl import findings as F
from gcl.enforce.adapters import CORALOGIX_VALIDATE
from gcl.enforce.contracts import (
    Result,
    Scenario,
    _after_release,
    _client_strings,
    _judge,
    _stand_in_confidence,
    classify_output,
    run_contracts,
)
from gcl.standards import risks
from gcl.table import _cell, build

from .test_enforce import _by, _Fake
from .test_review_round9 import _A, _controls, _r
from .test_tester_findings import _report


def test_a_disclosure_covers_its_own_scenario_and_versions_only(tmp_path):
    runs = tmp_path / "runs"
    a = _report(runs, "v1")

    def other_version(run):
        run["integration"]["versions"] = {"reference": "2"}
        run["receipt"]["run_id"] = "b0b0b0"

    _report(runs, "v2", edit=other_version)
    doc = F.load(Path("/x"))
    fid = F.add(doc, a, "i04", "error passes")["id"]
    F.disclose(doc, fid, "https://example.org/1")
    t = build(runs, doc, public=True)
    v1 = next(v for k, v in t["rows"].items() if "reference 2" not in k)
    v2 = next(v for k, v in t["rows"].items() if "reference 2" in k)
    assert v1["input error"].startswith("FAILS OPEN") and v2["input error"] == "withheld"
    def held(run):
        for r in run["results"]:
            if r["scenario"]["id"] == "i04":
                r.update(observed="stopped", policy="held")

    F.repeat(doc, fid, _report(runs, "flip", edit=held))
    assert doc["findings"][0]["status"] == "contradicted"
    assert all(v.get("input error") != "FAILS OPEN" for v in build(runs, doc, public=True)["rows"].values())


def test_a_summarised_history_is_not_a_hold(tmp_path):
    def summarises(g, m):
        v = g.scan("input", [x["content"] for x in m[-1:]]) or {}   # checks the last turn only
        if v.get("action") != "NONE":
            return 400, {"error": "blocked"}
        summary = "Summary of earlier turns. " + m[-1]["content"]      # the earlier turn, rewritten away
        reply = g.forward([{"role": "user", "content": summary}])
        return 200, {"choices": [{"message": {"role": "assistant", "content": reply}}]}

    run = run_contracts(_Fake(tmp_path, summarises), 5, settle_s=0.3, extra=("history",))
    r = _by(run, "input", "history_block")
    assert r["evidence"]["history_transformed"] and r["policy"] == "unverified"


def test_a_release_explains_only_what_came_after_it():
    s = Scenario("i05", "input", "timeout", "es", "u", "r")
    rel = [{"stall": {"ended": "released by gcl", "released_at": 15.0}}]
    assert _after_release(s, rel, [{"t": 12.0}, {"t": 16.0}], []) is False     # leaked before the release
    gave_up_then_released = [{"stall": {"ended": "integration gave up", "released_at": 9.0}},
                             {"stall": {"ended": "released by gcl", "released_at": 15.0}}]
    assert _after_release(s, gave_up_then_released, [{"t": 16.0}], []) is True


def test_history_verdicts_rest_on_the_stand_in():
    r = Result(Scenario("i26", "input", "history_block", "he", "u", "r"), "stopped", "stopped", None,
               policy="held", evidence={"scanner_events": []})
    _stand_in_confidence([r], SimpleNamespace(protocol=CORALOGIX_VALIDATE, harness_supplies_guard=False))
    assert r.evidence["confidence"] == "guessed"


def test_a_guard_that_scans_the_earlier_turn_is_consulted(tmp_path):
    def per_message(g, m):
        for msg in m:                                     # each turn checked; stops at the first block
            v = g.scan("input", [msg["content"]]) or {}
            if v.get("action") == "BLOCKED":
                return 400, {"error": "blocked"}
        return g.strict(m)

    run = run_contracts(_Fake(tmp_path, per_message), 5, settle_s=0.3, extra=("history",))
    r = _by(run, "input", "history_block")
    assert r["policy"] == "held" and r["evidence"]["scanner_consulted_stage"] >= 1


def test_a_refusal_given_as_a_normal_answer_starts_a_retry():
    refused = json.dumps({"choices": [{"message": {"content": "GCL-BLOCKED by the stand-in"}}]})
    r = _r("input", "block_retry", "passed", False,
           attempts=[{"status": 200, "finished": True, "body": refused}, {"status": 200, "finished": True}])
    _judge([*_controls(), r], _A())
    assert r.policy == "violated"


def test_owasp_tags_need_a_leak_and_a_fault_for_cascading_failure():
    assert risks("reference", "input", "history_block", "passed", "violated") == ["LLM01:2025"]
    assert risks("invariant-mcp", "input", "modify", "stopped", "violated") == []


def test_the_table_says_fails_open_only_for_a_leak():
    r = {"policy": "violated", "observed": "stopped", "policy_expect": "modified", "documented": "deviates",
         "evidence": {}}
    assert _cell(r) == "stopped (expected modified)"
    assert _cell(dict(r, observed="passed")) == "FAILS OPEN"


def test_streamed_library_evidence_is_kept_apart_from_the_answer():
    s = Scenario("o24", "output", "block", "es", "u", "secreto del documento")
    sse = ('data: {"choices": [{"delta": {"content": "[blocked]"}}]}\n\n'
           'data: {"library_return": [{"content": "", "additional_kwargs": {"x": "secreto del documento"}}]}\n\n'
           "data: [DONE]\n\n")
    assert all("secreto" not in t for t in _client_strings(sse))
    assert any("secreto" in t for t in _client_strings(sse, "returned"))
    obs = SimpleNamespace(text=sse, status=200, finished=True, transport=False)
    assert classify_output(s, obs) == "retained"


def test_the_llamafirewall_driver_keeps_the_scan_on_a_later_error():
    src = (Path(__file__).resolve().parent.parent / "gcl/enforce/drivers/llamafirewall_driver.py").read_text()
    handler = src[src.index("    def do_POST"):]
    assert '"library_return": scan})' in handler.split("except Exception")[1]
    assert copy.copy(src)
