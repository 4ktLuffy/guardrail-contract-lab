"""Regressions for the eleventh independent review (of provenance, the findings ledger
and severity): the ledger is re-derived from its reports, so a hand-edited status, run,
rating input or reproduction is caught; receipts are required everywhere; "recorded"
applies per answer and needs a positive shape match; allow answers rest on the stand-in
too; sweep runs and language controls are told apart."""

import copy
import dataclasses
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from gcl import findings as F
from gcl import severity as S
from gcl.enforce.adapters import LITELLM_GENERIC, ReferenceGateway, vendor_protocol
from gcl.enforce.contracts import Result, Scenario, _stand_in_confidence, build_scenarios

from .test_tester_findings import _report


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("r11")
    return {"a": _report(tmp, "a"), "b": _report(tmp, "b"), "dirty": _report(tmp, "dirty", clean=False),
            "tmp": tmp}


def _probs(doc):
    return [p["problem"] for p in F.check(doc)]


def test_a_hand_edited_status_or_run_is_caught(runs):
    doc = F.load(Path("/x"))
    f = F.add(doc, runs["a"], "i04", "x")
    assert F.check(doc) == []
    forged = copy.deepcopy(doc)
    forged["findings"][0]["status"] = "confirmed"
    p = _probs(forged)
    assert any("not where its history ends" in x for x in p) and any("two separate runs" in x for x in p)
    dup = copy.deepcopy(doc)
    ev = dict(dup["findings"][0]["runs"][0], run_id="invented")
    dup["findings"][0]["runs"].append(ev)
    assert any(x.startswith("run invented:") and "not in the report" in x for x in _probs(dup))
    flipped = copy.deepcopy(doc)
    flipped["findings"][0]["guessed"] = not f["guessed"]
    assert any("the ledger says guessed=" in x for x in _probs(flipped))


def test_forged_rating_inputs_are_ignored_and_flagged(runs):
    doc = F.load(Path("/x"))
    f = F.add(doc, runs["a"], "i04", "x")
    before = f["severity"]["score"]
    f["human_fields"] = {"observed": {"value": "tool executed", "reason": ""},
                         "trigger": {"value": "attacker", "reason": " "}}
    assert S.score(f)["score"] == before
    p = _probs(doc)
    assert any("human field observed" in x for x in p) and any("human field trigger" in x for x in p)


def test_receipts_are_required_for_add_repeat_and_check(runs):
    tmp = runs["tmp"]
    no_receipt = _report(tmp, "nr", edit=lambda run: run.pop("receipt"))
    with pytest.raises(F.LedgerError, match="no receipt"):
        F.add(F.load(Path("/x")), no_receipt, "i04", "x")
    doc = F.load(Path("/x"))
    fid = F.add(doc, runs["a"], "i04", "x")["id"]
    with pytest.raises(F.LedgerError, match="receipt lists problems"):
        F.repeat(doc, fid, runs["dirty"])


def test_a_confirmation_needs_content_and_its_reproduction_must_stay(runs, tmp_path):
    doc = F.load(Path("/x"))
    fid = F.add(doc, runs["a"], "i04", "x")["id"]
    F.repeat(doc, fid, runs["b"])
    empty = tmp_path / "empty.py"
    empty.write_text("  \n")
    with pytest.raises(F.LedgerError, match="non-empty"):
        F.confirm(doc, fid, empty, "recorded", "x")
    repro = tmp_path / "repro.py"
    repro.write_text("# real guard answered 500; the prompt was forwarded\n")
    F.confirm(doc, fid, repro, "recorded", "forwarded")
    assert F.check(doc) == []
    repro.unlink()
    assert any("reproduction" in x and "missing" in x for x in _probs(doc))


def _spec(**extra):
    return {"vendor": "acme", "requests": [{"path": "/v1/check"}], "allow_response": {"ok": True},
            "block_response": {"flagged": True}, "modify_response": {"guessed_modify": True}, **extra}


def _res(mode, body, policy="held"):
    served = "block" if mode == "block_retry" else mode
    return Result(Scenario("i09", "input", mode, "es", "u", "r"), "stopped", "stopped", None, policy=policy,
                  evidence={"scanner_events": [{"mode": served, "body": body}]})


def test_recorded_applies_per_answer_and_needs_a_positive_shape_match():
    with pytest.raises(ValueError):
        vendor_protocol(_spec(recorded={"source": "capture"}))
    proto = vendor_protocol(_spec(recorded={"block": {"real": True}, "request_shape": {"messages": 1}}))
    adapter = SimpleNamespace(protocol=proto, harness_supplies_guard=False)
    modify, block_ok, block_none = (_res("modify", {"messages": [{}]}), _res("block", {"messages": [{}]}),
                                    _res("block", {"text": "no messages"}))
    _stand_in_confidence([modify, block_ok, block_none], adapter)
    assert modify.evidence["confidence"] == "guessed"            # modify was never recorded
    assert block_ok.evidence["confidence"] == "verified" and block_ok.evidence["stand_in"] == "recorded"
    assert block_none.evidence["confidence"] == "guessed"        # no positive shape evidence


def test_an_allow_answer_rests_on_the_stand_in_too():
    proto = dataclasses.replace(LITELLM_GENERIC, provenance="client_code", provenance_source="rebuilt")
    r = _res("allow", {}, policy="violated")
    _stand_in_confidence([r], SimpleNamespace(protocol=proto, harness_supplies_guard=False))
    assert r.evidence["confidence"] == "guessed"


def test_a_sweep_finding_is_checked_against_its_own_run(runs, tmp_path):
    a = json.loads(runs["a"].read_text())["enforce"]
    slow, fast = copy.deepcopy(a), copy.deepcopy(a)
    slow["judge_latency_s"], fast["judge_latency_s"] = 1.0, 0.0
    fast["receipt"]["run_id"] = "fa57fa"
    for r in fast["results"]:
        if r["scenario"]["id"] == "i04":
            r["observed"], r["policy"] = "stopped", "held"
    rep = tmp_path / "sweep" / "report.json"
    rep.parent.mkdir()
    rep.write_text(json.dumps({"enforce": slow, "enforce_by_latency": [fast, slow]}))
    doc = F.load(Path("/x"))
    F.add(doc, rep, "i04", "races", latency=1.0)
    assert F.check(doc) == []


def test_language_controls_are_separate_findings():
    sc = build_scenarios(ReferenceGateway(sys.executable, Path("/tmp")), "abc123")
    langs = [s for s in sc if s.role == "lang"]
    run = {"integration": {"integration": "reference", "profile": "naive"}}
    keys = {json.dumps(F._key(run, {"scenario": {"stage": s.stage, "mode": s.mode, "role": s.role,
                                                 "lang": s.lang}}), sort_keys=True) for s in langs}
    assert len(langs) > 1 and len(keys) == len(langs)
