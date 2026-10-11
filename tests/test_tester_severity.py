"""The tester's own mistakes, stage 7: severity from fields. The same evidence gives the
same number every time; inputs only a person can know need a written reason; a person's
own number sits next to the computed one, and drift is caught."""

import copy

import pytest

from gcl import findings as F
from gcl import severity as S


def _f(mode="error", observed="passed", profile="default", documented="unspecified", guessed=False):
    return {"id": "F-1", "status": "proposed", "guessed": guessed, "hand_repro": None, "history": [],
            "evidence_level": "end-to-end run",
            "key": {"integration": "x", "profile": profile, "stage": "input", "mode": mode, "role": ""},
            "runs": [{"run_id": "r1", "report": "/nonexistent/report.json", "observed": observed, "policy": "violated",
                      "documented": documented, "stand_in": "integration",
                      "versions": {}}]}


@pytest.mark.parametrize(("kw", "want"), [
    ({"mode": "block", "observed": "tool executed"}, 7),          # attacker content, a side effect
    ({"mode": "error", "observed": "passed"}, 5),                 # guard down, the prompt went through
    ({"mode": "wrong_schema", "observed": "passed"}, 4),          # an odd guard answer
    ({"mode": "policy_missing", "observed": "passed"}, 4),        # operator misconfiguration
    ({"mode": "error", "observed": "passed", "profile": "fail_open"}, 3),   # not the default
    ({"mode": "error", "observed": "passed", "documented": "conforms"}, 4),  # documented behaviour
    ({"mode": "block", "observed": "tool executed", "guessed": True}, 3),   # capped until confirmed
    ({"mode": "error", "observed": "stopped"}, None),             # nothing leaked: not rated
])
def test_the_rubric(kw, want):
    assert S.score(_f(**kw))["score"] == want


def test_the_same_evidence_gives_the_same_number():
    f = _f(mode="block", observed="tool executed")
    assert S.score(f) == S.score(copy.deepcopy(f)) == S.score(f)


def test_human_inputs_need_a_reason_and_are_recorded():
    doc = {"findings": [_f()]}
    with pytest.raises(F.LedgerError, match="reason"):
        F.set_field(doc, "F-1", "default_config", False, " ")
    with pytest.raises(F.LedgerError, match="trigger is one of"):
        F.set_field(doc, "F-1", "trigger", "the moon", "x")
    f = F.set_field(doc, "F-1", "default_config", False, "the default profile is called 'sequential'")
    assert f["severity"]["score"] == 3
    assert "set by a person" in S.inputs(f)["default_config"]["from"]


def test_an_override_sits_next_to_the_computed_number():
    doc = {"findings": [_f()]}
    doc["findings"][0]["severity"] = S.score(doc["findings"][0])
    F.override(doc, "F-1", 8, "the tool sends email")
    f = doc["findings"][0]
    assert f["severity"]["score"] == 5 and f["severity_override"]["score"] == 8
    assert "a person rates it 8" in F._sev(f)


def test_check_catches_a_hand_edited_rating():
    f = _f()
    f["history"] = [{"to": "proposed"}]
    f["severity"] = {"score": 9, "why": "felt like it"}
    probs = [p["problem"] for p in F.check({"findings": [f]}) if "severity" in p["problem"]]
    assert probs and "the rubric gives 5" in probs[0]
