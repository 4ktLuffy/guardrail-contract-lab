"""Regressions for the eighth independent review: control eligibility, spec validation,
operative-field faults, refusal evidence, 5xx precedence, explicit echo fields,
per-scenario replay, timing, tool attribution, routes, single-identity stages."""

import json
import sys
from typing import ClassVar

import pytest

from gcl.enforce.adapters import LiteLLMVendor, NemoVendor, Observation, _stage_by_sentinel, vendor_protocol
from gcl.enforce.contracts import Result, Scenario, _judge, classify
from gcl.enforce.servers import Protocol, StandInScanner, _fault_on_operative, _path_ok

S = Scenario("i12", "input", "block", "es", "Resume este documento confidencial, por favor.",
             "Aquí tienes el resumen del documento.")
SENT = [{"model": "m", "messages": [{"role": "user", "content": f"{S.user_text} {S.user_sentinel}"}]}]


class _A:
    known_issues: ClassVar[dict] = {}
    capabilities: ClassVar[set] = {"output"}


def _r(stage, mode, observed, control, policy_expect="stopped", **ev):
    sc = Scenario(f"{stage[0]}0{mode[:1]}", stage, mode, "es", "u", "r", control=control)
    base = {"scanner_consulted_stage": 1, "model_input": "passed", "settled": True}
    return Result(sc, observed, policy_expect, None, evidence={**base, **ev})


def test_an_unverified_retained_control_unlocks_nothing():
    ctrl = [_r("input", "allow", "passed", True, "passed"), _r("output", "allow", "passed", True, "passed"),
            _r("output", "block", "retained", True, scanner_consulted_stage=0)]
    err = _r("output", "error", "stopped", False)
    _judge([*ctrl, err], _A())
    assert ctrl[2].policy == "unverified" and err.policy == "unverified"


def test_specs_with_nothing_to_exercise_are_rejected(tmp_path):
    with pytest.raises(ValueError):
        spec = {"vendor": "x", "guardrail": "x", "supported_modes": ["during_call"],
                "allow_response": {}, "block_response": {}}
        LiteLLMVendor(sys.executable, tmp_path, spec=spec)
    with pytest.raises(ValueError):
        NemoVendor(sys.executable, tmp_path, spec={"vendor": "x", "allow_response": {}, "block_response": {}})


def test_faults_change_the_operative_field_not_metadata():
    out, changed = _fault_on_operative({"status": "ok", "result": {"flagged": True}},
                                       {"status": "ok", "result": {"flagged": False}}, "unknown_verdict")
    assert out == {"status": "ok", "result": {"flagged": "unknown"}} and changed
    out, changed = _fault_on_operative({"debug": True, "action": "block"}, {"debug": True, "action": "allow"},
                                       "verdict_type")
    assert not changed  # nothing operative can change type here: not exercised, never "held"
    out, _ = _fault_on_operative({"action": "BLOCKED", "blocked_reason": "GCL-BLOCKED"}, {"action": "NONE"},
                                 "unknown_verdict")
    assert out["action"] == "DENY_UNKNOWN" and out["blocked_reason"] == "GCL-BLOCKED"


def test_the_marker_counts_only_in_the_answer():
    meta = Observation(200, json.dumps({"choices": [{"message": {"content": "otra cosa"}}],
                                        "library_return": {"debug": "GCL-BLOCKED"}}), True, 0.1)
    assert classify(S, SENT, meta) == "altered"
    answer = Observation(200, json.dumps({"choices": [{"message": {"content": "GCL-BLOCKED"}}]}), True, 0.1)
    assert classify(S, SENT, answer) == "blocked after send"


def test_a_5xx_stays_failed_even_when_it_quotes_the_reply():
    err = Observation(500, json.dumps({"error": f"{S.reply_text} {S.reply_sentinel}"}), True, 0.1)
    assert classify(S, SENT, err) == "failed after send"


def test_echo_needs_an_explicit_field_and_uses_only_it():
    spec = {"vendor": "v", "allow_response": {"text": "ECHO_TEXT"}, "block_response": {"x": 1}}
    with pytest.raises(ValueError):
        vendor_protocol(spec)
    p = vendor_protocol({**spec, "scanned_path": "text"})
    body = {"text": "not the reply", "metadata": "model reply GCL-R-o02"}
    assert p.verdicts["allow"](body, "") == {"text": "not the reply"}
    assert p.scanned(body) == "not the reply"


def test_a_late_retry_is_answered_with_its_own_scenarios_behaviour():
    import urllib.request

    proto = Protocol(name="t", verdicts={"allow": lambda b, m: {"a": 1}, "block": lambda b, m: {"a": 0},
                                         "modify": lambda b, m: {"m": m}}, trust_listener=True)
    with StandInScanner(proto) as sc:
        sc.configure({"input": "modify"}, "first", sid="i01")
        sc.configure({"input": "allow"}, "", sid="i02")
        req = urllib.request.Request(sc.base_for("input"), data=json.dumps({"t": "x GCL-U-i01"}).encode())
        assert json.loads(urllib.request.urlopen(req, timeout=3).read()) == {"m": "first"}
        assert sc.events[-1]["mode"] == "modify" and sc.events[-1]["t_done"] is not None


def test_routes_are_checked_exactly():
    p = Protocol(name="t", verdicts={}, routes=("/v1/check", "/guards/<name>/validate"))
    assert _path_ok(p, "/v1/check?x=1") and _path_ok(p, "/guards/g1/validate/")
    assert not _path_ok(p, "/wrong") and not _path_ok(p, "/evil/v1/check")


def test_stage_inference_needs_exactly_one_scenario():
    assert _stage_by_sentinel({"m": "GCL-R-i01 GCL-R-o02"}) is None
    assert _stage_by_sentinel({"m": "GCL-U-i01 GCL-U-o02"}) is None
    assert _stage_by_sentinel({"m": "GCL-U-o02 GCL-R-o02"}) == "output"
