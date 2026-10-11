"""The tester's own mistakes, stage 5: a result that rests on the exact shape of a
stand-in answer is only as good as that answer. Every stand-in says how it was built; a
result on a rebuilt or guessed answer is "guessed" (held or violated alike), and a
recorded real reply counts only for the request shape it was recorded for."""

import dataclasses
import sys
from types import SimpleNamespace
from typing import ClassVar

import pytest

from gcl.enforce.adapters import ADAPTERS, LITELLM_GENERIC, ReferenceGateway, vendor_protocol
from gcl.enforce.contracts import Result, Scenario, _stand_in_confidence, run_contracts

from .test_enforce import _by

KINDS = {"integration", "vendor_schema", "recorded", "client_code", "guessed"}


def test_every_built_in_stand_in_says_how_it_was_built():
    for name, cls in ADAPTERS.items():
        if name in ("litellm-vendor", "nemo-vendor"):
            continue  # per spec
        p = cls.protocol
        assert p.provenance in KINDS and p.provenance_source, name
    harness = {n for n, c in ADAPTERS.items() if c.harness_supplies_guard}
    assert harness == {"pydantic-ai", "guardrails-ai", "google-adk", "semantic-kernel"}


class _Rebuilt(ReferenceGateway):
    """The reference gateway, its stand-in labelled as rebuilt from client code."""

    protocol = dataclasses.replace(LITELLM_GENERIC, provenance="client_code",
                                   provenance_source="rebuilt for this test")
    documented: ClassVar[dict] = ReferenceGateway.documented


def test_results_on_a_rebuilt_stand_in_are_guessed_held_or_violated(tmp_path):
    naive = run_contracts(_Rebuilt(sys.executable, tmp_path / "n", "naive"), 15, only={"i04", "i09", "i11"})
    unknown, error = _by(naive, "input", "unknown_verdict"), _by(naive, "input", "error")
    assert unknown["policy"] == "violated" and unknown["evidence"]["confidence"] == "guessed"
    assert any(n.startswith("guessed") for n in unknown["notes"])
    assert error["policy"] == "violated" and error["evidence"]["confidence"] == "verified"  # transport fault
    assert naive["summary"]["guessed"] >= 1
    strict = run_contracts(_Rebuilt(sys.executable, tmp_path / "s", "strict"), 15, only={"i09"})
    held = _by(strict, "input", "unknown_verdict")
    assert held["policy"] == "held" and held["evidence"]["confidence"] == "guessed"   # a hold too


def test_the_same_run_on_an_integration_defined_stand_in_is_verified(tmp_path):
    run = run_contracts(ReferenceGateway(sys.executable, tmp_path, "naive"), 15, only={"i09"})
    assert _by(run, "input", "unknown_verdict")["evidence"]["confidence"] == "verified"
    assert run["integration"]["stand_in"]["provenance"] == "integration"


def _spec(**extra):
    return {"vendor": "acme", "requests": [{"path": "/v1/check"}], "allow_response": {"flagged": False},
            "block_response": {"flagged": True, "guess": 1}, **extra}


def test_vendor_specs_default_to_client_code_and_recorded_replies_replace_the_guess():
    assert vendor_protocol(_spec()).provenance == "client_code"
    rec = vendor_protocol(_spec(recorded={"block": {"flagged": True, "categories": ["jailbreak"]},
                                          "request_shape": {"messages": 1}, "source": "captured 2026-10-01"}))
    assert rec.provenance == "client_code" and rec.recorded_modes == ("block",)   # only what was recorded
    assert rec.recorded_shape == {"messages": 1}
    assert rec.verdicts["block"]({}, "") == {"flagged": True, "categories": ["jailbreak"]}
    assert vendor_protocol(_spec(provenance={"kind": "vendor_schema", "source": "https://x"})).provenance \
        == "vendor_schema"
    for bad in ({"provenance": {"kind": "trust-me"}}, {"provenance": {"kind": "recorded"}},
                {"recorded": {"source": "capture"}},                        # names no reply
                {"recorded": {"block": {"flagged": True}}}):                # no request shape
        with pytest.raises(ValueError):
            vendor_protocol(_spec(**bad))


def _result(mode, n_messages, policy="held"):
    s = Scenario("i09", "input", mode, "es", "u", "r")
    served = "block" if mode == "block_retry" else mode
    r = Result(s, "stopped", "stopped", None, policy=policy, evidence={
        "scanner_events": [{"mode": served, "body": {"messages": [{}] * n_messages}}]})
    return r


def test_a_recorded_reply_counts_only_for_the_request_shape_it_was_recorded_for():
    proto = dataclasses.replace(LITELLM_GENERIC, provenance="client_code", provenance_source="captured",
                                recorded_modes=("allow", "block"), recorded_shape={"messages": 1})
    adapter = SimpleNamespace(protocol=proto, harness_supplies_guard=False)
    same, other, retry = _result("block", 1), _result("block", 3), _result("block_retry", 1)
    _stand_in_confidence([same, other, retry], adapter)
    assert same.evidence["confidence"] == "verified"
    assert other.evidence["confidence"] == "guessed" and "messages=[3]" in other.notes[0]
    assert retry.evidence["confidence"] == "guessed" and "retry" in retry.notes[0]


def test_a_harness_supplied_guard_is_not_a_guess_about_a_vendor():
    adapter = SimpleNamespace(protocol=dataclasses.replace(LITELLM_GENERIC, provenance="guessed"),
                              harness_supplies_guard=True)
    r = _result("block", 1)
    _stand_in_confidence([r], adapter)
    assert r.evidence["stand_in"] == "harness" and r.evidence["confidence"] == "verified"
