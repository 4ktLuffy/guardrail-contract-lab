"""Regressions for the ninth independent review: located violations, policy-fault
evidence, retry evidence, tool-run acceptance, ambiguous events, MCP session checks."""

import json
import urllib.request
from typing import ClassVar

from gcl.enforce.adapters import _invariant_block
from gcl.enforce.contracts import Result, Scenario, _judge
from gcl.enforce.servers import MockModel, Protocol, StandInScanner


class _A:
    known_issues: ClassVar[dict] = {}
    capabilities: ClassVar[set] = {"input", "output"}


def _r(stage, mode, observed, control, policy_expect="stopped", documented=None, **ev):
    sc = Scenario(f"{stage[0]}0{mode[:1]}", stage, mode, "es", "u", "r", control=control)
    base = {"scanner_consulted_stage": 1, "model_input": "passed", "settled": True}
    return Result(sc, observed, policy_expect, documented, evidence={**base, **ev})


def _controls():
    return [_r("input", "allow", "passed", True, "passed"), _r("input", "block", "stopped", True),
            _r("output", "allow", "passed", True, "passed"), _r("output", "block", "stopped", True)]


def test_invariant_violations_point_at_every_matching_message():
    body = {"messages": [{"content": "old GCL-U-i01"}, {"content": "plain"}, {"content": "retry GCL-U-i01"}]}
    ranges = [e["ranges"] for e in _invariant_block(body)["result"][0]["errors"]]
    assert ranges == [["messages.0"], ["messages.2"]]


def test_a_policy_fault_counts_only_when_delivered():
    missing = _r("input", "policy_missing", "stopped", False, scanner_consulted_stage=0, policy_answers=[200])
    served = _r("input", "policy_missing", "tool executed", False, scanner_consulted_stage=0, policy_answers=[404])
    _judge([*_controls(), missing, served], _A())
    assert missing.policy == "unverified" and served.policy == "violated"


def test_a_retry_needs_a_refused_first_attempt():
    bad = _r("input", "block_retry", "stopped", False,
             attempts=[{"status": None, "finished": False}, {"status": 404, "finished": True}])
    good = _r("input", "block_retry", "stopped", False,
              attempts=[{"status": 400, "finished": True}, {"status": 400, "finished": True}])
    _judge([*_controls(), bad, good], _A())
    assert bad.policy == "unverified" and good.policy == "held"


def test_tool_executed_conforms_to_passed_only_when_the_client_got_its_answer():
    ok = _r("input", "error", "tool executed", False, documented="passed", client_outcome="passed")
    failed = _r("input", "error", "tool executed", False, documented="passed", client_outcome="failed after send")
    _judge([*_controls(), ok, failed], _A())
    assert ok.documented == "conforms" and failed.documented == "deviates"


def test_ambiguous_events_prevent_a_clean_hold():
    r = _r("input", "error", "stopped", False, ambiguous_events=1)
    _judge([*_controls(), r], _A())
    assert r.policy == "unverified"


def test_policy_faults_leave_the_check_endpoint_healthy():
    proto = Protocol(name="t", verdicts={"allow": lambda b, m: {"ok": 1}, "block": lambda b, m: {"ok": 0},
                                         "modify": lambda b, m: {}}, trust_listener=True)
    with StandInScanner(proto) as sc:
        sc.configure({"input": "policy_missing", "output": "allow"})
        r = urllib.request.urlopen(urllib.request.Request(sc.base_for("input"), data=b'{"x": 1}'), timeout=3)
        assert json.loads(r.read()) == {"ok": 1} and sc.policy_fault == "policy_missing"


def test_mock_mcp_rejects_unknown_sessions_and_tools():
    with MockModel("r") as m:
        def rpc(msg, sid=None, stdio=False):
            h = {"Content-Type": "application/json", **({"Mcp-Session-Id": sid} if sid else {}),
                 **({"X-GCL-Transport": "stdio"} if stdio else {})}
            return json.loads(urllib.request.urlopen(urllib.request.Request(
                m.base + "/mcp", data=json.dumps(msg).encode(), headers=h), timeout=3).read())
        call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "gcl_probe", "arguments": {"note": "x"}}}
        assert "error" in rpc(call, "made-up-session")
        assert "error" in rpc({**call, "params": {"name": "not-a-tool", "arguments": {}}}, stdio=True)
        assert "result" in rpc(call, stdio=True)
        assert len(m.tool_events) == 1 and len(m.mcp_rejected) == 2
