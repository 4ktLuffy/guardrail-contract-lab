"""The reference MCP gateway (examples/enforce/ref_mcp_gateway.py) under the ordinary contract.
It runs everywhere, so CI exercises the MCP path end to end: strict keeps its fail-closed
promise, naive breaks it on the scanner-failure modes."""

import sys

from gcl.enforce.adapters import ReferenceMCPGateway
from gcl.enforce.contracts import run_contracts


def _controls_hold(run):
    ctl = [r for r in run["results"] if r["scenario"]["control"]]
    assert ctl
    assert all(r["policy"] == "held" for r in ctl), [(r["scenario"]["id"], r["policy"]) for r in ctl]


def test_reference_mcp_strict_holds_everything(tmp_path):
    run = run_contracts(ReferenceMCPGateway(sys.executable, tmp_path, "strict"), 10)
    assert run["summary"]["policy_violated"] == 0, run["summary"]
    assert run["summary"]["policy_held"] == run["summary"]["scenarios"]
    _controls_hold(run)


def test_reference_mcp_naive_fails_open_on_scanner_faults(tmp_path):
    run = run_contracts(ReferenceMCPGateway(sys.executable, tmp_path, "naive"), 10)
    _controls_hold(run)
    violated = [r for r in run["results"] if r["policy"] == "violated"]
    assert len(violated) == 18  # 9 scanner faults x input/output
    assert {r["scenario"]["mode"] for r in violated} <= {
        "error", "timeout", "malformed", "empty", "wrong_schema", "unknown_verdict", "verdict_type",
        "refused", "null_verdict"}
