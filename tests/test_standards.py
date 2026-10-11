"""OWASP mapping: a risk is named only where the observed outcome is what it describes."""

import sys

import pytest

from gcl.enforce.adapters import ReferenceGateway
from gcl.enforce.contracts import run_contracts
from gcl.standards import TITLES, risks


@pytest.mark.parametrize(("args", "want"), [
    (("reference", "input", "block", "passed", "violated"), ["LLM01:2025"]),
    (("openai-agents", "input", "block", "tool executed", "violated"), ["LLM06:2025", "ASI02:2026", "LLM01:2025",
                                                                       "ASI01:2026"]),
    (("reference", "input", "error", "passed", "violated"), ["LLM01:2025", "ASI08:2026"]),
    (("reference", "input", "block", "blocked after send", "violated"), ["LLM02:2025"]),
    (("reference", "output", "block", "retained", "violated"), ["LLM05:2025"]),
    (("invariant-mcp", "input", "policy_missing", "passed", "violated"),
     ["LLM01:2025", "ASI08:2026", "MCP06:2025", "MCP08:2025"]),
    (("invariant-mcp", "output", "error", "passed", "violated"), ["LLM05:2025", "ASI08:2026", "MCP10:2025"]),
    (("reference", "input", "error", "stopped", "held"), []),
    (("reference", "input", "error", "passed", "unverified"), []),
])
def test_mapping(args, want):
    assert risks(*args) == want
    assert all(x in TITLES for x in want)


def test_results_and_sarif_carry_the_ids(tmp_path):
    from gcl.report.sarif import enforce_sarif

    run = run_contracts(ReferenceGateway(sys.executable, tmp_path, "naive"), 15, only={"i04"})
    r = next(x for x in run["results"] if x["scenario"]["id"] == "i04")
    assert r["evidence"]["owasp"] == ["LLM01:2025", "ASI08:2026"]
    tags = enforce_sarif(run, "x")["runs"][0]["results"][0]["properties"]["tags"]
    assert tags == ["LLM01:2025", "ASI08:2026"]
