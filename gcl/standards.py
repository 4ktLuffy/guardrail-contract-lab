"""Which OWASP risks a result is evidence about.

The mapping is gcl's judgement, kept small and explicit so a reader can disagree with a
line rather than with a black box. It names a risk only where the observed outcome is
the thing the risk describes:

  an attacker's input reached the model despite a block or a failed guard
      LLM01:2025 Prompt Injection; ASI01 Agent Goal Hijack (agent integrations)
  a reply the guard should have stopped reached the caller (or stayed in what the
  library returns)
      LLM05:2025 Improper Output Handling
  the provider received a prompt the client was told was blocked
      LLM02:2025 Sensitive Information Disclosure
  a tool ran although the request should have been stopped
      LLM06:2025 Excessive Agency; ASI02 Tool Misuse and Exploitation
  any of the above because the guard failed (fail-open)
      ASI08 Cascading Failures (a failure in one component disabled the protection)
  through an MCP proxy: requests MCP06:2025 Intent Flow Subversion; tool results and
  replies MCP10:2025 Context Injection & Over-Sharing; a missing policy that silently
  disables the guard MCP08:2025 Lack of Audit and Telemetry
  an MCP surface (`--extra mcp`, SURFACE_RISKS below) whose attack text reached the far end
  unstopped: tool results, errors, notifications and SSE events MCP03:2025 Tool Poisoning
  + MCP10:2025 + LLM01:2025; tool metadata (description, title), server instructions and a
  rug pull MCP03:2025 + LLM01:2025;
  resources and prompts MCP10:2025 + LLM01:2025; a sampling request MCP06:2025 + LLM01:2025;
  a nested argument or a batch MCP06:2025; a call to an unlisted tool MCP02:2025 Privilege
  Escalation via Scope Creep + ASI02:2026 + LLM06:2025
  a configuration check (`--extra config`, CONFIG_RISKS below) whose policy did not apply, so the
  request the guard should have stopped reached the model: LLM01:2025 (a policy that failed to load,
  a tightening edit, the scope itself); a failing component that disabled the protection (the load
  failure only) also ASI08:2026 Cascading Failures. A stricter-than-configured outcome (loosening,
  outside the scope) leaked nothing and has no tags.

MCP06:2025 is titled "Prompt Injection via Contextual Payloads" on the OWASP project page
and "Intent Flow Subversion" in the project's repository file; the ID is the same, and the
repository title is kept here.

Sources (read 2026-10-11): OWASP Top 10 for LLM Applications 2025; OWASP Top 10 for
Agentic Applications 2026 (ASI01-ASI10); OWASP MCP Top 10 (2025, beta): the project page
and the repository files for MCP02, MCP03, MCP06, MCP08 and MCP10. Lists change; the
version of each is part of every ID.
"""

from __future__ import annotations

TITLES = {
    "LLM01:2025": "Prompt Injection",
    "LLM02:2025": "Sensitive Information Disclosure",
    "LLM05:2025": "Improper Output Handling",
    "LLM06:2025": "Excessive Agency",
    "ASI01:2026": "Agent Goal Hijack",
    "ASI02:2026": "Tool Misuse and Exploitation",
    "ASI08:2026": "Cascading Failures",
    "MCP02:2025": "Privilege Escalation via Scope Creep",
    "MCP03:2025": "Tool Poisoning",
    "MCP06:2025": "Intent Flow Subversion",
    "MCP08:2025": "Lack of Audit and Telemetry",
    "MCP10:2025": "Context Injection & Over-Sharing",
}
MCP_INTEGRATIONS = ("invariant-mcp", "lasso-mcp-gateway", "contextforge", "toolhive")
AGENT_INTEGRATIONS = ("openai-agents", "openai-agents-js", "pydantic-ai", "google-adk", "semantic-kernel",
                      "crewai", "agno", "mastra")
VERDICTS = ("allow", "block", "modify", "block_retry")


FAULT_MODES = ("error", "timeout", "malformed", "empty", "wrong_schema", "unknown_verdict", "verdict_type",
               "refused", "null_verdict", "judge_refusal", "policy_missing", "policy_error")
LEAKS = ("passed", "altered", "blocked after send", "failed after send", "tool executed", "retained")


def risks(integration: str, stage: str, mode: str, observed: str, policy: str) -> list[str]:
    """OWASP IDs this one result is evidence about; [] for a hold, an unverified result, or
    a violation in which nothing leaked (a refused rewrite, an over-block)."""
    if policy != "violated" or observed not in LEAKS:
        return []
    out: list[str] = []
    if observed == "tool executed":
        out += ["LLM06:2025", "ASI02:2026"]
    if stage == "input" and observed in ("passed", "altered", "tool executed", "failed after send"):
        out.append("LLM01:2025")
        if integration in AGENT_INTEGRATIONS:
            out.append("ASI01:2026")
    if observed == "blocked after send":
        out.append("LLM02:2025")
    if stage == "output" and observed in ("passed", "altered", "retained"):
        out.append("LLM05:2025")
    if mode in FAULT_MODES:
        out.append("ASI08:2026")
    if integration in MCP_INTEGRATIONS:
        out.append("MCP10:2025" if stage == "output" else "MCP06:2025")
        if mode == "policy_missing":
            out.append("MCP08:2025")
    return list(dict.fromkeys(out))


_RESULT = ["MCP03:2025", "MCP10:2025", "LLM01:2025"]
# MCP surface -> OWASP IDs, applied to a violated attack result (see mcp_surfaces.py).
SURFACE_RISKS = {
    **{sid: _RESULT for sid in ("m00", "m01", "m02", "m03", "m04", "m05", "m11", "m13")},
    **{sid: ["MCP03:2025", "LLM01:2025"] for sid in ("m06", "m07", "m08", "m17", "m18")},
    **{sid: ["MCP10:2025", "LLM01:2025"] for sid in ("m09", "m10")},
    "m12": ["MCP06:2025", "LLM01:2025"],
    "m14": ["MCP06:2025"], "m16": ["MCP06:2025"],
    "m15": ["MCP02:2025", "ASI02:2026", "LLM06:2025"],
    # tool-shaped text the model reads (descriptions, annotations, links, templates, results, errors)
    **{sid: ["MCP03:2025", "LLM01:2025"] for sid in ("m21", "m22", "m24", "m25", "m23")},
    **{sid: _RESULT for sid in ("m20", "m29", "m31", "m33")},
    # server requests the client forwards to a person or a model
    **{sid: ["MCP06:2025", "LLM01:2025"] for sid in ("m26", "m27", "m34")},
    # what the client sends out
    **{sid: ["MCP06:2025"] for sid in ("m19", "m28", "m30", "m32")},
}


def surface_risks(surface_id: str) -> list[str]:
    return list(SURFACE_RISKS.get(surface_id, []))


# Config check -> OWASP IDs, applied to a violated result (see config_checks.py).
# Keyed on the check kind (the part before ":"), not on an id number: ids depend on the adapter.
CONFIG_RISKS = {"load_failure": ["LLM01:2025", "ASI08:2026"], "live_tighten": ["LLM01:2025"],
                "scope_in": ["LLM01:2025"]}


def config_risks(kind: str) -> list[str]:
    return list(CONFIG_RISKS.get(kind.split(":")[0], []))


# Ledger verdict -> OWASP IDs, applied to a violated result (see ledger.py, actions.py). All
# three are a tool/action running when the configured control (approval, read-only, allowlist)
# said it must not: excessive agency and tool misuse, same tags `risks()` gives "tool executed".
ACTION_RISKS = {
    "executed without approval": ["LLM06:2025", "ASI02:2026"],
    "ran with no model turn": ["LLM06:2025", "ASI02:2026"],
    "approved args != executed args": ["LLM06:2025", "ASI02:2026", "ASI01:2026"],
}


def action_risks(observed: str) -> list[str]:
    return list(ACTION_RISKS.get(observed, []))
