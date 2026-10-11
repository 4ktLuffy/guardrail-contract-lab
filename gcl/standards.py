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

Sources (read 2026-10-11): OWASP Top 10 for LLM Applications 2025; OWASP Top 10 for
Agentic Applications 2026 (ASI01-ASI10); OWASP MCP Top 10 (2025, beta). Lists change;
the version of each is part of every ID.
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
    "MCP06:2025": "Intent Flow Subversion",
    "MCP08:2025": "Lack of Audit and Telemetry",
    "MCP10:2025": "Context Injection & Over-Sharing",
}
MCP_INTEGRATIONS = ("invariant-mcp", "lasso-mcp-gateway")
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
