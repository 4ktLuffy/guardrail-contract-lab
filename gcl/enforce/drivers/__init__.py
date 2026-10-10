"""Drivers: tiny HTTP fronts for guardrail *libraries* (no server of their own).

A driver runs inside the integration's own runtime (`--python` or `--env`), imports the
library, and serves /v1/chat/completions by calling the library's documented API. It
translates outcomes to HTTP: a library exception that signals a block becomes 400, any
other exception 500, a returned result 200, with what the library returned passed along
as `library_return`. Drivers for libraries that do guarding (openai-guardrails, LangChain,
Mastra, Agno, CrewAI, Lasso/Invariant gateways, ...) never inspect guardrail results.
Drivers for frameworks that ship no guard (Pydantic AI, Google ADK, Semantic Kernel,
Guardrails AI) supply one — gcl's strictest — and that guard does read the scanner's
verdict; those runs test the framework's enforcement of it.
"""
