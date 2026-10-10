"""Drivers: tiny HTTP fronts for guardrail *libraries* (no server of their own).

A driver runs inside the integration's own Python (`--python`), imports the library,
and serves /v1/chat/completions by calling the library's documented client API. It
translates outcomes to HTTP only: a library exception that signals a block becomes 400,
any other exception 500, a returned completion 200. It never inspects guardrail results.
"""
