# Changelog

## Unreleased

**New**
- `--extra mcp`: 16 MCP surfaces (tool results, errors, metadata, resources, prompts,
  notifications, sampling, SSE, nested arguments, unlisted tools, batches), each with a
  benign carry control that must arrive intact before the attack is judged.
- `reference-mcp`: the bundled MCP reference gateway, profiles `naive` and `strict`.
- A raw MCP client (standard library only) and mock MCP server surfaces: resources,
  prompts, SSE, sampling, `list_changed`, batches. The stdio bridge forwards every message.
- `surface_block` stand-in mode: blocks only text that carries an attack marker.
- `invariant-mcp` and `lasso-mcp-gateway` run the surfaces.
- `contextforge`: IBM ContextForge MCP gateway (profiles `default`, `enforce`, `ignore_error`,
  `permissive`), with a gcl-supplied scanner plugin loaded through ContextForge's own plugin framework.
- Surface results in the terminal, HTML, SARIF, `gcl compare`, `gcl table` and findings.
- `toolhive`: Stacklok ToolHive as an MCP gateway (profiles `fail`, `ignore`). `--env` is the
  `thv` binary or its folder; the mock MCP server runs as a remote workload (no container), with
  ToolHive's mutating and validating webhooks pointed at the stand-in. Request side only; needs a
  Docker-compatible runtime socket (`TOOLHIVE_DOCKER_SOCKET`, `DOCKER_HOST` or the docker context).
- `--mcp-protocol` (2025-03-26, 2025-06-18, 2025-11-25): the version the MCP client asks for. A
  surface the version does not have (m16 batches after 2025-03-26) is not run and reads n/a "not in
  protocol"; the report names the version the gateway's initialize answered. m02 is run in every
  session (a gateway that drops it gives n/a "not carried"). The terminal and HTML summaries count
  "not in protocol" apart from "not carried"; `report.json` gains `not_in_protocol` and
  `not_carried` next to `n/a`.
- `gcl demo`: a seventh step, the same enforce drill on an MCP gateway, with an MCP hero line.
- Stand-in flag `allow_unmarked`: a webhook that also sees traffic gcl never marked (a handshake)
  is answered allow instead of the scenario's verdict.

**Fixed**
- `block_retry` on MCP gateways that refuse inside the JSON-RPC answer (an `isError` result or an
  `error` object): only a response without any of the blocked text counts as a refusal, so a leak
  is never read as a stop.
- `modify` with a tool: a tool that ran with exactly the stand-in's rewrite and none of the
  original text is "modified", no longer "tool executed".
- Headline numbers: the README and NUMBERS.md said 16 of 22 gateway scenarios; the demo prints
  18 of 38 (strict build 0 of 38). MCP surfaces: 13 of 16 naive, 0 of 16 strict (2 more not carried).

**Standards**
- OWASP MCP02:2025 and MCP03:2025 added to the mapping.

## 0.3.0

gcl now checks the tester as well as the guardrail: a result it cannot back with evidence
from the run is reported as unverified or guessed, never as held or as a finding.

**Checks on the tester**
- Run receipts: a run id in every sentinel, gcl's commit and uncommitted files, installed
  versions with a check that installed files match the release, docs-version mismatch.
- Controls repeated at the end of the run, in every language used, and with a long reply;
  a block that ends in a server error is not a block.
- Delivery receipts from the stand-in; unmarked provider calls and answers from another
  run decide nothing; a timeout result caused by gcl closing the connection is unverified.
- An ordered boundary timeline per result; `--judge-latency` reports races as unstable.
- Stand-in provenance: results resting on a rebuilt or guessed vendor answer are labelled
  "guessed"; recorded replies count only for requests shaped like the recorded ones.
- `gcl findings`: a ledger that only accepts findings backed by stored runs, re-checks
  them, keeps retractions, and computes severity from fields.
- `gcl coverage` reports held-out and fit recall separately.

**New**
- `gcl record`: capture real vendor replies through a recording proxy and turn them into
  a vendor spec.
- `--attacks` / `--detector`: real attacks, a real detector's verdict, and guard faults
  at the same time.
- `--extra stream,history,retry`: streamed answers, attacks in an earlier turn, repeated
  requests (opt-in).
- OWASP LLM / Agentic / MCP Top 10 IDs on every violated result and in SARIF.
- `--format sarif`, `gcl compare` (regressions between two reports), a GitHub Action and
  a version-watch workflow.
- `gcl table`: integration × guard behaviour × version, private by default.
- Integrations: Coralogix (Aporia) guardrails for LangChain, Meta LlamaFirewall.

**Fixed**
- `python -m gcl.cli` lost every command defined after the module's main guard.
- Four independent review rounds (10-13); every defect is pinned by a regression test.

## 0.2.0

`gcl enforce`: end-to-end enforcement contracts for real guardrail integrations.
