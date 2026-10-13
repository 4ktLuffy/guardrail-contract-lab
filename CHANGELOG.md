# Changelog

## Unreleased

**New**
- `gcl evidence-pack REPORT.json ... --out DIR` and `gcl evidence-verify DIR`: a compliance evidence pack
  from stored reports. Maps check families to EU AI Act (2024/1689 as amended by 2026/1744), NIST AI RMF
  1.0, NIST AI 600-1 and OWASP ids (reused from `gcl/standards.py`), each row with a reason and a
  strength (direct / supporting). Coverage matrix with held, violated, unverified, not tested and not
  applicable cells and counts; unverified is never promoted. Manifest with SHA-256 of every input and
  output plus each run's receipt; optional `--sign-key` HMAC-SHA256 (integrity, not identity). Dates block,
  a "considered, not mapped" list, ISO/IEC 42001 listed as not mapped. New modules `gcl/frameworks.py`,
  `gcl/evidence.py`.
- `--extra config`: is the configured policy the one that runs. A policy that fails to load must
  not allow everything; a live edit (tighten, loosen, once per edit mechanism) must take effect; a
  scoped policy must apply to its scope and only to it. Two stand-in scanners of gcl's own (A allows,
  B blocks) prove which policy was running; a check is never held without that receipt. Runs on
  `reference` and `litellm`; other adapters refuse it. New adapter interface: `config_checks`, `config_scopes`,
  `load_failures`, `edit_mechanisms`, `propagation_s`, `start_policy`, `edit_policy`, `call_scope`,
  `StartRefused`, `CheckUnavailable`.
- The reference gateway takes `--policy-file` (guards with scopes, re-read on change, fail closed);
  profile `naive` reproduces the LiteLLM failures (ignored edits, scoped guards that match nothing,
  a broken file that allows everything).
- `--extra config` on LiteLLM: four load failures, live edit through `PATCH` and `PUT /guardrails/{id}`
  (needs `GCL_LITELLM_DATABASE_URL`, a Postgres database used only for this), and a model-scoped policy.
- Config results carry a documented verdict (`Adapter.config_documented`, `config_documented_sources`),
  shown with its quoted passage in the terminal and HTML tables.
- OWASP mapping for config results: LLM01:2025 where a request that should have been stopped passed;
  ASI08:2026 (Cascading Failures) only on a policy that failed to load.
- Severity: a config result is trigger "configuration not applied" (0), not an operator mistake (-1).
- A stop outside the policy's scope without scanner B consulted is unverified, not violated.

- `--extra mcp`: sixteen more surfaces, m19-m34, each with a carry control and an attack and
  version-gated: `completion/complete` argument (m19) and values (m20), resource templates
  (m21 description, m22 uriTemplate), `resource_link` items (m23), tool `outputSchema` descriptions
  (m24), tool `annotations.title` (m25), elicitation message (m26), requestedSchema (m27), the
  client's answer (m28) and URL mode (m34), `notifications/progress` message (m29), the client's
  `roots/list` answer (m30), `_meta` on results (m31) and requests (m32), JSON-RPC error `data` (m33).
  The reference MCP gateway holds all of them in `strict` and leaks all of them in `naive`.
  `mcp_client.Answers` lets a session put text into what the client answers to server requests;
  `resources/templates/list` is paged like the other lists. On the table a surface not in the
  negotiated protocol reads "not in protocol", not "not carried".

- `--extra routes`: is the same guard on every route to the same action. An adapter declares `routes`
  (`reference` and `litellm`: chat completions, streamed, `/v1/messages`, `/v1/responses`,
  `/v1/completions`; MCP gateways: `tools/call`, a batch, a direct call to a hidden tool,
  `resources/read`, `prompts/get`, which run as the surfaces m00, m16, m15, m09, m10). Each route gets a
  carry control and an attack in the request and in the reply, with the surfaces' proof rules (not
  carried is n/a and needs a proper 404/405/501 or a 200 without the text; never held), and a parity
  summary: one route held and another violated is "parity broken", naming both. Results are mode
  `route` (ids r01..), with a section in the terminal and HTML reports, SARIF rules `GCL-E-route-*`,
  compare, findings and the table (a `routes` column).
- The reference gateway serves `/v1/messages`, `/v1/completions` and `/v1/responses` besides chat
  completions (anything else is 404) and answers `stream: true` as an event stream; `strict` guards every
  route, `naive` only chat completions (the LiteLLM #40583 shape). The mock model also serves
  `POST /responses` and `/completions`, which LiteLLM calls when it carries `/v1/messages` and
  `/v1/completions`.

**Fixed** (`--extra mcp`: results are now reported only with full proof)
- A reply counts as an answer only if it is a valid JSON-RPC 2.0 response: `jsonrpc` "2.0", exactly
  one of `result` / `error`, an error with an integer `code` and a string `message`. `error: null`,
  both members or a missing `jsonrpc` no longer end as "not carried" or "dropped unscanned".
- The surface's own request must have been sent and answered. An initialize error ends as the new
  unverified outcome "handshake failed", a skipped step as "probe not sent", never n/a or held.
  m17's handshake and m18's list must be answered too.
- A session that did not settle is "unsettled" (unverified), not held or n/a; a proven leak stays
  violated. `evidence.settled` records it.
- "stopped" and "passed despite block" need a block answer whose delivery is confirmed; a missing
  delivery receipt is "unconfirmed".
- m00 judges the note in and the reply out each on the stand-in events that carry its own marker.
- `--extra mcp`: observe everything. stdio sessions read until the server has been quiet (0.3 s,
  at most 2 s) after the last answer instead of killing it with notifications still queued; over
  HTTP the standalone GET stream is opened after the handshake and what arrives on it counts (a
  405 is recorded as `evidence.standalone_stream`); a stream that cannot be watched makes an
  absence-based result the new unverified outcome `stream not observed`.
- `--extra mcp`: the payload counts, not only the marker. A gateway that strips `GCL-A-...` but
  forwards the injection sentence is the new violated outcome `passed without marker` (was
  "stopped" or "dropped unscanned"); a control whose marker is stripped but whose benign sentence
  arrives whole is `carried, marker stripped` (held, the attack then runs; was n/a), a partly
  arrived one is the unverified `text altered`.
- `--extra mcp`: m00's reply out has its own sentences (no shared fragment with the note in), and
  the argument of every other session is a third benign sentence, so a refusal that quotes what it
  refuses cannot read as the other end's text arriving ("passed without marker" without proof).
- `--extra mcp`: lists are read to their end (`nextCursor`, 20 pages at most) and names match the
  adapter's documented name exactly before a recorded suffix match. A list not read to its end is
  `list incomplete` and several equally good suffix matches are `name ambiguous`, both unverified,
  never "not listed" or n/a. The mock MCP server can paginate (test option).

## 0.4.0 — 2026-10-12

**New**
- `--extra mcp`: 18 MCP surfaces (tool results, errors, metadata, server instructions, tool
  titles, resources, prompts,
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
  18 of 38 (strict build 0 of 38). MCP surfaces: 15 of 18 naive, 0 of 18 strict (2 more not carried).

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
