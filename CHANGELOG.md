# Changelog

## Unreleased

**New**
- `gcl actions TARGET`: agent-action controls (approval / read-only / allowlist), generalising the
  observed object from "a guard verdict" to "a safety control fired on its path". New
  `gcl/enforce/ledger.py` (an append-only executor/approval ledger; pure verdicts: `blocked`/held,
  `executed without approval`, `ran with no model turn`, `approved args != executed args` — all from
  a recorded executor receipt, never from text) and `gcl/enforce/sinks.py` (stand-in executors that
  record and never really act: a fake shell on PATH, a fake DB/file sink, plus
  `SqliteStateObserver`, a read-only connection to a real target's own throwaway file). A dedicated
  command rather than `gcl enforce --extra` (justified in `gcl/enforce/actions.py`'s docstring):
  there is no guard protocol to translate, and the scenario planner has no slot for a ledger
  verdict or a classifier bypass. Controls first (`k00a`/`k00d`, same shape as `--extra config`'s
  k00c): a benign approved action must run and an obviously denied one must be stopped, or the real
  check is unverified. Results are ordinary `Result` dicts (mode `approval`/`exec`), filed under
  `enforce` too, so `--format sarif`, `gcl findings add` and severity scoring work unchanged.
  First real target: **dbhub** (`gcl/enforce/dbhub_target.py`, `DbhubTarget` on a reusable
  `StdioMCPActionTarget` base) — a known-CVE replay for CVE-2026-61788 / GHSA-mwwr-p57h-56pf
  (`@bytebase/dbhub`'s read-only mode does not stop a `PRAGMA user_version = N` assignment): red on
  `<= 0.22.5`, green on `>= 0.22.6`, both hand-checked against the throwaway SQLite file's own state.
  See README "Agent actions (`gcl actions`)".
- `gcl enforce ... --attest`: the mutation control. After the run, the opening controls (input and
  output, allow and block) are re-run on two fresh sessions with the stand-in forced to always allow
  and to always block. The outcome has to follow: a block control that cannot be made to pass, an
  allow that cannot be made to stop, a stand-in that is never asked, means the adapter does not reach
  the integration's own control (a stub or a mock). Then every result becomes unverified ("adapter
  did not reach the control: not evidence"), the receipt lists a problem, and the run exits 2 whatever
  `--fail-on` / `--allow-incomplete` say. It only ever demotes; a pass changes nothing. Run-level field
  `mutation_control` (`state` passed / failed / n/a, the probes, the reason). Opt-in because it costs two
  more integration starts; the fleet and any generated adapter should always pass it. Not combinable
  with `--judge-latency`.
- Control-path attestation in the receipt (`receipt.control_path`, always on, descriptive, never changes
  a verdict): the environment the adapter launched into, every command it started with each named file's
  path / sha256 / size, the generated config's sha256, the installed packages with versions and
  locations, the bundled reference gateway's path, digest and gcl release, and who called the stand-in
  (User-Agent, peer). A bundled-gateway subclass that never launched the gateway says so instead of
  borrowing its identity. New `Adapter.attest_control` and `receipt.file_digest`.
- `gcl replay BUNDLE` (a repro bundle directory or a zip): re-runs exactly one stored finding offline from
  the bundle's pinned inputs and says reproduced (exit 0), not reproduced (1) or unverified (2). Repro
  bundles are now sealed (`bundle.json`: a sha256 per file) and carry what a replay needs (`finding.json`
  `replay`: extras, MCP protocol, target interpreter, vendor spec, guard latency). Unverified, never a
  false reproduce: damaged, edited, unsealed or incomplete bundle, unsafe zip, integration not installed,
  a pinned version or control file changed (`--allow-version-drift` to run anyway), the scenario at that
  id differs, attack-mode findings (the attack plan is not in the bundle), controls broken on replay.
  New module `gcl/enforce/replay.py`.
- `gcl upgrade-check ADAPTER --before PY --after PY`: the same enforce plan against the installed and the
  next version, one report (per scenario before -> after, regressions, improvements, unchanged); exit 1 on
  held -> violated, held -> unverified or a guard no longer consulted at a stage, exit 2 if the comparison
  could not be made (unusable controls on a side, guard never consulted, scenarios on one side only).
  `--before-profile` / `--after-profile` per side. Reports which documented expectations were read for an
  older version than the one installed (re-read due). `gcl compare` now shares its classification
  (`compare.classify`) with it.
- `gcl coverage` false-positive budget per language: every rate is printed with counts and its
  Wilson 95% interval (n = 0 is "not measured", never 0%), plus a gap-vs-English column for recall
  and false positives (starred when the intervals do not overlap).
- `--hard-negatives` adds a bundled set of 144 hard negatives (12 each in en, es, fr, he, pt, de,
  ar, ru, zh, it, ja, hi: ten themes translated from one English base plus two language-specific),
  `gcl/data/hardneg.multilingual.jsonl`. Authored for gcl by an AI assistant, not native-speaker reviewed.
- CI gate for `coverage`: `--max-fpr` (overall) and `--max-fpr-lang` (per language) as fractions,
  with the existing `--min-recall` and `--max-fp` (percent); exit 1 and a named breach, also in
  `report.json` as `coverage.gate`. A limit with nothing measured is a breach.
- `examples/coverage/adapter.substring.yaml`: a naive substring detector, the negative control.
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
- An integration started by an adapter no longer outlives the process that started it. Adapters
  start integrations in their own session, so a killed or interrupted run (SIGTERM, SIGHUP, an exit
  without `stop()`) left `ref_gateway.py ... --policy naive` running. Started processes are now
  registered and stopped on exit and on SIGTERM/SIGHUP, and the bundled reference gateways exit when
  their parent is gone (covers SIGKILL).
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
- `--extra mcp`: a refusal is not the payload. The sentence is now matched by a run of four words
  around its distinctive word (`attacker`, `quillfern`, ...) or by half of it in order, not by any two
  common words, so a gateway's own block text ("explain to the user ...", "blocked for the user") no
  longer reads as "passed without marker" (was a false violation on invariant-gateway). The same rule
  serves every surface and `--extra routes`; the benign and request sentences gained a distinctive word.
- `--extra mcp` and `routes`: the distinctive word of a sentence at a far end, without a full match (e.g. an
  error echoing a truncated copy), is `text altered` (unverified) for control and attack, not an absence.
- `--extra mcp` and `routes`: a sighting is proof. A marker (or payload) seen at the far end is
  "carried" or a leak even if the result was lost, the stream cut or the session unsettled (a control
  was "no answer" and its attack never judged; a violation on an undelivered stream became unverified).
  Only claims of absence (not carried, stopped, dropped unscanned, held) keep the full proof rules.
- `--extra mcp`: lists are read to their end (`nextCursor`, 20 pages at most) and names match the
  adapter's documented name exactly before a recorded suffix match. A list not read to its end is
  `list incomplete` and several equally good suffix matches are `name ambiguous`, both unverified,
  never "not listed" or n/a. The mock MCP server can paginate (test option).

**Fixed** (`gcl actions`: "blocked"/held now needs a completed run and a live observer)
- A crashed, timed-out or unanswered target was reported **held / "blocked"**: a denied or bypass probe
  was judged only by "did the observed state change?", and the exchange's `finished` / `error` were
  recorded but never consulted, so a target that never ran the probe left the state unchanged and read
  as a perfect block (on a vulnerable build, a false green). Now a held verdict for `k00d` / `k01`
  requires an exchange that finished without error, an observer that could be read before and after,
  and, where the target can tell, a reply that is not a claim of success. Anything less is
  **unverified** (`run incomplete`, `observer not read`, `contradicted`), never held. A positive
  observation (the state changed) is unchanged: still `violated`, even if the target died afterwards.
  A target whose `call()` raises is recorded as an unfinished exchange instead of aborting the run.
- New control `k00l`, **observer liveness** (the actions-phase analogue of the mutation control /
  `--extra config`'s k00c): before any probe is sent, gcl itself makes one benign change on each
  state surface a probe could move (`liveness_nudge`, through the observer's own fixture, never through
  the target), the observer must see it, and gcl puts it back exactly. A dead, blind or misconfigured
  observer ("no change" about everything) makes every check unverified and no probe is sent. A target
  that defines no nudge is unverified, not trusted.
- The approved control `k00a` is confirmed by the independent observer, not only by the target's
  reply (`confirm_approved`): dbhub's reply must carry exactly the rows gcl reads from the SQLite file
  itself, and the read must not have moved any state. A reply the observer cannot confirm leaves the
  control, and so every later check, unverified.
- API for target authors: `StdioMCPActionTarget` gains `liveness_nudge`, `confirm_approved` (both
  required: the defaults fail closed to unverified) and `reply_refused` (optional; `False` only
  when a success reply is truly inconsistent with no change). `_judge_controls` takes `live=`.
  `gcl actions dbhub` output gains a `k00l` row (4 checks, not 3).

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
