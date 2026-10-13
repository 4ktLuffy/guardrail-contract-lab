# Limitations

What `gcl` does not do, or does only partly. Read this before quoting a number from it.

## Engines
- Two engines: Python `re` (the reference) and JavaScript `RegExp` via Node. No RE2
  (Go, Envoy), Rust `regex`, Java, .NET or PCRE yet. Each would be a new runner
  speaking the same JSON-lines protocol (`gcl/engines/`).
- Bun runs JavaScriptCore, not V8. The divergence classes `gcl` checks are defined by
  the ECMAScript spec and behave the same there (checked against macOS JavaScriptCore
  by hand), but the test suite runs Node only.
- The loader's flags are an input (`--py-flags`, `--js-flags`, or a per-rule `flags:`
  key in JavaScript notation). If you pass the wrong ones, the results describe a
  loader you do not have. For Python, only `i`, `m`, `s` of a per-rule flag string carry
  over; `g`, `y`, `u`, `d`, `v` do not change what `search()` finds.
- Rule sets embedded in code (regex literals in TypeScript, lists in Python) must be
  extracted into YAML/JSON first; there is no source-code extractor yet.

## Rule samples and witnesses
- Positive samples are generated from Python's parse tree, without running the rule.
  Back-references, lookarounds and conditionals are approximated; a rule counts in
  `rules_without_samples` unless an engine confirmed one of its samples matches, and is
  then only tested on your cases and the bundled texts.
- "Engines agree on every text we tried" is not a proof of equivalence. `gcl fix` is
  verified on samples, boundary probes and 288 texts, not formally. Its letter classes
  are exact only for the scripts it names (by Unicode character name, BMP only); next to
  letters of other scripts or astral-plane letters a rewrite can differ from Python.
- Case folding: rewrites spell out every case partner Python's `re.IGNORECASE` accepts
  (dotless i, long s, Kelvin/Angstrom/Ohm signs, Greek variant forms…) for literals,
  escaped literals and classes, region by region for scoped `(?i:)`/`(?-i:)`. Rules with
  other scoped modifiers (`(?s:…)`, `(?m:…)`, `(?x:…)`) are not rewritten. A JavaScript
  loader using the `u` flag folds differently again and is not modelled.
- Witnesses are shrunk by delta debugging for at most 60 steps: usually 1-minimal, not
  always (the finding says when shrinking hit the limit), and never globally smallest.
  An input that hangs a rule is reported as found, not shrunk (each try could cost a
  deadline); if no single input hangs it alone, the finding says that instead.

## Coverage numbers
- The bundled 288 cases are machine-written (`native_reviewed: false`). Amharic and
  Arabizi wording is the least certain. Use your own reviewed cases for decisions.
- 12 attacks per language: a 0/12 has a 95% interval up to 24%. The report prints
  intervals for that reason; don't drop them when quoting.
- Recall on a fixed set measures the set. Rules tuned against it will score high on it.
  Rows marked `"heldout": true` are reported separately; with none, the report says every
  number is fit. gcl cannot check that a row marked held out really was written
  independently and before the rules: that is the author's declaration.

## Trust
- Manifests are executable: `gcl` runs the commands they name. Process groups,
  deadlines and output caps limit the damage of a buggy command, not a malicious one.

## Probe
- Needs a system whose scanner location comes from an environment variable (URL or
  command) and whose protected action can write a receipt file. Systems that hard-code
  their scanner need a small shim.
- Fault modes are the common ones (timeout, 5xx/exit 1, malformed, empty, wrong schema,
  refused). Partial responses, slow-drip bodies and TLS failures are not simulated.
- A violation shows that one request path fails open. It does not show every path does.

## Enforce
- Offline by design: a scripted stand-in scanner and a mock model replace the real
  services. Results show how the integration's own enforcement code handles the scripted
  inputs — not detector accuracy, production networking, or every configuration.
- Nineteen built-in targets, plus any LiteLLM or NeMo vendor guardrail described by a
  spec file:
  - LiteLLM `generic_guardrail_api` (pre_call + post_call)
  - NeMo Guardrails: `jailbreak detection model`; self-check input/output
  - openai-guardrails LLM checks (Python and JavaScript); the OpenAI Agents SDK with
    `GuardrailAgent` (Python and JavaScript)
  - Portkey gateway `default.webhook` hooks
  - LangChain `OpenAIModerationMiddleware`
  - Mastra PromptInjectionDetector / ModerationProcessor
  - Pydantic AI harness guardrails; Google ADK model callbacks; Semantic Kernel filters;
    CrewAI `LLMGuardrail`
    (output only)
  - Guardrails AI `Guard` (Python API and RAIL)
  - Invariant Gateway MCP proxy (streamable HTTP; the ordinary contract gets JSON replies,
    and SSE replies are exercised only under `--extra mcp`, by m08, m11, m12 and m13; the
    stdio transport is not modelled)
  - Lasso mcp-gateway `lasso` plugin (stdio MCP; the plugin's API URL is set by a
    launcher because its plugin manager passes no config)
  - Agno `OpenAIModerationGuardrail` (input only)
  - the bundled reference gateway
- LlamaFirewall returns a decision and leaves enforcement to the caller: gcl's driver
  refuses on BLOCK and calls the model otherwise, as the README shows, so its results test
  the library's decision under judge failures. Only the PII check is driven (the other
  LLM scanners hard-code their endpoint). Coralogix is driven through `invoke` and
  `stream` of a wrapped ChatOpenAI; its guard API is rebuilt from the client's schema, so
  verdict-shape results are labelled guessed.
- When gcl releases a stalled guard call (the scenario ended) and the integration only
  then reacts, the timeout result is unverified: it reacted to a closed connection.
- Where a framework ships no guard of its own (Pydantic AI, Google ADK, Semantic Kernel, Guardrails AI), the driver supplies the
  strictest guard (allow only on an explicit allow, raise on anything else), so those
  runs test the framework's enforcement, not a vendor's guard.
- Tool probing uses one harmless tool called once on the first model turn; for the
  Agents SDK and Pydantic AI adapters the stand-in answers after a fixed delay (1 s) to
  model a real LLM check, so races between a parallel check and the model are visible. With an instant
  judge some races are not.
- When one guard client serves both stages (one URL), refusing it refuses both, so the
  output-stage "refused" scenario is not run for it.
- Judges are told apart by a per-stage model name or URL where the integration allows
  it; otherwise by the markers in the request: exactly one scenario's markers are
  required (an output check may carry that scenario's user turn), anything else is
  rejected rather than guessed.
- Vendor specs cover vendors that answer one POST per check with a fixed body (plus the
  checked text via ECHO_TEXT and an explicit `scanned_path`). Multi-step protocols,
  response headers and websocket streams are not modelled.
- A guard that calls the same endpoint as the model (LLM-as-judge on a shared client)
  cannot be "refused" without refusing the model too, so that scenario is skipped for it.
  Libraries without a server run behind a small gcl driver: the library's block
  exception becomes HTTP 400, any other exception 500, a return value 200. The driver
  passes the exception's text, repr and attributes, and the return-value fields the
  library's docs tell callers to use: close to, not provably, everything a caller
  could inspect.
- Leak detection looks for the whole original, its marker, or any fragment of it (two
  consecutive words, or four characters in Chinese/Japanese). A paraphrase of the
  original is not detected (a scenario that receives one is unverified, not held).
  Results are for the versions recorded in the report (gcl records them; it does not pin
  them) and the configuration printed there.
- Synchronous, single-turn requests only. Streaming, multi-turn history and policy reload
  are not tested yet; retry after a block is tested for the Invariant MCP adapter only.
- The client deadline (default 45 s) is absolute. A scenario with no complete answer by
  then is "unverified" — unless the original text already reached the model, which is a
  proven leak and is judged as "passed" whatever the client saw.
- After each answer gcl waits for both observers to go quiet (0.6 s, at most 15 s) and
  attributes events by sentinel over the whole run, so a call that lands later is still
  charged to its scenario. A call that arrives after the run ends is not seen.
- An input-stage "stopped" means nothing reached the model for that scenario; an
  output-stage "stopped" means a complete HTTP response arrived without the reply. A
  dropped connection is "transport failure" and is never counted as held.
- "Documented" expectations are taken from each project's docs for a stated version; the
  report prints the source, the version and the passage relied on. When the docs are
  silent, the verdict says "unspecified".

## Checks on the tester (receipts and bracketing controls)
- Every run carries a run id in every sentinel (user, reply, rewrite and tool markers). An
  answer that carries another run's id, or no run id, (an integration's cache, a replay) is
  not evidence for either a leak or a stop, and a client reply with no model call
  behind it makes a "stopped" unverified. A cache keyed on text without the markers that
  returns a *refusal* is not detected.
- The receipt records gcl's commit, uncommitted and untracked files and a hash over its
  source, and the integration's distributions as its own interpreter imports them. Install
  integrity is checked only for Python distributions whose RECORD carries hashes; Node
  packages are reported by version only. The docs-version check compares versions named in
  the "read for" text with the installed ones; a docs page that names no version is not
  checked.
- Controls run again after the last scenario, plus an allow control in every language a
  judged scenario used and an allow with a ~6,000-character reply. If one of them fails, a
  clean result that depends on it is unverified; a proven leak still counts. A driver that
  cuts answers only beyond 6,000 characters, or a setup that breaks and recovers between
  the brackets, is not detected.
- A block control that ends in a server error (5xx) is not accepted as a block: it cannot
  be told from an integration that crashed on the stand-in's answer.
- The stand-in records whether each answer reached a connected client (it checks for a
  closed peer before writing). A peer that closes in the instant between that check and
  the write is not seen.
- A provider call charged to a scenario only by its time window, with no marker and no
  fragment of that scenario's text, is left out of the verdict and makes a clean result
  unverified. A rewrite that shares no two consecutive words with the original is
  therefore never reported as a leak — only as unverified.
- Every result carries an ordered timeline (guard asked / answered, provider received, tool
  ran, client answered) and flags a provider call or tool run that came before the guard's
  answer. Times are gcl's clock at its own boundaries, not the integration's.
- `--judge-latency 0,0.2,1` runs the whole contract once per guard latency and reports
  results that change as unstable (a race); the report shows the slowest run in full, the
  JSON keeps every run, and repro bundles go to one folder per latency. Each latency is a
  full run, so the time multiplies.
- Every stand-in says how its answers were built: defined by the integration under test
  (an LLM judge's format, its own webhook or guardrail API), a third party's published
  schema, recorded real replies, rebuilt from the integration's client code, or guessed.
  A result that rests on the exact shape of an answer (allow, block, rewrite, retry, and
  the unknown / wrong-type / null verdict faults) on a rebuilt or guessed stand-in is
  labelled "guessed", held or violated alike: it shows what the integration did with that
  answer, not with the real vendor's. The Invariant and Lasso stand-ins and every vendor
  spec without recorded replies are rebuilt from client code. A spec may carry recorded
  real replies (`"recorded": {"block": ..., "request_shape": {"messages": 1}}`); each
  counts only for its own verdict (a fault built from allow and block needs both) and only
  when the request positively shows the recorded message count — a retry, another count,
  or a request without a message list is still guessed. Whether a label is right is a
  human judgement; gcl only carries it.
- `null_verdict` sets the verdict field to null (unknown and falsy) where the protocol's
  block answer is JSON; plain-text judges do not get it.

## Attack mode, recording, CI
- Attack mode sends attacks as user input only, one request each, at most 100 scenarios per
  run (`--attack-limit`). The detector's verdict is computed once per attack text, before
  the run; the stand-in serves it in the integration's protocol, so the result shows how
  the integration enforces that verdict — the detector itself is not called in the loop.
- `gcl record` forwards HTTP(S) requests and JSON or text answers; streaming answers,
  websockets and request signing that covers the Host header are not handled. Redaction is
  by field name; a secret in a field with an innocent name is stored.
- `gcl compare` matches scenarios by stage, guard behaviour, role and language; runs of
  two different gcl versions may plan different scenarios, listed as "only in old/new".
- The GitHub Action and the version-watch workflow are tested for their structure, not run
  on GitHub from this repository.

## Blind spots, standards, table
- Streaming and history scenarios are opt-in and only for adapters that pass a message list
  and a `stream` flag through (LiteLLM, Portkey, the reference gateway). A guard that sees
  the earlier turn under a different text (summarised, truncated) still counts as "shown
  the attack" only if the marker survives. Generic retry is two separate calls; it is
  judged only after a first refusal (a 4xx, or an answer carrying the stand-in's block
  reason).
- The OWASP mapping is gcl's judgement, versioned per list, and names a risk only for
  violated results; the lists themselves change.
- A disclosure unhides exactly the finding's own scenario (stage, behaviour, role,
  language, latency, stream/history, attack) on the versions its runs were made on;
  other versions stay withheld until disclosed. Contradicted or retracted findings unhide
  nothing.
- A history scenario whose conversation reached the model without the earlier turn in
  recognisable form (dropped or summarised) is unverified: gcl cannot tell a safe drop
  from a summary of the blocked text.

## Config applied (`--extra config`)
- Only the adapters that implement it (`reference` and `litellm`). Propagation of a live
  edit is waited for (the adapter's documented time plus 0.5 s), not polled: an integration that
  applies edits later than it documents reads as "old policy kept running". One guard per policy;
  combinations of guards and scopes beyond one scope are not tested.
- LiteLLM: the live-edit checks need a database (`GCL_LITELLM_DATABASE_URL`) and only test guardrails
  created through the management API (config-file guardrails cannot be edited: 404). The edit is
  waited for 1.5 s (the endpoint updates the live guardrail before it answers; the 30 s periodic
  database sync is for other instances and runs only with `store_model_in_db: true`, which gcl does not
  set), so an edit that applies only at the next sync reads as "old policy kept running". Scope is the model name; teams, keys and tags are not tested. LiteLLM's docs
  say nothing on whether a guardrail change applies without a restart and nothing on a guardrail that
  fails to load, so only the in-scope check has a documented verdict.
- LiteLLM's MCP-scope case (issue #41680) is not reachable with gcl's stand-in guard on any released
  LiteLLM: attachments have no MCP-server dimension (teams, keys, models, tags only), the
  `generic_guardrail_api` guard that gcl points at its scanners cannot run on MCP traffic (its modes
  are `pre_call`, `post_call`, `during_call`; the MCP modes are skipped at start-up), and the fix that
  lets policy guardrails run on MCP output (PR #41334) is not merged. It needs a guard type that runs
  on MCP traffic, plus that PR.

## MCP surfaces (`--extra mcp`)
- Shapes of protocol versions 2025-03-26 to 2025-11-25 only. gcl negotiates 2025-03-26 unless
  `--mcp-protocol` asks for another. Some surfaces were introduced later (m02 `structuredContent`
  and `outputSchema` in 2025-06-18): at 2025-03-26 a gateway that enforces the negotiated version
  may legitimately not carry them, and the surface is then "not carried" (n/a), not a failure;
  rerun with `--mcp-protocol 2025-06-18` to test m02. A surface the requested version does not
  have (m16 batches, only in 2025-03-26, at later versions) is not run and reads n/a "not in
  protocol". The version reported is the one the gateway's initialize answer named, else the one
  asked for. The 2026-07-28 specification
  (no `initialize`, no sessions, multi-round-trip requests in place of server-to-client
  requests, sampling and logging deprecated) is not covered yet.
- ToolHive (`toolhive`) is tested on the request side only, by design: its webhooks are sent what
  a client sends to the server and never a server reply, so there is no output side to test. The
  webhook also sees the MCP handshake and notifications gcl never marked, which the stand-in
  allows (`allow_unmarked`), so those requests prove nothing about the verdict. ToolHive's state
  (config, run configs, status) is kept in the run's own folder, never the real home; it still
  needs a Docker-compatible runtime socket to start.
- m02 is run at every protocol version, so at 2025-03-26 it asks a gateway for a field that
  version does not define: a gateway that drops it is "not carried", one that passes it unscanned
  is reported as it is.
- Encodings and obfuscation (zero-width characters, Unicode tags, base64) are not tested
  here. They are a detector question for `gcl coverage`.
- OAuth and authorization flows are not tested.
- Tool pinning, a changed tool reaching the client unscanned, is seen only through m08.
- Names of proxied tools, prompts and resources are read back from the same session's own
  `tools/list`, `prompts/list` and `resources/list` (the entry ending in `gcl_probe` /
  `gcl-probe`, `gcl_prompt`, `note`), with the adapter's `mcp_name` as the fallback when the
  list is not a proper result. m15 uses `mcp_name` for its unlisted tool by design. A
  proper list (every page, `nextCursor` followed up to 20 pages) that does not show the item
  makes the surface "not carried"; a list not read to its end is "list incomplete". The
  adapter's documented name is matched exactly; only if it is not listed does the entry ending
  like it count, recorded as "matched by suffix" (several such entries: "name ambiguous").
- The attack is judged on its marker and on its sentence. The sentence is looked for with the
  ordinary contracts' fragment rule (any distinctive word pair of ATTACK_TEXT), so a gateway
  that strips the marker and forwards the sentence reads "passed without marker" (violated),
  also if only part of the sentence survived. A sentence a gateway paraphrases or encodes (no
  fragment left) is not seen: that reads as stopped or dropped. The benign control is "carried"
  without its marker only if the whole sentence arrived (case, punctuation and spacing aside);
  part of it is "text altered" (unverified). For m14 only `arguments.meta` is searched, since
  the benign note travels beside the payload there.
- m19-m34: one field per surface (m21 description but not name, m23 description but not name or
  uri, m25 `annotations.title` only since the other hints are booleans, m27 one property
  description). A gateway that scans only some fields of a place reads as held for the field
  tested. Each field and the protocol version it first
  appeared in (`since`) were checked against `schema/<version>/schema.ts` of github.com/modelcontextprotocol/modelcontextprotocol (versions 2025-03-26, 2025-06-18, 2025-11-25). Task-augmented
  and other 2025-11-25 additions beyond URL-mode elicitation are not covered. m29 is sent only
  to a request that carries a progress token, as the specification requires of a server. m30
  and m28 judge the client's answer where the mock server received it; a gateway that rewrites
  the answer before the server is seen as "stripped"/"altered" like any other surface.
- A sentence found at a far end must be that far end's own: m00's reply out has sentences of its
  own, and gcl's requests carry a note no payload shares a fragment with. A gateway that quotes the
  text it blocks back to the client (the same surface's payload) is still counted as that
  payload arriving, as it did before the payload search: the sentence did reach the model.
- Server-to-client traffic outside the replies is watched, not provoked: over HTTP the
  standalone GET stream is opened once after the handshake and read until it has been quiet for
  0.3 s (at most 2 s); a 4xx answer (405 is the spec's "none") is recorded as "refused". Traffic
  a server sends later than that, or only on a stream opened by another request, is not seen. A
  stdio server is watched the same way after its last answer. If the stream cannot be opened or
  dies, or a server is still sending at the cap, absence-based outcomes become "stream not
  observed".
- The stdio adapter (`lasso-mcp-gateway`) starts a gateway per session.
- `contextforge` caches a backend's tools, prompts and resources at registration; the adapter
  re-registers the mock server when the surface or payload changes (provisioning, not a
  scenario). Rate limiting is switched off so registration is not refused with 429. A block
  arrives as HTTP 200 with `isError: true`, which the retry check does not read as a refusal:
  `block_retry` is unverified there.
- "not carried" is not a pass. It means the gateway did not carry the surface at all, so no
  claim is made about its scanning. The attack is not sent in that case.
- Real-gateway surface runs are opt-in (`GCL_INTEG_INVARIANT_PYTHON`, `GCL_INTEG_LASSO_PYTHON`)
  and are not in CI.

## Route parity (`--extra routes`)
- A route is one way to reach the same action, as declared by the adapter; routes it does not declare
  are not tried (embeddings, files, audio, other vendors' paths). Whether a guard *should* apply to a
  route is the adapter's declaration, not gcl's opinion.
- The request is one user message and the reply one assistant message. Tool calls, images, multi-turn
  history and system prompts on the other routes are not sent: a gateway that guards only some content
  types of a route reads as held.
- "Not carried" needs HTTP 404, 405 or 501, or a 200 in which the text did not arrive. A gateway that
  answers a missing route with another status (400, 403, 500) is unverified, not n/a. A route that
  fails because gcl's mock model lacks the upstream shape would read the same: the mock serves chat
  completions, `/responses` and `/completions`, and a gateway that translates to anything else gets
  404 from the mock (an unexpected upstream path is recorded in `unexpected`). LiteLLM answers
  `429` ("all deployments in cooldown") on later routes after such a failure, which is unverified.
- Streaming is judged on what the client received: the marker or the sentence anywhere in the event
  stream is a leak, even if an error event follows (LiteLLM 1.105.0 streams the first chunks of a blocked
  reply before the error).
- The MCP routes are the surfaces m00, m16, m15, m09 and m10: their limits are the surfaces'. The route
  table copies their outcome; it adds no second judgement.
- Parity compares the routes of one adapter against each other. Two routes that are both unguarded are
  "equal" (and violated): parity says nothing about whether the guard exists.

## Findings ledger
- Severity is a fixed, published rule over a few fields, not a CVSS score. "Documented"
  comes from gcl's own map of each integration's docs (quoted in every report); "default
  configuration" is read from the profile name unless a person sets it. Both can be wrong;
  `findings set` records a correction and its reason.
- "Repeated" is a second gcl run: it rules out flakiness, not a wrong stand-in. Only a
  confirmation with recorded or live vendor answers rules that out, and gcl cannot verify
  what a reproduction file actually did — it checks the declaration and that gcl's own
  stand-in answers are not reused verbatim.
- `check` compares newer runs only when they are in the folder it is given.

## Evidence pack (`gcl evidence-pack`)
- It is technical test evidence, not a conformity assessment and not legal advice. The mapping from
  results to provisions is gcl's reading of the text, kept as data in `gcl/frameworks.py` so it can be
  disputed line by line. gcl tests a guardrail integration against stand-ins, not a deployed AI system;
  most rows are therefore "supporting", and a "held" cell says the tests gcl ran held, not that a
  provision is met.
- ISO/IEC 42001 is not mapped: iso.org blocked every fetch and Annex A is a paid standard, so no
  control text was read and none is cited.
- The OWASP MCP Top 10 is in Beta; its ids (and titles) are provisional. `gcl/standards.py` keeps the
  repository's title for MCP06:2025 ("Intent Flow Subversion"), the project page prints "Prompt
  Injection via Contextual Payloads"; the id is the same.
- EU AI Act text was read from the Publications Office copies of the Official Journal (EUR-Lex was not
  reachable). The corrigendum to Regulation (EU) 2026/1744 dated 2026-09-29, the corrigenda to 2024/1689
  and the 2026-07-27 consolidation were not read. A text search of the Omnibus found no amendment to
  Arts 9, 12, 13, 15, 26 or 55; that is a search, not a legal review. No harmonised standard was found
  cited in the Official Journal, so no presumption of conformity can be claimed.
- Art 55(1)(a) (adversarial testing) applies to providers of general-purpose AI models with systemic
  risk and to the model; the attack-corpus and MCP rows are context for such a provider at most.
  Art 12 (the system's own logs) is not mapped: gcl's run records are records of a test.
  MS-2.7-007 asks for red-teaming; a scripted corpus is not a human red team.
- The pack cell is the worst state of all results in that check family across all inputs. Mixing a
  `strict` and a `naive` run shows "violated"; the per-report table and the lists of violated and
  unverified scenario ids keep them apart. Mix only runs you mean to compare.
- `gcl coverage` stores recall but no pass/fail threshold, so its languages count as unverified in the
  pack, with the numbers beside them. A `gcl check` report has no mapping and is only hashed.
- The HMAC covers `manifest.json` (which holds the hashes); it is not a signature by a responsible
  person as Annex IV 2(g) describes. The key is read from a file, never from the command line.

## What it cannot see
- Keyword rules cannot tell "disable the firewall" from "don't disable the firewall".
  `gcl` measures that as hard-negative false positives; it does not fix it.
- No input normalization testing yet for zero-width characters or bidi controls beyond
  NFD and case variants.
