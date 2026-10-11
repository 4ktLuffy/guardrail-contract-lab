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
  - Invariant Gateway MCP proxy (streamable HTTP with JSON responses; SSE and stdio
    transports are not modelled)
  - Lasso mcp-gateway `lasso` plugin (stdio MCP; the plugin's API URL is set by a
    launcher because its plugin manager passes no config)
  - Agno `OpenAIModerationGuardrail` (input only)
  - the bundled reference gateway
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

## What it cannot see
- Keyword rules cannot tell "disable the firewall" from "don't disable the firewall".
  `gcl` measures that as hard-negative false positives; it does not fix it.
- No input normalization testing yet for zero-width characters or bidi controls beyond
  NFD and case variants.
