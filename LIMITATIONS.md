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
- Eleven targets today (plus any LiteLLM or NeMo vendor guardrail from a spec file): LiteLLM's `generic_guardrail_api` (pre_call + post_call), NeMo
  Guardrails' `jailbreak detection model` input rail and self-check input/output rails, openai-guardrails' LLM checks, the
  Portkey gateway's `default.webhook` hooks, LangChain's `OpenAIModerationMiddleware`,
  Mastra's PromptInjectionDetector/ModerationProcessor, the OpenAI Agents SDK with
  `GuardrailAgent`, Pydantic AI's harness guardrails, CrewAI's `LLMGuardrail` (output only), and the bundled
  reference gateway.
- Where a framework ships no guard of its own (Pydantic AI), the driver supplies the
  strictest guard (allow only on an explicit allow, raise on anything else), so those
  runs test the framework's enforcement, not a vendor's guard.
- Tool probing uses one harmless tool called once on the first model turn; for agent
  adapters the stand-in judge answers after a fixed delay (1 s) to model a real LLM
  check, so races between a parallel check and the model are visible. With an instant
  judge some races are not.
- When one guard client serves both stages (one URL), refusing it refuses both, so the
  output-stage "refused" scenario is not run for it.
- Judges are told apart by a per-stage model name or URL where the integration allows
  it; otherwise by the markers in the request, and a request carrying both or neither
  is rejected rather than guessed.
- A guard that calls the same endpoint as the model (LLM-as-judge on a shared client)
  cannot be "refused" without refusing the model too, so that scenario is skipped for it.
  Libraries without a server run behind a small gcl driver: the library's block
  exception becomes HTTP 400, any other exception 500, a return value 200. The driver
  passes the full exception text and the full return value (every message or field the
  caller receives) to the client, so the judge sees what an application would see.
- Leak detection looks for the whole original, its marker, or any fragment of it (two
  consecutive words, or four characters in Chinese/Japanese). A paraphrase of the
  original is not detected.
  Results are for the versions recorded in the report (gcl records them; it does not pin
  them) and the configuration printed there.
- Synchronous, single-turn requests only. Streaming, multi-turn history, policy reload and
  retry behaviour are not tested yet.
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

## What it cannot see
- Keyword rules cannot tell "disable the firewall" from "don't disable the firewall".
  `gcl` measures that as hard-negative false positives; it does not fix it.
- No input normalization testing yet for zero-width characters or bidi controls beyond
  NFD and case variants.
