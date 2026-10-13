# Guardrail Contract Lab


AI-agent guardrails are usually a file of detection rules plus some glue: a scanner
that reads tool output or tool calls, and code that decides what happens next. The
config can look complete while the protection is not there:

- **Rules that half-run.** The same rule file is loaded by a Python service and a
  JavaScript/TypeScript hook. `(?i)`, `(?P<name>…)` and `\Z` are Python syntax;
  `\w` and `\b` are Unicode in Python and ASCII in JavaScript. So some rules never
  compile in the JS runtime — and a loader that wraps the compile in `try/catch`
  drops them without a word — while others compile and quietly stop matching
  non-English text.
- **Coverage that collapses by language.** A rule set that catches 90%+ of English
  attacks can catch nothing in Arabic, Hebrew or Chinese. One aggregate number hides it.
- **Scanners that fail open.** When the classifier times out, returns a 500 or
  garbage, the tool call runs anyway.
- **Decisions that don't control the action.** The scanner says "block" or "redact",
  but the gateway forwards the original anyway — or treats a verdict it doesn't
  recognise as "allow".

`gcl` checks whether deployed guardrail policies are loaded, evaluated and enforced
consistently — against your real rule files, real integrations and real systems — and
produces reproducible evidence when they are not: a shrunken witness string for a rule
that disagrees or over-fires, the input that hangs a rule, and for enforcement the exact
boundary events (what reached the model, what the client got back). Red-teaming tools
(garak, PyRIT) attack the model or the app, and Promptfoo can also test guardrail
services directly; `gcl` concentrates on the guardrail's own rules, runtimes and failure
contract.

## 60 seconds

```bash
git clone https://github.com/4ktLuffy/guardrail-contract-lab && cd guardrail-contract-lab
uv venv && uv pip install -e .     # Python 3.11+, and Node for the JavaScript engine
gcl demo --open
```

On the bundled fixtures (written for the demo; see [NUMBERS.md](NUMBERS.md)):

| | |
|---|---|
| **4 of 9** rules | never compile, or silently stop matching, in JavaScript (and 1 more runs in quadratic time) |
| **0** after `gcl fix` | 8 rules rewritten; each agrees with the original under Python on every tested input before it is written |
| **91.7% → 0.0%** | recall in English vs Arabic for the same, reasonable, English rule set |
| **6 of 6** scanner faults | still let the tool call run, in a fail-open tool runner (0 of 6 after the fix) |
| **18 of 38** gateway scenarios | break a gateway's own fail-closed promise, end to end (0 of 38 for the strict build) |
| **15 of 18** MCP surfaces | reach the client or server unscanned through a naive MCP gateway (0 of 18 for the strict build; 2 more not carried) |

## Commands

### `gcl check RULES` — does every rule run the same in every engine?

```bash
gcl check rules.yaml --engines python,node --out report/
```

For each rule it:

1. **lints** the source for engine-dependent syntax (`GCL101`–`GCL110`);
2. **compiles** it in every engine — a compile failure is reported on its own, never
   folded into "no match";
3. **runs** it on strings it is *meant* to match (generated from the rule's own parse
   tree, so every rule is tested even with no cases), on Unicode-normalization
   variants, on your `--cases`, and on 144 bundled benign texts in 12 languages —
   in every engine, per rule, so one rule cannot mask another;
4. **shrinks** each disagreement to a short witness (delta debugging, capped at 60 steps;
   the finding says if the cap was hit):
   `"забудь инструкци"` — python: match, node: no match;
5. **times** it on adversarial long inputs at two sizes and reports the *growth*: a
   rule that is fast at 2 KB but n² (seconds at 32 KB) is flagged even though no static
   check can see it; a rule that hangs is killed, named, and the run continues.

Loader flags are inputs: `--py-flags IM --js-flags gi` for the whole file, or a
`flags:` key per rule (JavaScript notation, as most rule files keep it). Time rules at
your loader's real input cap with `--max-len 50000` to get a measured verdict rather
than an extrapolation. A rule that hangs comes with the single input that hangs it
whenever that input can be isolated (the report says when it cannot).

Exit codes for CI: `0` clean, `1` findings at or above `--fail-on`, `2` incomplete
(a requested engine is missing — never reported as a pass) or unusable input. Writes `report.json`
(the record), `report.html`, and `report.sarif` (annotates the exact line of the rule
file in code-scanning UIs).

### `gcl fix RULES` — make them portable, and verify it

```bash
gcl fix rules.yaml            # writes rules.portable.yaml next to it
```

Rewrites only what it can rewrite exactly: a leading `(?i)` the loader already
applies, `\A`/`\Z`, `{,n}`, un-back-referenced `(?P<name>…)`, `.`/`^`/`$` (into forms with
Python's line semantics), and `\w`/`\b` (into explicit letter classes, with single
lookarounds where the neighbouring token is provably a letter). **Every rewrite is verified before it is
written**: the new rule must agree with the original under Python, in every engine, on
the rule's own samples, on those samples with letters and non-letters of every in-scope
script glued to each side, and on 288 bundled texts; a rewrite with no tested input that the original matches is refused
(agreement would prove nothing). Letter classes contain exactly the characters Python's
`\w` matches among every Basic-Multilingual-Plane character whose Unicode name starts
with the rule's scripts (LATIN…, CYRILLIC…; Latin always, widen with `--scripts`), plus
common word characters (digits, super/subscripts, fractions, fullwidth forms). The
rewrite is exact for text made of those characters; next to letters of other scripts,
or astral-plane letters, it can differ — and the output names each rewrite's scope. Anything it cannot
verify (a rule that hangs) or cannot fix safely (scoped modifiers, script-blind
classes) is left untouched and reported. Comments and layout in the YAML survive.

### `gcl coverage` — how much of each language does it catch?

```bash
gcl coverage --rules rules.yaml --engines python,node
gcl coverage --adapter my-guardrail.yaml --cases my-cases.jsonl --min-recall 50
```

Per-language recall with Wilson 95% intervals, false positives on plain benign text
and on *hard negatives* (benign text that uses the trigger words: "ignore the blank
rows", "run the test suite"), an intent × language grid, and — with several engines —
the same rules side by side per runtime.

**False alarms next to gaps.** Every rate is printed as counts plus its Wilson interval
(`2/12 = 16.7% [4.7-44.8]`), never a bare percentage, because per language the samples are
small; a language with no cases of a kind says "not measured", not 0%. A gap-vs-English
column gives the difference in points for recall and for false positives, starred only
when the two intervals do not overlap. `--hard-negatives` adds gcl's own set: 12 benign
texts that look risky in each of en, es, fr, he, pt, de, ar, ru, zh, it, ja, hi (144 rows):
ten themes translated from one English base (a security guide about injection, a quoted
attack asked about, "ignore" / "system" / "password" in everyday use, code and config,
medical, legal, send-a-report-with-a-link, a magician's secret) plus two
language-specific ones each (ordinary words that contain a trigger stem, and "forget the
old schedule"). They were written for gcl by an AI assistant and are **not
native-speaker reviewed**; treat them as a smoke test for false alarms, not a benchmark.
Note the bundled attacks cover 12 other languages, so pt, it, ja and hi get a false-positive
rate here but no recall.

```bash
gcl coverage --adapter my-guardrail.yaml --hard-negatives --max-fpr 0.05 --max-fpr-lang 0.10 --min-recall 50 --out reports
```

CI gate: `--min-recall` (percent, any language), `--max-fpr` (overall) and `--max-fpr-lang`
(any language) as fractions (`0.05` = 5%); `--max-fp` is the older percent spelling of
`--max-fpr-lang`. The run exits 1 and prints each breach with its counts and interval
(`THRESHOLD BREACHED: false-positive rate in pt: 8/12 = 66.7% [39.1-86.2] ...`); the same
breaches are in `report.json` under `coverage.gate`. An incomplete run exits 2, and a limit
that nothing was measured against is a breach, not a pass. The gate compares the observed
rate; with 12 texts a pass of 0/12 still allows a true rate near 24%, which is why the
interval is printed. SARIF is not written for `coverage`.
`examples/coverage/adapter.substring.yaml` is a deliberately naive word-list detector, the
negative control: a real guardrail should do clearly better on `--hard-negatives`.

Any guardrail can be measured, not only regex files: an **adapter** is a command that
reads `{"id","text"}` JSON lines and writes `{"id","flagged"}` lines. A case with no
answer is recorded as *incomplete*, never as "not flagged".

Bundled cases: 12 attack intents × 12 languages (en, es, fr, de, ru, he, ar, zh,
**Amharic, Swahili, Arabizi, code-switched**) plus 6 benign and 6 hard-negative texts
each — 288 rows, machine-written, marked `native_reviewed: false`. The optional
hard-negative set (above) is a separate 144-row file, `gcl/data/hardneg.multilingual.jsonl`.

### `gcl probe ADAPTER` — when the scanner fails, does the action still run?

```bash
gcl probe examples/failopen/runner.fail-open.yaml --contract examples/failopen/contract.yaml
```

Points your system at a stand-in scanner (via the env var it already reads: a URL for
HTTP scanners, a command line for subprocess scanners) and injects faults: `timeout`,
`error`, `malformed`, `empty`, `wrong_schema`, `refused`. Whether the protected action
really ran is read from a **receipt** the action writes — not from logs. Two controls
run first (scanner says *malicious* → must block; *clean* → must allow). If the clean
control leaves no receipt, every fault result is **unverified**, never "held".
The contract says what each fault must do; the default is fail closed.

### `gcl enforce INTEGRATION` — does the integration enforce what its scanner decides?

```bash
gcl enforce reference --python python3 --profile naive        # bundled reference gateway
gcl enforce litellm --python /path/to/venv/bin/python --profile default --out report/
gcl enforce nemo    --python /path/to/venv/bin/python --out report/
gcl enforce openai-guardrails --python /path/to/venv/bin/python --profile pre_flight
gcl enforce portkey --env /dir/with/node_modules --profile fail_on_error
```

Drives a **real** guardrail integration end to end, offline: LiteLLM's proxy guardrails
(`generic_guardrail_api`, before and after the model call), NeMo Guardrails' built-in
jailbreak-detection and self-check rails, openai-guardrails' LLM checks in Python and JavaScript (a small driver serves the
library over HTTP), the Portkey gateway's webhook guardrails (Node: `--env DIR`), LangChain's
OpenAI moderation middleware, Mastra's model-backed processors, the OpenAI Agents SDK (Python and JavaScript) with
openai-guardrails' `GuardrailAgent`, Pydantic AI's harness guardrails, Google ADK's model callbacks, Semantic Kernel's filters, CrewAI's `LLMGuardrail`, Guardrails AI's `Guard` (Python API and RAIL), Coralogix (Aporia) guardrails for LangChain models (`coralogix-langchain`, Node), Meta
LlamaFirewall's LLM-judged PII check (`llamafirewall`), Invariant Gateway's MCP proxy and Lasso's
mcp-gateway (gcl plays the MCP client and a mock MCP server, over HTTP or stdio), Agno's built-in guardrails, the bundled
reference gateway (`reference`), IBM ContextForge's MCP gateway (`contextforge`: ContextForge ships no
plugin that calls an HTTP scanner, so gcl's driver supplies one and the run tests ContextForge's plugin
framework — hook dispatch, modes, `on_error`, timeout), Stacklok ToolHive's MCP proxy (`toolhive`: `--env DIR` is the `thv` binary or its folder; gcl's mock MCP server runs as a remote workload, so no container or image, but ToolHive needs a Docker-compatible runtime socket to start even then: `TOOLHIVE_DOCKER_SOCKET`, else `DOCKER_HOST`, else the current docker context; its webhooks see the request side only), or the reference gateway's MCP variant (`reference-mcp`, profiles `naive` and `strict`). A report notes when one request ran a tool more than once (retries that
re-execute side effects). The Invariant MCP adapter also runs a retry scenario (the same
blocked request sent twice in one session), and integrations that fetch their rules get
policy-source faults (the policy is missing, or its source errors). Agent integrations run with a
probe tool: the mock model calls it first, so a tool that runs despite a block is
reported as "tool executed". LLM-as-judge guards get a stand-in
judge on the model's own endpoint, including the case where the judge model *refuses*
to answer. The integration runs from
its own environment (`--python`), unmodified. A stand-in scanner answers its real
protocol with **allow, block or rewrite**, or misbehaves (HTTP 500, timeout, malformed,
empty, missing verdict field, unknown verdict, the right verdict in the wrong type
(`"false"` as a string, `"blocked"` in lower case), refused), one stage at a time. Two
independent observers record what happened: a mock model (what exactly reached the
provider, and when?) and the client (what exactly came back?). Payloads are compared
whole, so a gateway that strips the marker but forwards the text, keeps part of the
original in a rewrite, or forwards a second after rejecting the client is caught; a
check that runs alongside the model call is reported as "blocked after send" — the client
was refused, but the provider already saw the prompt; and a reply that is refused in the
answer but still returned in the library's result is "retained". Adapters translate protocols only and never interpret a verdict — except where a
framework ships no guard of its own (Pydantic AI, Google ADK, Semantic Kernel, Guardrails AI): there the driver
supplies the strictest guard, and the run tests the framework's enforcement.

Every scenario gets **two verdicts**: *policy* (strict fail-closed) and *documented*
(does it match the integration's own docs for this configuration? the report quotes the
passage and the version it was read for). A fail-open you switched on is reported as a
configuration choice, not a bug; behaviour the docs don't cover is labelled as such.
Four controls (allow and block, before and after the model) are judged first, and only
if the scanner was really consulted with that scenario's text; if a control doesn't
hold, what depends on it is **unverified**, never "held", and the run exits 2. The controls
run again at the end (the setup must still work), in every language a scenario used, and
with a long reply (a driver that cuts answers cannot hide a leak); a block that ends in a
server error does not count as a block. The stand-in keeps a receipt of what actually
reached the integration, and every report carries a run receipt: a run id in every
sentinel, gcl's commit and uncommitted files, and the integration's installed versions
with a check that the installed files match the release. Each result has an ordered
timeline of its boundary events; `--judge-latency 0,0.2,1` re-runs the contract at several
guard latencies and reports results that change with timing (races) as unstable. Every
stand-in says how it was built; a result that rests on the shape of a stand-in answer
rebuilt from client code or guessed is labelled "guessed" (it still counts for the exit code).
Payloads rotate through Spanish, French, Hebrew, Portuguese, German, Arabic, Russian,
Chinese, Italian, Japanese and Hindi, so a rewrite that corrupts the text is caught
too. `--out` writes the report and a reproduction bundle for every scenario that did not
cleanly hold: every attributed event, the generated config, and the command that reruns
just that scenario (`--scenario ID`).

#### Vendor guardrails from a spec file

LiteLLM and NeMo Guardrails each ship dozens of vendor guardrail integrations. For vendors
that answer one POST per check, describe the vendor once instead of writing an adapter:

```json
{"vendor": "acme", "guardrail": "acme", "litellm_params": {"api_key": "x"},
 "requests": [{"path": "/v1/check"}], "supported_modes": ["pre_call", "post_call"],
 "allow_response": {"flagged": false}, "block_response": {"flagged": true}}
```

```bash
gcl enforce litellm-vendor --spec acme.json --python /path/to/venv/bin/python
gcl enforce nemo-vendor --spec acme-nemo.json --python /path/to/venv/bin/python
```

The real integration code runs unmodified; only the vendor's API is replaced. NeMo specs
name the input/output flows and the `rails.config` block, with `STANDIN_URL` where the
endpoint goes.

#### Real attacks, a real detector, and faults at the same time

```bash
gcl enforce litellm --python /path/to/venv/bin/python --attacks attacks.jsonl \
    --detector my-detector.yaml --attack-faults error,timeout --attack-limit 8
```

Each attack (JSON lines, the `coverage` format) is sent once with the stand-in answering
what your detector decided about that exact text, and once per fault. The detector is a
`coverage` adapter: wrap Prompt Guard, LlamaFirewall or a vendor API in a small script.
The report separates what the detector missed (a detector problem), what it flagged but
the integration let through (an enforcement problem) and what leaked while the guard was
failing (fail-open), per attack.

#### Record real vendor replies

```bash
gcl record serve --upstream https://api.vendor.example --out rec.jsonl --port 8899
# point the integration's vendor URL at http://127.0.0.1:8899, send one clean and one bad request
gcl record to-spec rec.jsonl --spec vendor.json --allow 1 --block 2 --out vendor.recorded.json
```

The proxy forwards everything unchanged and never stores request headers; secret-looking
JSON fields are redacted. The spec then serves the vendor's real answers, and results on
them are "recorded", not "guessed" — for requests shaped like the recorded ones.

#### Blind spots, opt-in

`--extra stream,history,retry` adds, after the usual plan: output checks on a **streamed**
answer (an output guard that blocks after the text was already streamed is a leak), the
attack in an **earlier turn** behind a benign follow-up (a guard that checks only the last
message is caught: the stand-in blocks only when it is shown the attack), and a blocked
request **sent twice** for any integration. Streaming and history run where the adapter
can send them (LiteLLM, Portkey, the reference gateway).

#### MCP: every place a message can carry text (`--extra mcp`)

The MCP checks above test one path: `tools/call` arguments `note` going in, and
`result.content[0].text` coming back. `--extra mcp` adds 34 more surfaces, each a place an
MCP message can carry text to the model or out of the agent:

| id | surface |
|---|---|
| m01 | tool result, second content item |
| m02 | tool result, `structuredContent` |
| m03 | tool result, embedded resource |
| m04 | tool result, `isError` |
| m05 | JSON-RPC error message |
| m06 | tool description |
| m07 | tool schema description |
| m08 | rug pull (`tools/list_changed`, then a poisoned list) |
| m09 | resource content |
| m10 | prompt content |
| m11 | log notification in the stream |
| m12 | sampling request in the stream |
| m13 | result as an event stream |
| m14 | nested argument |
| m15 | call to an unlisted tool |
| m16 | call inside a JSON-RPC batch |
| m17 | server `instructions` in the initialize result |
| m18 | tool `title` |
| m19 | `completion/complete` argument going out (2025-03-26+) |
| m20 | `completion/complete` values coming back |
| m21 | resource template `description` |
| m22 | resource template `uriTemplate` |
| m23 | `resource_link` item in a tool result (2025-06-18+) |
| m24 | tool `outputSchema` description (2025-06-18+) |
| m25 | tool `annotations.title` |
| m26 | elicitation `message` (2025-06-18+) |
| m27 | elicitation `requestedSchema` description (2025-06-18+) |
| m28 | the client's elicitation answer going out (2025-06-18+) |
| m29 | `notifications/progress` `message` |
| m30 | the client's `roots/list` answer going out (root names) |
| m31 | `_meta` on a tool result |
| m32 | `_meta` on a request going out |
| m33 | JSON-RPC error `data` |
| m34 | URL-mode elicitation `url` (2025-11-25) |

m19-m34 are version-gated (`since`): a surface newer than the negotiated protocol is not run and
reads n/a "not in protocol". Each field and the version that introduced it were checked against `schema/<version>/schema.ts` of github.com/modelcontextprotocol/modelcontextprotocol (versions 2025-03-26, 2025-06-18, 2025-11-25)
(2025-03-26: completion, resource templates, tool annotations, progress `message`, `Root.name`,
`_meta`, error `data`; 2025-06-18: `resource_link`, `outputSchema`, elicitation; 2025-11-25: URL mode). m28 and m30 put the payload in
what gcl's client answers to a server request (the mock server makes the server ask); m29 needs a
request that carries a progress token, which gcl sends.

Each surface runs twice. A **carry control** puts a benign marker in the surface, with a
stand-in that allows everything. The marker must arrive whole at the far end; if it does
not, the gateway does not carry that surface: "not carried", policy n/a, never "held". The
**attack** puts an injection sentence in the same place. The stand-in answers block only for
text it is shown with an attack marker. The attack is not sent when its control was not carried.

Outcomes: `stopped` and `dropped unscanned` are held; `passed unscanned` (the stand-in was never
shown the text), `passed despite block` (the stand-in said block and the text arrived anyway) and
`passed without marker` (the marker was removed but the injection sentence reached the far end;
the marker is how gcl finds a message, not what is protected) are violated; no answer, a transport failure, a response cut at the byte cap, or a baseline (m00)
that did not carry its own benign marker is unverified. "Not carried" is claimed only when the
gateway answered every request properly (a valid JSON-RPC 2.0 result or error: `error: null`, both
members, or no `jsonrpc` is no answer) and the surface's own request was really sent. A stop rests
on a block answer whose delivery to the gateway is confirmed. What was seen needs no such proof: a
marker at the far end makes a control `carried` and an attack a leak even if the result was lost or
the session did not settle. The sentence counts as arrived only by a run of four words round its
distinctive word (or half of it, in order), never by common words a gateway's own refusal also says. More unverified outcomes, each one
line:

| outcome | meaning |
|---|---|
| `handshake failed` | initialize got an error or no result, so no probe was sent |
| `probe not sent` | the session ended before the surface's own request was sent and answered |
| `unsettled` | a late call may still arrive: a clean result is not proven (a leak or a carried control already seen stands) |
| `unconfirmed` | the stand-in said block but the delivery of that answer is missing or failed |
| `carried, marker stripped` | (control, held) the marker is gone but the benign sentence arrived whole: the surface is carried, so the attack runs and is judged on its sentence |
| `text altered` | part of a sentence arrived without its marker, or only its distinctive word (an echoed error): neither whole nor absent, so no absence is claimed (control or attack) |
| `list incomplete` | a `tools/list`, `resources/list` or `prompts/list` was not read to its last page (`nextCursor` is followed, 20 pages at most; a repeated cursor or an error on a later page also stops it): "not listed" and "absent" are not proven |
| `name ambiguous` | the gateway's documented name for the item is not listed and more than one entry ends like it: no guess |
| `stream not observed` | the standalone GET stream could not be opened (other than a 4xx refusal, e.g. 405) or died, or a stdio server was still sending when the session ended: nothing is claimed absent |

Everything the far end receives counts: every reply and event stream, what the server sends on
the standalone GET stream of streamable HTTP (opened after the handshake; a 405 is recorded as
"none offered"), and, over stdio, lines that arrive after the last answer (the session is read
until it has been quiet for 0.3 s, at most 2 s). Names are read from the session's own lists
and matched exactly against the gateway's documented name (`mcp_name`) first; a match by
suffix is recorded as such.

m00 judges its two far ends (note in, reply out) each on the stand-in events that carry its own
marker. The far end is what gcl's own
observers recorded: a raw MCP client (standard library only, so every byte is visible) and a
mock MCP server. Gateway logs are not used.

It runs on the MCP adapters only: `reference-mcp`, `invariant-mcp`, `lasso-mcp-gateway`, `contextforge` and `toolhive`.
Any other adapter refuses `--extra mcp`. The protocol is 2025-03-26 unless `--mcp-protocol`
(2025-06-18, 2025-11-25) asks otherwise. m02 is run in every session, although structuredContent
came with 2025-06-18: real gateways carry it in older sessions and may leak it there, and a gateway
that drops it gives n/a "not carried". m16 (batches) exists only in 2025-03-26, so at a later version it
is not run and reads n/a "not in protocol".

```bash
gcl enforce reference-mcp --python python3 --profile naive --extra mcp
gcl enforce reference-mcp --python python3 --profile strict --extra mcp --mcp-protocol 2025-06-18
```

#### Same guard on every route (`--extra routes`)

A guard is usually written against one door, and the same action has others. LiteLLM #40583:
`/v1/messages` skipped the guardrails. LiteLLM #32329: MCP resources and prompts skipped them.
mcp-server-kubernetes CVE-2026-46519: a tool hidden at `tools/list` was still callable. `--extra
routes` runs the same check on each way in and then compares them. An adapter declares its routes:

| gateway | routes |
|---|---|
| `reference`, `litellm` | `/v1/chat/completions`, the same streamed, `/v1/messages` (Anthropic shape), `/v1/responses`, `/v1/completions` |
| MCP gateways | `tools/call`, a batch, a call to a tool `tools/list` never showed, `resources/read`, `prompts/get` |

Each HTTP route gets a **carry control** (a benign marker in the request must reach the model, one in
the reply must reach the client, the stand-in allowing) and an **attack** (an injection sentence in
the request and one in the reply, the stand-in blocking any text with a `GCL-A-` marker). The proof
rules are the MCP surfaces': a route is "not carried" (policy n/a, never held) only when the gateway
answers properly that it has none (HTTP 404, 405 or 501) or the text does not arrive on a 200; any
other refusal or a missing answer is unverified; the attack is judged only on a carried route; a
marker or its sentence at the far end is a leak, "passed unscanned" when the stand-in was never shown
it. The MCP routes are surfaces that already are the same thing (m00, m16, m15, m09, m10): they run
as `--extra mcp` does and the route table refers to their results (with `--extra mcp` as well they
are not counted twice).

Then the **parity** line: every route that carried must hold. One held and another violated is
`parity broken`, naming both; fewer than two carried routes, or an unverified one, is not a
conclusion.

```bash
gcl enforce reference --python python3 --profile naive --extra routes     # chat held, the other routes violated
gcl enforce litellm --python /path/to/litellm-venv/bin/python --extra routes
gcl enforce reference-mcp --python python3 --profile naive --extra routes
```

#### Config applied (`--extra config`)

Every check above assumes the guard is configured and loaded. `--extra config` tests that the
configured policy is the one that runs. It starts the integration fresh for each check with a
policy gcl writes, pointed at one of two stand-in scanners of its own: A always allows, B always
blocks. Which scanner received the check's marker (`GCL-K-<id>-<run>`) is the proof of which policy
was running; the mock model's record says whether the request reached the provider.

| id | check | held when |
|---|---|---|
| k00c | controls | guard to B stops a request with B consulted; guard to A passes both scopes with A consulted. If not, every check is unverified |
| k01-k03 | policy fails to load (missing, malformed, unknown guard type; the adapter declares the variants) | it refuses to start, or starts and the probe is stopped. Violated: the probe reached the model ("ran without its policy") |
| k04 | live edit, tighten (once per edit mechanism) | after the edit the request is stopped with B consulted. Violated: it passed (A consulted: the old policy kept running) |
| k05 | live edit, loosen | after the edit the request passes with A consulted. Not applied: violated, but stricter than configured, not a leak |
| k06 | scoped policy, in scope | a request to the scope is stopped with B consulted |
| k07 | scoped policy, other scope | a request to the other scope passes and B is never consulted (stopped or B consulted: violated, not a leak) |

"Stopped" needs the model never to have received the marker and a complete response; a timeout is
unverified. An edit the integration rejects is n/a "edit rejected", never a violation. A check the
adapter knows it cannot run on this setup is unverified with the reason. The ids follow what the adapter
declares; reports and `gcl compare` key on the check kind. Each result also carries the documented
verdict (conforms / deviates) where the integration's docs state the outcome for that kind, with the
passage quoted below the table; where they say nothing it is "unspecified". It runs on the adapters
that implement it (`reference`, `litellm`); any other refuses `--extra config`.

```bash
gcl enforce reference --python /path/to/python3 --profile strict --extra config
gcl enforce reference --python /path/to/python3 --profile naive --extra config
gcl enforce litellm --python /path/to/litellm-venv/bin/python --extra config
GCL_LITELLM_DATABASE_URL=postgresql://user@localhost:5432/gcl_scratch \
  gcl enforce litellm --python /path/to/litellm-venv/bin/python --extra config
```

LiteLLM's four load failures (missing `--config` file, unknown guardrail type, `generic_guardrail_api`
without `api_base`, a `guardrails` entry without `litellm_params`) and the scope pair (a policy plus a
`models:` attachment, scope = model name) need nothing else. The live-edit checks (tighten and loosen,
once through `PATCH /guardrails/{id}` and once through `PUT /guardrails/{id}`) need LiteLLM's database
because only guardrails created through the management API can be edited: set
`GCL_LITELLM_DATABASE_URL` to a Postgres URL of a database used only for this, with `prisma` installed
in LiteLLM's environment and its client generated (`prisma generate --schema
<site-packages>/litellm/proxy/schema.prisma`); gcl starts the proxy with `--use_prisma_db_push`
and **deletes every guardrail in that database** before each live-edit check. To make that hard to do by mistake, the database name must contain `gcl`; any other is refused. Without the variable
those four checks are unverified ("needs a database"), never held.

The reference gateway's `--policy-file` contract is in `examples/enforce/ref_gateway.py`; `naive`
ignores edits, ignores scoped guards and allows everything when the file is broken, as the real
LiteLLM issues did.

#### Which OWASP risk a failure is evidence about

Every violated result names the OWASP risks it is evidence about — OWASP Top 10 for LLM
Applications 2025, Top 10 for Agentic Applications 2026, MCP Top 10 — in the report and
as SARIF tags. The mapping is a short, explicit table ([gcl/standards.py](gcl/standards.py)).
MCP surface results add MCP03:2025 Tool Poisoning and, for a call to an unlisted tool,
MCP02:2025 Privilege Escalation via Scope Creep.

#### A compatibility table

`gcl table RUNS/` turns a folder of reports into integration × guard behaviour × version.
It is private by default (it shows everything). `--public --ledger L` shows a failure
only if a finding in the ledger covers it and was marked disclosed
(`gcl findings disclose ID --where URL`); every other failure prints as "withheld".

#### In CI

`--format json,html,sarif` writes SARIF for code scanning (`--sarif-anchor FILE` names the
repository file results attach to). `gcl compare old/report.json new/report.json` lists
what changed between two runs — typically before and after an upgrade — and exits 1 on a
regression (held → violated). The repository is also a GitHub Action
([action.yml](action.yml)); [examples/ci/version-watch.yml](examples/ci/version-watch.yml)
re-runs an integration on its latest release every week and fails on a regression.

### `gcl findings` — a ledger that only holds what runs can back

```bash
gcl findings add    ledger.json --report out/report.json --scenario i04 --title "500 from the guard passes"
gcl findings repeat ledger.json F-1a2b3c4d --report out2/report.json
gcl findings confirm ledger.json F-1a2b3c4d --repro repro.py --answer-source recorded --note "..."
gcl findings retract ledger.json F-1a2b3c4d --reason "..."
gcl findings check  ledger.json --runs out/        # exit 1 on any problem
gcl findings render ledger.json                    # Markdown table, every qualifier a column
```

A finding is created from a stored run, never typed by hand; a run whose receipt lists
problems (uncommitted gcl, a patched install) is refused. A second run with its own run id
makes it *repeated* (same stand-in: not independent); *confirmed* needs a hand reproduction
that says where its guard answers came from and does not reuse gcl's stand-in answers, and
for a result on a guessed stand-in, real recorded or live vendor answers. `check` re-reads
every report a finding names (present, unchanged, same outcome), flags newer runs of the
same scenario and versions that disagree (*contradicted*) or used another gcl source or
spec (*stale*), and recomputes the severity. Severity comes from fields — what leaked, who
has to misbehave, default configuration, documented — by a fixed rule
([gcl/severity.py](gcl/severity.py)); inputs only a person can know (`findings set`) and a
person's own number (`findings override`) are kept with their reasons. The ledger may not
live inside gcl's own checkout.

### `gcl evidence-pack REPORT.json ... --out DIR` — stored runs as hashed, honest compliance evidence

```bash
gcl evidence-pack strict/report.json naive/report.json mcp/report.json --out pack/ --sign-key key.bin
gcl evidence-verify pack/ --sign-key key.bin        # exit 1 on any changed, missing or unlisted file
```

Takes stored `enforce`, `coverage` and `probe` reports and writes `pack.json` (machine-readable),
`pack.html`, a copy of every input, and `manifest.json`: the SHA-256 of every input and output and each
run's receipt (run id, gcl commit, uncommitted files, integration versions). The pack maps each kind of
check (allow/block controls, fail-closed faults, attack corpus, streaming and history, MCP surfaces,
`--extra config`, coverage recall, scanner probe, latency) to provisions of the EU AI Act (Regulation (EU)
2024/1689 as amended by 2026/1744), NIST AI RMF 1.0, NIST AI 600-1 and the OWASP lists, each row with a
one-line reason and a strength (*direct* or *supporting*). The coverage matrix shows, per provision and
check family, **held**, **violated**, **unverified**, **not tested** (no input covers it) or **not
applicable**, with counts; a cell shows the worst state in it, so an unverified result is never reported
as held and a family nobody ran is never blank. Provisions gcl considered and left out are listed with
the reason ([gcl/frameworks.py](gcl/frameworks.py) holds the mapping and the list of provisions read from
primary sources, with URLs), and so are the AI Act application dates (with the Digital Omnibus changes).
`--sign-key FILE` adds an HMAC-SHA256 over the manifest: it proves the manifest is unchanged to whoever
holds the key, not who made it. Without it nothing is called signed. This is technical test evidence,
not a conformity assessment and not legal advice. ISO/IEC 42001 is listed as not mapped (control text
not read).

## What the static checks mean

| Code | Level | Hazard |
|---|---|---|
| GCL101 | error | `(?i)`-style global flag group — invalid in JavaScript |
| GCL102 | warning | `(?i:…)`/`(?-i:…)` scoped modifiers — ES2025 engines only |
| GCL103 | warning | `\w \b \d` next to non-ASCII text — Unicode in Python, ASCII in JS |
| GCL104 | error | `(?P<name>…)` — Python-only syntax |
| GCL105 | error | `\A`/`\Z` — literal letters in JavaScript (silent) |
| GCL106 | error | atomic groups / possessive quantifiers — Python 3.11+ only |
| GCL107 | note | lookbehind — not in RE2/Go or old engines |
| GCL108 | warning | nested quantifier — possible catastrophic backtracking |
| GCL109 | note | case-folding hazards (ß, İ, ı, ſ, Kelvin sign) |
| GCL110 | warning | class of Cyrillic/Greek letters that look Latin — fires on ordinary text |
| GCL111 | warning | `.` — JavaScript also excludes `\r`, U+2028, U+2029 |
| GCL112 | warning | multiline `^`/`$` — JavaScript also breaks at `\r`, U+2028, U+2029 |
| GCL113 | error | `{,n}` — 0..n in Python, literal text in JavaScript |

A static hazard is a *suspicion*; `check` confirms or clears it by running the rule.
In the demo, a German `\b` rule on ASCII words and `(?-i:DAN)` on node 25 are *not*
reported for those hazards — both behave the same in both engines there — but both are
reported for what does differ: `.` across a carriage return.

## Field-tested

Beyond its own fixtures, `gcl` has been run on the published rule sets of five
open-source AI-guardrail projects (about 1,700 rules, Python and TypeScript loaders).
Every finding was reproduced by hand with the project's real flags. Those findings are
being reported to the maintainers privately first; the tool's own usability fixes from
that run (per-rule flags, hang inputs, `--max-len`, clearer reasons) are in this release.

## Trust model

Adapter and probe manifests name commands, and `gcl` runs them: treat a manifest like a
script you are about to execute. `gcl` runs each command in its own process group, kills
the whole group at the deadline, caps the output it reads, and never runs a rule
pattern in its own process (rules are untrusted input: they are parsed in-process, but
matched only by the out-of-process engine runners, under a deadline).

## Honest limits

See [LIMITATIONS.md](LIMITATIONS.md). In short: Python `re` and Node `RegExp` only (no
RE2/Rust yet); the bundled language cases are machine-written and small (12 attacks
per language — read the intervals); keyword rules cannot see negation, and `gcl` does
not pretend otherwise; `probe` needs a system whose scanner location is configurable
and whose protected action can leave a receipt.

## Development

```bash
make test     # node-dependent tests are skipped, not passed, without node
make demo     # writes demo-out/report.html
make lint
```

MIT licence.
