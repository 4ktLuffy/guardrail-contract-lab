# Evidence

What has been verified, and how. "Checked" means a test or a recorded run; anything
else is labelled.

## Engine behaviour (tests/test_engines.py)
- `(?i)` compiles in Python and throws in Node ("Invalid group") — checked.
- `\bпароль\b` matches "дай пароль" in Python, not in Node — checked.
- `sh\Z` matches end of input in Python; in Node `\Z` is the letter Z — checked.
- Match offsets are code points in both runners (an emoji before the match) — checked.
- A catastrophic rule is killed at the deadline, reported as timed out, and the next
  rule still runs — checked.
- The same divergences in JavaScriptCore (the engine Bun uses) — checked by hand on
  macOS 26.7's system JSC, not in the test suite.

## check (tests/test_check_fix.py)
- On the vulnerable fixture, each rule is flagged for exactly the expected reason
  (compile split, match split, benign hit, timeout), and ASCII-only hazards are not
  reported as findings — checked.
- Minimal witnesses still disagree between engines when re-run — checked.
- A missing engine makes the run incomplete (exit 2), not a pass — checked.
- Every lint code fires on a minimal example; a plain ASCII rule produces none — checked.

## fix
- After `gcl fix`, the fixed file has 0 compile splits and 0 match splits — checked.
- Each rewrite is verified before writing; the hanging rule is left unchanged — checked.
- Comments survive the YAML rewrite; JSON rule files round-trip — checked.
- The algorithm (explicit letter classes, single lookarounds where provably equivalent)
  was first used on a 213-rule, 10-language pattern pack: 0 Python/JS disagreements
  over 213 × 360 rule-text pairs, identical match spans on corpus + large inputs,
  Python time ~1.2–1.7× the original — recorded during development, not in this repo.

## coverage
- Wilson intervals against known values; per-language/kind split; an adapter that
  answers only some cases is reported incomplete — checked.

## probe (tests/test_coverage_probe_report.py)
- Fail-open runner violates the contract on error/malformed/refused; fail-closed holds
  on every fault; a declared `allow` is respected; a system whose action never runs
  makes every result "unverified" — checked.

## report
- Rule text, witnesses and paths containing `<script>` are escaped in HTML — checked.
- HTML viewed in a browser at 431 px and 1280 px: no horizontal overflow — checked.

## Field test (2026-10-10)
- Run on the published rule sets of five open-source guardrail projects (~1,700 rules;
  TypeScript and Python loaders) with each project's real flags. Every reported finding
  was reproduced by hand with a 3-line snippet — catastrophic backtracking on ordinary
  text, quadratic rules at a project's own input cap (3.5 s measured; `gcl` reports
  3,524 ms with `--max-len`), missing word boundaries, script-wide character classes.
  Project names and details are withheld until maintainers have been told.
- That run produced the per-rule `flags` key, flag validation, hang inputs, `--max-len`,
  engine-relevant hazards and the "one rule is the whole story" coverage note.

## enforce (tests/test_enforce.py)
- Reference gateway: the strict build holds all 38 scenarios and conforms to its docs on
  every one; the naive build deviates on 18 (the fault scenarios, 9 faults × 2 stages) and holds
  the other 20, all controls among them — checked (`gcl demo`, re-run 2026-10-13: 18 of 38 / 0 of 38).
- Adversarial gateways, each built to fool a sentinel-only judge: forwarding the blocked
  text with its marker stripped ("altered", violated); a rewrite that keeps only the
  marker (violated); rejecting the client, then forwarding 1 s later (caught as a late
  provider call, violated); never consulting the scanner (every scenario unverified);
  dropping the connection (transport failure, unverified) — checked.
- Output "refused" is only judged when the model produced a reply and the input check
  has its own listener (not run where one URL serves both stages); the client deadline is absolute against a server dripping one byte every
  0.2 s; the stand-in rejects wrong paths and unknown stages; `--fail-on` is validated and
  a partly unverified run exits 2 — checked.
- The reference gateway's strict build blocks rewrites with the wrong number of texts or
  non-string texts — checked.
- A check that runs alongside the model call is classified "blocked after send"; judge
  calls on the model's endpoint are routed to the stand-in, staged by content, and never
  counted as provider calls; a judge refusal is answered as OpenAI does — checked.
- Real integrations (opt-in, `GCL_INTEG_PYTHON`): LiteLLM 1.104.2 proxy, NeMo Guardrails
  0.24.1 server, openai-guardrails 0.3.3 and the Portkey gateway 1.15.2 (Node) run end to
  end through the same suite —
  checked locally, not in CI.

## Review round 7 (tests/test_review_round7.py)
- Fragments of the original (cut text, stripped marker, rewrite plus leftovers, marker-
  only rewrite, Chinese runs) are "altered", not stopped or modified; "blocked after send"
  needs a 4xx; a scanner answer served with another scenario's mode is not evidence; an
  unsettled scenario gets no clean verdict while a proven leak still counts; a fault the
  protocol cannot express is unverified; ambiguous judge requests are rejected; the
  deadline worker is stopped — checked.

## Review round 8 (tests/test_review_round8.py)
- A control that is itself unverified unlocks nothing; specs with no testable stage are
  refused; unknown/wrong-type faults change only the operative verdict field (fields
  that differ between allow and block) or report "not exercised"; the block marker
  counts only in the answer content; a 5xx stays "failed after send" even when it quotes
  the reply; ECHO_TEXT needs an explicit field; a late retry is answered with its own
  scenario's behaviour; vendor routes are matched exactly; stage inference needs exactly
  one scenario identity — checked.

## MCP, retry and policy sources (tests/test_enforce.py)
- The mock MCP server answers initialize / tools/list / tools/call over streamable HTTP,
  issues one session per client, and records tool calls at the server boundary; static
  POST routes and GET policy routes answer without counting as consultations; policy-
  source faults return 404 / 500 on policy routes only (the check endpoint stays healthy)
  and count only when delivered; the Invariant MCP adapter runs "block_retry", judged only
  when the first attempt was a clean refusal; the mock MCP server rejects unknown sessions
  and tools — checked. Real run: Invariant Gateway 0.0.9 MCP proxy — opt-in.

## Review round 9 (tests/test_review_round9.py)
- The Invariant stand-in locates a violation at every matching message, as the real
  analyzer does (a fixed location gave a misleading retry result); policy-source faults count only when
  the 404/500 was delivered and leave the check endpoint healthy; a retry is judged only
  after a refused first attempt, with every attempt kept; "tool executed" conforms to a
  documented pass only when the client also got its answer; events carrying several
  scenarios' markers prevent a clean hold; the mock MCP server rejects unknown sessions
  and tools; JS drivers serialise exception state and results — checked.

## Checks on the tester (tests/test_tester_receipts.py, test_tester_controls.py, test_tester_delivery.py)
- Receipts: every sentinel carries the run id; a marker from another run is not evidence; a
  reply served from a cache with no model call is not a hold; a truncated client body is
  never judged clean and the bundle says `truncated: true`; a locally patched install
  (a file that no longer matches its RECORD hash) is flagged; docs read for another
  version are flagged; `--out` refuses a non-empty folder — checked.
- Bracketing controls, each against a gateway built to fool the judge: one that breaks
  after eight requests, one that fails on Arabic text after the guard answered, one whose
  driver cuts answers to 300 characters while leaking inside an error, one that crashes
  (500) on a block answer — every affected clean result is unverified; a correct gateway
  still holds everything — checked.
- Delivery: an answer written after the integration hung up is not evidence; an unmarked
  background provider call is not a violation; background traffic before the run is in
  the receipt; a stall records who ended it; a gateway that blocks on any truthy verdict
  holds `unknown_verdict` by accident and is caught by `null_verdict` — checked.

- Timeline (tests/test_tester_timeline.py): a gateway that forwards to the provider before
  asking the guard, then refuses, is "blocked after send" with the provider first in the
  timeline and flagged; a gateway that races a parallel check against the model call holds
  at 0 s guard latency and leaks at 0.6 s, and the sweep reports it unstable — checked.

## Stand-in provenance (tests/test_tester_provenance.py)
- Every built-in stand-in declares how it was built; results on a stand-in rebuilt from
  client code are "guessed" whether they hold or not, while a transport fault on the same
  stand-in stays verified; the same scenarios on an integration-defined stand-in are
  verified; vendor specs default to client code, recorded replies replace the rebuilt
  bodies and count only for their request shape (a retry or another message count is
  guessed); a guard supplied by gcl's own driver is labelled "harness" — checked.

## Held-out cases (tests/test_tester_heldout.py)
- Coverage without held-out rows says its recall is fit; with them, held-out and fit
  recall are reported apart and a large gap is called out; unanswered held-out rows are not counted as
  misses — checked.

## Attack mode, recording, CI (tests/test_attacks.py, test_record.py, test_ci.py)
- Attack × fault: with the bundled keyword detector, a strict gateway shows only detector
  misses; a gateway that passes anything but an explicit block leaks every attack under
  error and timeout; a gateway that ignores the detector's block on attack text is "not
  enforced"; the CLI refuses half a configuration — checked. Real run: LiteLLM 1.104.2,
  profile fail_open, five bundled attacks: the flagged attack is enforced, every attack
  leaks under a guard timeout and stops under a guard error, as LiteLLM documents; all
  controls hold — checked locally, not in CI.
- Recording: the proxy is transparent, stores no request headers and redacts secret
  fields; recorded allow/block replies become a spec whose block results are "recorded" for
  the recorded request shape and "guessed" otherwise; `to-spec` refuses identical,
  failed, redacted or differently shaped records — checked (against a fake vendor; no real
  vendor credentials were used).
- CI: SARIF has one result per scenario that did not cleanly hold, with stable
  fingerprints; `gcl compare` reports regressions, fixes and unverified changes and exits
  1 on a regression; every command is registered under `python -m gcl.cli`; the Action
  passes its inputs as environment data, not script text — checked. Real run: LiteLLM
  1.104.2 against 1.105.0, `gcl compare`: no change — checked locally.

## Blind spots, standards, table (tests/test_blind_spots.py, test_standards.py, test_table.py)
- The default plan is unchanged with no `--extra`; a strict gateway holds every blind-spot
  scenario; a gateway that streams the reply before the output check, one that checks only
  the last message, and one that lets a repeated request skip the guard are each caught
  — checked. Real run: LiteLLM 1.104.2 with all three: history and retry hold — checked
  locally.
- OWASP IDs per outcome (prompt injection, output handling, disclosure to the provider,
  excessive agency, cascading failure, MCP intent/context) and in SARIF tags — checked.
- A private table shows every result; a public one withholds every violation not covered
  by a disclosed ledger finding and shows it once disclosed — checked; built from real
  LiteLLM runs — checked locally.

## New targets (tests/test_new_targets.py)
- Coralogix guardrails-langchain 0.6.0 and LlamaFirewall 1.0.3 adapters: protocol shapes
  and capabilities — checked; real runs with every control holding, including streaming,
  history and retry for Coralogix — checked locally (opt-in `GCL_INTEG_CORALOGIX_ENV`,
  `GCL_INTEG_LLAMAFIREWALL_PYTHON`), not in CI.
- A timeout result that only followed gcl releasing the stalled call is unverified
  (tests/test_tester_delivery.py) — checked; found on a real run.

## Review round 13 (tests/test_review_round13.py)
- A third independent review of the new parts found ten defects; each is fixed and
  pinned, and each test fails on the code before its fix: disclosure scope, a summarised
  history counted as a hold, release attribution of timeout leaks, history verdicts
  bypassing stand-in confidence, a per-message guard counted as not consulted, retries
  after a normal-answer refusal, OWASP tags without a leak, "fails open" for an over-block,
  and drivers dropping the library's own evidence — checked.

## Findings ledger and severity (tests/test_tester_findings.py, test_tester_severity.py)
- A finding comes only from a violated or deviating result in a stored run with a clean
  receipt; a repeat needs another run id; a different outcome contradicts it; confirmation
  needs a declared answer source, refuses a reproduction that reuses the stand-in's
  answers, and for a guessed stand-in needs recorded or live answers; a retraction keeps
  the record; `check` catches an edited or missing report, a newer disagreeing run on the
  same versions, a run on another gcl source, and a hand-edited rating; the ledger is
  refused inside gcl's checkout; the severity rule gives the same number for the same
  evidence, and human inputs need a reason — checked.

## Review round 11 (tests/test_review_round11.py)
- A second independent review, of provenance, the ledger and severity, found nine
  defects; each is fixed and pinned: `check` now re-derives every field of a finding from
  the report it names (status, runs, run ids, guessed, versions) and its history; rating
  inputs a person may not set are ignored and flagged; receipts are required for add,
  repeat and check; a confirmation needs a non-empty reproduction that must stay in place;
  "recorded" applies per verdict and needs a positive request-shape match; allow answers
  rest on the stand-in too; a finding from a latency sweep is checked against its own run;
  language controls are separate findings — checked (the tests pass; the reviewer showed
  each defect on the code before the fix in memory, the tests were not re-run against it).

## Review round 10 (tests/test_review_round10.py)
- An independent adversarial review of the checks above found eight defects, each
  reproduced and fixed: a 5xx block control that leaked was hidden as unverified; another
  run's reply in a client body counted as a leak; another run's marker for a different
  scenario fell back to time-window attribution; tool markers lacked the run id; the
  cached-reply check erased a recorded tool run; the latency sweep kept only one run,
  overwrote language controls in its table and replayed without the latency; "before the
  guard answered" used handler completion instead of transmission. Each test fails on the
  code before its fix — checked.

## Review pins (tests/test_review_pins.py)
- Five earlier review fixes that had no test of their own are pinned: no output "refused"
  scenario for a single-listener guard; a slow stand-in answer keeps the configuration it
  arrived under, and quiet time counts from completion and tool runs; tool runs are
  attributed by exact marker, then by time window, and agent runs need the probe tool to
  fire; the JS drivers' serialiser keeps nested state, cycles and bigints; one deadline
  covers a whole MCP session. Each test was run against the code before its fix and
  failed there — checked.

## Independent review
- Ten adversarial review rounds by independent models (nine by an OpenAI model, one by a
  separate Claude instance) before release. Every issue they reproduced — wrong verdicts,
  misattributed timeouts, rewrites that changed what a rule matches, unbounded
  subprocesses, overclaims — was fixed and pinned by a regression test
  (`tests/test_review_round*.py` and the suites above).
- Local runs: 639 tests pass and 20 are skipped (the opt-in real-integration tests, `GCL_INTEG_*`
  unset), 0 fail, on Python 3.13.15 with Node 25.8.0 (2026-10-13, run file by file, six at a time; 336 s).
  The earlier opt-in real-integration runs (twelve installed integrations) are recorded above, not
  re-run for this count; the demo ran from the checkout on 2026-10-13 (190 s), from an installed wheel
  outside it earlier — not re-checked.

## MCP surfaces (tests/test_mcp_surfaces.py, test_mcp_mock_surfaces.py, test_mcp_real_adapters.py)
- Reference gateway, naive profile, every surface m00–m34 with its carry control: each control is
  carried, 4 attacks are held (m00, m04, m13, m15), every other surface the protocol version has
  is "passed unscanned" and violated, with the OWASP IDs and the scanner never shown the text — checked.
- Reference gateway, strict profile: every carried surface is stopped and held, with the scanner shown
  the text; m15 and m16 are "not carried" (n/a) and the surfaces newer than the protocol "not in
  protocol"; nothing is violated or unverified — checked.
- Mock MCP server, each surface over streamable HTTP and over the stdio bridge, read by
  gcl's raw MCP client: the payload arrives where the surface says, the SSE surfaces (m08,
  m11, m12, m13) stream, a client without SSE in its Accept falls back to JSON, a sampling
  answer is recorded, and the server records each message with its session and transport —
  checked.
- Classification on synthetic exchanges: each outcome (stopped, dropped unscanned, passed
  unscanned, passed despite block), unfinished and transport-failure sessions (never held),
  a cut or rewritten copy of the marker (counted as arrived), the carry-control cases
  (carried, not carried, undelivered event stream), "not carried" only after a proper answer
  to every request (an HTTP error page, a non-JSON body or a missing answer is unverified),
  a response cut at the byte cap (unverified, never stopped), a baseline (m00) that was not
  carried (every other surface unverified), names read back from the session's own lists,
  and "scanner shown" counting only a valid block answer that was delivered — checked.
- Ordinary results are the same with and without `--extra mcp`: on the reference gateway
  (strict profile, the full ordinary plan) every ordinary scenario has the same observed
  outcome and policy, and no surface result appears without the flag — checked. On the naive
  profile this is checked for the opening controls and two surfaces only.
- `--extra mcp` on an adapter without an MCP transport is refused with a clear error — checked.
- Invariant and Lasso adapters: name mapping, and the URL, headers and argv each hands to the
  raw client — checked without a gateway.
- Real gateways, opt-in (`GCL_INTEG_INVARIANT_PYTHON`: Invariant Gateway 0.0.9;
  `GCL_INTEG_LASSO_PYTHON`: Lasso mcp-gateway 1.2.1): run 2026-10-11, and re-run 2026-10-12/13
  under the stricter rules above (all 35 surfaces, full observation, payload matching). The results
  are not stated here; findings go to the maintainers first, as the README says.
- ToolHive v0.51.4 real runs, opt-in (`--env` the `thv` binary): profiles `fail` and `ignore`, with
  and without `--extra mcp`, run 2026-10-11 and re-run 2026-10-12/13 under the stricter rules — checked;
  results withheld, as above. Extra real profiles run 2026-10-11 and re-run 2026-10-12/13: Invariant
  `push`, Lasso `no_key`, ContextForge `enforce` and `ignore_error` — checked; results withheld.
- structuredContent (m02) is run at every protocol version (a gateway that drops it reads
  n/a "not carried").

## MCP surfaces, 35 of them, and what counts as proof (tests/test_mcp_next.py, test_mcp_presence.py, test_mcp_refusal.py, test_ref_mcp_gateway.py)
- Reference MCP gateway, all 35 surfaces m00–m34 (each with a carry control), `--extra mcp` at the three
  protocol versions, naive / strict. Violated: 25 / 0 at 2025-03-26, 29 / 0 at 2025-06-18, 30 / 0 at
  2025-11-25. Naive holds 4 (m00, m04, m13, m15) at every version. Strict holds 27 / 32 / 33, with n/a
  8 / 3 / 2 (not in protocol 6 / 2 / 1, not carried 2 / 1 / 1: m15 always, m16 at 2025-03-26).
  Nothing is unverified — checked, re-run 2026-10-13 (counts in NUMBERS.md).
- Proof rules, each pinned by a test that fails on the code before the fix: a reply is an answer only
  as a valid JSON-RPC 2.0 response (`error: null`, both members, no `jsonrpc` are not); the surface's own
  request must have been sent and answered (an initialize error is "handshake failed", a skipped
  step "probe not sent"); a session that did not settle is unverified, a proven leak stays violated; a
  block counts as "stopped" only with its delivery confirmed; stdio is read until the server is quiet,
  the standalone GET stream is opened and watched, and a stream that cannot be watched makes an
  absence unverified; lists are read to their end (20 pages) and names match exactly before a suffix,
  else "list incomplete" / "name ambiguous"; the payload counts, not only the marker (a gateway that
  strips `GCL-A-…` and forwards the injection sentence is "passed without marker"); the sentence is
  matched by a run of four words around its distinctive word, so a gateway's own refusal text is not
  a leak; a lone distinctive word is "text altered"; a sighting at the far end is proof even when
  the result was lost — checked.
- A gateway started by an adapter does not outlive the run (SIGTERM, SIGHUP, exit without `stop()`; the
  bundled reference gateways also exit when their parent is gone) — checked (tests/test_process_cleanup.py).

## Same guard on every route, `--extra routes` (tests/test_routes.py)
- Reference gateway: strict holds all 5 routes (chat, chat streamed, `/v1/messages`, `/v1/responses`,
  `/v1/completions`), parity equal; naive holds chat and chat streamed and violates the other 3, parity
  broken. Reference MCP gateway: strict holds `tools/call`, `resources/read`, `prompts/get` and does not
  carry the batch or the hidden tool (n/a), parity equal; naive holds `tools/call` and the hidden tool
  and violates batch, `resources/read`, `prompts/get`, parity broken — checked, re-run 2026-10-13.
- A route is "not carried" only on a proper 404, 405 or 501 or a 200 without the text, never held; parity
  names both sides and ignores routes that did not carry; routes do not change the ordinary
  results; routes appear in the terminal and HTML reports, SARIF, compare and table — checked.
- LiteLLM 1.105.0: routes r01, r03, r04, r05 held; r02, a streamed chat completion, violated (the
  blocked reply's text reaches the client before the block event); `/v1/messages` held — checked locally
  (reported in the pull-request description #9), opt-in `GCL_INTEG_PYTHON`, not re-run for this file.

## Config applied, `--extra config` (tests/test_config_checks.py, test_litellm_config.py)
- Reference gateway: strict holds all 7 checks (3 load failures, tighten, loosen, scope in and out); naive
  holds 1 and violates 6 (a missing file, invalid JSON and an unknown guard type all allow; an edit is
  ignored; a scoped guard matches nothing); controls hold in both — checked, re-run 2026-10-13.
- A check is never held without the receipt of which stand-in scanner (A allows, B blocks) answered;
  a broken control makes every check unverified; a rejected edit is not a violation; an adapter without
  the property gets no check for it; the extra is refused on adapters without it — checked.
- LiteLLM 1.105.0 starts WITHOUT the guardrail for an unknown guardrail type and for
  `generic_guardrail_api` without `api_base`; 1.99.0 refuses to start; `PUT /guardrails/{id}` on 1.99.0
  answers 200 but the old policy keeps running (BerriAI/litellm#40201), `PATCH` applies; on 1.105.0 `PATCH`
  and `PUT` both apply; scope by model held on both — checked locally (reported in pull-request
  descriptions #3 and #7), live edits need `GCL_LITELLM_DATABASE_URL`, opt-in, not in CI, not re-run here.

## Upgrade check (tests/test_upgrade_check.py)
- `upgrade-check` on the reference gateway, strict → naive: exit 1, 18 regressions, 20 unchanged; strict
  → strict: exit 0, 0 regressions, 38 unchanged — checked, re-run 2026-10-13.
- Unit level: held → violated is a regression and violated → held an improvement; held → unverified
  is a regression only when the after-controls hold; broken controls make the comparison unverified,
  not regressed, and a proven leak survives them; a guard that went silent is a regression even if
  everything still looks held; a guard never consulted proves nothing; scenarios on one side only and
  different integrations are refused or unverified; a latency sweep is refused; "docs due" follows the
  installed version against the version the docs were read for — checked.
- LiteLLM 1.99.0 → 1.105.0 with `--extra config`: exit 1 with two regressions (the unknown guardrail type
  and `generic_guardrail_api` without `api_base` now start without the guardrail) — checked locally
  (reported in pull-request description #5), opt-in, not re-run here.

## Coverage: false alarms per language (tests/test_lang_fpr.py)
- Wilson intervals at zero and tiny n; n = 0 reads "not measured", never 0%; every rate prints with counts
  and its interval; the gap to English is starred only when the intervals do not overlap; an unanswered
  case is not counted as clean — checked.
- Gate: `--max-fpr`, `--max-fpr-lang`, `--min-recall`, `--max-fp`: exit 1 naming language and counts; the
  boundary is not a breach; a limit with nothing measured is a breach; an incomplete run exits 2;
  fractions outside 0–1 and percents given as fractions are refused — checked.
- Bundled hard negatives (`--hard-negatives`): 144 rows, 12 per language, consistent across languages, not
  copied between them, marked as written for gcl — checked. They are machine-written and not
  native-speaker reviewed: a smoke test, not a benchmark — not tested by a native speaker.
- Measured with the bundled cases plus `--hard-negatives` (432 rows): the English-only rule set 2.4%
  (7/288) false positives, recall unchanged at 11.8%; the substring detector (negative control) 42.4%
  (122/288), 14 breaches of `--max-fpr 0.05 --max-fpr-lang 0.10`; the keyword example adapter 0.3% (1/288)
  — checked, re-run 2026-10-13 (NUMBERS.md).

## Evidence pack (tests/test_evidence_pack.py)
- Every mapped id is on the list of provisions read from a primary source, with its URL; every row has a
  reason, a strength and a known check family; ISO/IEC 42001 is not mapped; a status is never promoted
  (unverified and missing stay as they are); a coverage report is never shown as held; a dirty tree or a
  missing receipt is warned — checked.
- Manifest: SHA-256 of every input and output, each run's receipt; a changed input, a changed output
  and an extra file are each detected (exit 1); HMAC-SHA256 verifies, fails with a wrong key and on a
  changed manifest; an unsigned pack claims nothing — checked.
- On six real reference reports (config and routes, strict and naive, MCP at 2025-11-25, coverage): 199
  results mapped (112 held, 72 violated, 12 unverified, 3 n/a), 10 files written, `evidence-verify`
  8 files checked, signature verified, exit 0; the same pack with one byte appended to a copied input,
  with `pack.json` edited, and with a stray file: exit 1 each — checked, 2026-10-13.
- The mapping is gcl's reading of the texts, not a legal opinion or a conformity assessment — not
  reviewed by a lawyer or an assessor.

## Not yet verified
- CI matrix (Python 3.11–3.13 × Node 20/22): the workflow is written, not run.
- Behaviour on Windows.
- The 144 bundled hard negatives: no native-speaker review of any language.
- LiteLLM 1.99.0 / 1.105.0 results above (config, routes, upgrade-check): taken from the pull-request
  descriptions, not re-run when this file was updated; need `GCL_INTEG_PYTHON` and, for live edits,
  `GCL_LITELLM_DATABASE_URL`.
- Evidence pack: the mapping to the AI Act, NIST and OWASP has not been read by a lawyer or an assessor.
- Serial wall time of the test suite (only the six-at-a-time run was timed).
