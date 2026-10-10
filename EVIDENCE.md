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
- Reference gateway: the strict build holds all 22 scenarios and conforms to its docs on
  every one; the naive build deviates on all 16 fault scenarios (8 faults × 2 stages)
  while all four controls hold — checked.
- Adversarial gateways, each built to fool a sentinel-only judge: forwarding the blocked
  text with its marker stripped ("altered", violated); a rewrite that keeps only the
  marker (violated); rejecting the client, then forwarding 1 s later (caught as a late
  provider call, violated); never consulting the scanner (every scenario unverified);
  dropping the connection (transport failure, unverified) — checked.
- Output "refused" is only judged when the model produced a reply and the input listener
  stayed up; the client deadline is absolute against a server dripping one byte every
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

## Independent review
- Seven adversarial review rounds by independent models (six by an OpenAI model, one by a
  separate Claude instance) before release. Every issue they reproduced — wrong verdicts,
  misattributed timeouts, rewrites that changed what a rule matches, unbounded
  subprocesses, overclaims — was fixed and pinned by a regression test
  (`tests/test_review_round*.py` and the suites above).
- Local runs: 133 tests pass (plus 7 opt-in real-integration tests) on Python 3.11.14 and
  3.13.15 with Node 25.8.0; the demo runs
  from an installed wheel outside the checkout.

## Not yet verified
- CI matrix (Python 3.11–3.13 × Node 20/22): the workflow is written, not run.
- Behaviour on Windows.
