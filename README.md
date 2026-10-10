# Guardrail Contract Lab

**Check whether a guardrail does what its config says.**

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
  attacks can catch nothing in Arabic, Amharic or Chinese. One aggregate number hides it.
- **Scanners that fail open.** When the classifier times out, returns a 500 or
  garbage, the tool call runs anyway.

`gcl` checks all three, against your real rule files and your real system, and hands
back a concrete reproducer wherever it can: a shrunken witness string for a rule that
disagrees or over-fires, the input that hangs a rule, the receipt and exit status for a
probe scenario. Existing tools (garak, promptfoo)
fire attacks at a *model*; `gcl` tests the *guardrail*: its rules, in every runtime
that loads them, and its failure contract.

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

Any guardrail can be measured, not only regex files: an **adapter** is a command that
reads `{"id","text"}` JSON lines and writes `{"id","flagged"}` lines. A case with no
answer is recorded as *incomplete*, never as "not flagged".

Bundled cases: 12 attack intents × 12 languages (en, es, fr, de, ru, he, ar, zh,
**Amharic, Swahili, Arabizi, code-switched**) plus 6 benign and 6 hard-negative texts
each — 288 rows, machine-written, marked `native_reviewed: false`.

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
