# Numbers

Every number in the README comes from `gcl demo` on the bundled fixtures, recorded
from `demo-out/report.json` (python 3.13.15, node v25.8.0, macOS; re-run 2026-10-13 on
`evidence-docs`: every row below still reproduces). Regenerate with `make demo`; the JSON is
the record. The sections after the table list the commands behind the numbers that `gcl demo`
does not print.

| Claim | Value | Source in report.json |
|---|---|---|
| Rules that do not compile, or disagree, in JS | 4 of 9 (2 compile, 2 match) | `sections[0].check.summary` |
| Same, after `gcl fix` | 0 (8 rules rewritten and verified; the hanging rule left alone) | `sections[1].check.summary`, `fix` |
| Rules that disagree only on line terminators (`.` vs `\r`) | 2 of 9 before, 0 after `gcl fix` | findings `line_split` |
| Rule firing on ordinary text | 1 of 9 — benign Russian 10/12; not auto-fixable | findings `benign_hit` |
| Rule that hangs on long input | 1 of 9, in both engines | findings `timeout` |
| Rule with quadratic time (no lint rule sees it) | 1 of 9 — slowest single input ~34→~560 ms for 2k→8k chars in Python (n^2.0); node ~2→~26 ms (n^1.8) | findings `slow` |
| English-only rules, recall in English | 91.7% (11/12), 95% CI 64.6–98.5% | `sections[2].coverage.by_lang.en` |
| Same rules, recall in Arabic (and es, fr, de, ru, he, zh, sw) | 0.0% (0/12), 95% CI 0–24.3% | `…by_lang.ar` |
| Same rules, all 12 languages | 11.8% (17/144) in Python, 11.1% (16/144) in node | `…aggregate`, `…compare` |
| Same rules, false positives | 2.8% (4/144) on the bundled 6 benign + 6 hard negatives per language; English hard negatives 2/6 (a Wi-Fi password note, a harmless "don't tell"). With `--hard-negatives` (144 more) 2.4% (7/288), 95% CI 1.2–4.9% | `…aggregate`, `…by_lang.en`; second figure: see "Per-language false positives" |
| The one case node misses | Amharic `የ.env`: `\b` before `.env` exists in Python (Ethiopic letter = word char), not in JS | `…compare` |
| Fail-open runner: scanner faults that let the call run | 6 of 6 | `sections[3].probe.summary` |
| Fail-closed runner | 0 of 6; both controls held | `sections[4].probe.summary` |
| Reference gateway, naive build: scenarios breaking its documented fail-closed contract | 18 of 38 (strict build: 0 of 38) | `sections[5].enforce.summary`, `sections[6]` |
| MCP gateway (`reference-mcp`), naive build: surfaces that reach the client or server unscanned | 25 of 34 attack surfaces (m01–m34, m00 excluded) at the default protocol 2025-03-26; 29 at 2025-06-18; 30 at 2025-11-25. Strict build: 0 violated at every version. Full counts over all 35 surfaces m00–m34: see "MCP surfaces" below | `sections[7].enforce.mcp_surfaces.summary`, `sections[8]` |
| Wall time | ~190 s in total (190 s measured 2026-10-13; most of it the deliberate hang, timing and timeout drills and the two MCP builds; per-stage times not re-measured) | terminal |

## MCP surfaces

Two commands per protocol version (no model, no network; the stand-in scanner answers block only
for text carrying a `GCL-A-` marker). 35 surfaces, m00–m34, each judged only when its carry control
arrived and with the full proof rules (valid JSON-RPC 2.0, session settled, block delivery
confirmed, everything observed, payload match on a distinctive word, lists read to their end).
"violated" is `passed unscanned`, `passed without marker` or `passed despite block`. `held` counts m00;
`n/a` is split into `not in protocol` (surface newer than the version, or m16 batches after
2025-03-26) and `not carried` (the gateway does not have it):

```bash
for v in 2025-03-26 2025-06-18 2025-11-25; do
  gcl enforce reference-mcp --python python3 --profile naive  --extra mcp --mcp-protocol $v
  gcl enforce reference-mcp --python python3 --profile strict --extra mcp --mcp-protocol $v
done
```

| Protocol | Profile | held | violated | unverified | n/a (not in protocol / not carried) |
|---|---|---|---|---|---|
| 2025-03-26 | naive | 4 (m00, m04, m13, m15) | 25 | 0 | 6 (6 / 0) |
| 2025-03-26 | strict | 27 | 0 | 0 | 8 (6 / 2: m15, m16) |
| 2025-06-18 | naive | 4 | 29 | 0 | 2 (2 / 0) |
| 2025-06-18 | strict | 32 | 0 | 0 | 3 (2 / 1: m15) |
| 2025-11-25 | naive | 4 | 30 | 0 | 1 (1 / 0) |
| 2025-11-25 | strict | 33 | 0 | 0 | 2 (1 / 1: m15) |

Wall time per run, six running in parallel on 10 cores: naive 47–50 s, strict 56–71 s. `gcl demo` runs
the 2025-03-26 pair with only the opening controls of the ordinary plan (88 scenarios instead of 107),
which is the "25 of 34 ... 8 more not carried" hero line.

## Route parity (`--extra routes`)

```bash
gcl enforce reference     --python python3 --profile naive  --extra routes
gcl enforce reference     --python python3 --profile strict --extra routes
gcl enforce reference-mcp --python python3 --profile naive  --extra routes
gcl enforce reference-mcp --python python3 --profile strict --extra routes
```

| Gateway | Profile | routes held | violated | n/a | parity |
|---|---|---|---|---|---|
| `reference` | naive | 2 (chat, chat streamed) | 3 (`/v1/messages`, `/v1/responses`, `/v1/completions`) | 0 | broken |
| `reference` | strict | 5 | 0 | 0 | equal |
| `reference-mcp` | naive | 2 (`tools/call`, unlisted tool) | 3 (batch, `resources/read`, `prompts/get`) | 0 | broken |
| `reference-mcp` | strict | 3 (`tools/call`, `resources/read`, `prompts/get`) | 0 | 2 (batch, unlisted tool: not carried) | equal |

Whole runs: `reference` 48 scenarios (naive 21 violated, 27 held; strict 48 held), `reference-mcp` 47
scenarios (naive 21 violated, 26 held; strict 43 held, 4 n/a). Each took 34–38 s.

## Config applied (`--extra config`)

```bash
gcl enforce reference --python python3 --profile naive  --extra config
gcl enforce reference --python python3 --profile strict --extra config
```

Seven checks (policy file missing, not valid JSON, a guard of an unknown type; live tighten; live
loosen; scoped policy in scope and out of scope) after a control that proves which scanner ran.
Naive: 1 held (out of scope), 6 violated (the three broken files let the call through; a tightening is
ignored; after a loosening the old policy still blocks; a scoped guard matches nothing). Strict: 7 held.
Both: controls held, 0 unverified. Whole runs: 46 scenarios (naive 24 violated, strict 0), 38–41 s.

## Upgrade check

```bash
gcl upgrade-check reference --before python3 --after python3 --before-profile strict --after-profile naive
gcl upgrade-check reference --before python3 --after python3 --before-profile strict --after-profile strict
```

strict → naive: exit 1, 18 regressions (held → violated, listed per scenario in the report), 20 unchanged, guard consulted on both sides (input 4 / 4,
output 8 / 8). strict → strict: exit 0, 0 regressions, 38 unchanged. About 65 s each (two builds in
sequence). The 18 are the same 18 scenarios the naive build breaks in the table above.

## Per-language false positives (`gcl coverage`)

```bash
gcl coverage --rules examples/coverage/rules.english-only.yaml --engines python,node --hard-negatives
gcl coverage --adapter examples/coverage/adapter.substring.yaml --hard-negatives
gcl coverage --adapter examples/coverage/adapter.keyword.yaml --hard-negatives
```

`--hard-negatives` adds 144 texts (12 per language in 12 languages) to the 288 bundled rows: 432 in all.

| Detector | Recall | False positives, all benign + hard negatives | Worst language |
|---|---|---|---|
| English-only rules (python; node recall 16/144 = 11.1%) | 11.8% (17/144) | 2.4% (7/288), 95% CI 1.2–4.9% | en 4/24 = 16.7% [6.7–35.9] |
| Substring detector (negative control) | 28.5% (41/144) | 42.4% (122/288), 95% CI 36.8–48.1% | hi 9/12 = 75.0% [46.8–91.1]; pt 8/12 = 66.7% [39.1–86.2] |
| Keyword example adapter | 7.6% (11/144) | 0.3% (1/288), 95% CI 0.1–1.9% | en 1/24 = 4.2% [0.7–20.2] |

The gap-vs-English column, English-only rules: the recall gap is starred (intervals do not overlap
English's) in all 11 other languages with attacks, the false-positive gap in none. Substring detector:
the false-positive gap is starred only in am, sw and ar-Latn, where it is lower than English (0/12).
Gate, same commands with limits: `--max-fpr 0.05 --max-fpr-lang 0.10` on the substring detector exits 1
with 14 breaches (overall and 13 languages); `--max-fpr 0.05 --max-fpr-lang 0.20` on the English-only
rules exits 0.

## Evidence pack

```bash
gcl evidence-pack ref_config_strict.json ref_config_naive.json mcp_strict.json mcp_naive.json \
    ref_routes_strict.json coverage_rules.json --out pack --sign-key key.bin
gcl evidence-verify pack --sign-key key.bin
```

(reference-gateway reports above; MCP at 2025-11-25.) 6 reports, 199 results mapped (112 held, 72
violated, 12 unverified, 3 n/a); matrix 11 held / 34 violated / 3 unverified / 47 not tested /
0 not applicable cells. The output folder holds 10 files: `pack.json`, `pack.html`, `manifest.json`,
`manifest.hmac` and the 6 copied inputs under `inputs/`. `evidence-verify`: 8 file(s) checked (6 inputs,
`pack.json`, `pack.html`), signature verified, exit 0. Tamper checks, each exit 1 (NOT OK): one byte appended to
a copied input, `pack.json` edited, an extra file in the folder (`stray.txt`: "not listed in the manifest").
Unsigned packs say "not signed".

## Tests

```bash
python -m pytest -q          # 659 tests collected
```

Run once per test file, six files at a time (no xdist installed), on python 3.13.15 and node v25.8.0:
639 passed, 20 skipped (the opt-in real-integration tests: `GCL_INTEG_*` unset), 0 failed, all 47 files
exit 0; wall time 336 s with six files in parallel (a serial run was not timed).

The fixtures are written for the demo: `examples/portability/rules.vulnerable.yaml`
(each rule is one known divergence class), `examples/coverage/rules.english-only.yaml`
(reasonable English rules), `examples/failopen/tool_runner.py` (both policies).
