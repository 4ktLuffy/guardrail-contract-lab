# Numbers

Every number in the README comes from `gcl demo` on the bundled fixtures, recorded
from `demo-out/report.json` (python 3.13.15, node v25.8.0, macOS). Regenerate with
`make demo`; the JSON is the record.

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
| Same rules, false positives | 2.8% (4/144); English hard negatives 2/6 (a Wi-Fi password note, a harmless "don't tell") | `…aggregate`, `…by_lang.en` |
| The one case node misses | Amharic `የ.env`: `\b` before `.env` exists in Python (Ethiopic letter = word char), not in JS | `…compare` |
| Fail-open runner: scanner faults that let the call run | 6 of 6 | `sections[3].probe.summary` |
| Fail-closed runner | 0 of 6; both controls held | `sections[4].probe.summary` |
| Reference gateway, naive build: scenarios breaking its documented fail-closed contract | 18 of 38 (strict build: 0 of 38) | `sections[5].enforce.summary`, `sections[6]` |
| MCP gateway (`reference-mcp`), naive build: surfaces that reach the client or server unscanned | 15 of 18 at the default protocol 2025-03-26 (m02 structuredContent is run in every session, since real gateways carry it in older sessions too). Strict build: 0 of 18 violated, 17 held, 2 n/a (m15 unlisted tool and m16 batch refused, so not carried). At `--mcp-protocol 2025-06-18` m16 batches are not in the protocol (n/a, not run) | `sections[7].enforce.mcp_surfaces.summary`, `sections[8]` |
| Wall time | ~175 s in total (173 s measured; most of it the deliberate hang, timing and timeout drills, and ~25 s per MCP build) | terminal |

The MCP row is produced by two commands (no model, no network; the stand-in scanner answers
block only for text carrying a `GCL-A-` marker). The count excludes m00, the baseline path the
ordinary contract already tests; "violated" is `passed unscanned` or `passed despite block`:

```bash
gcl enforce reference-mcp --python python3 --profile naive --extra mcp
gcl enforce reference-mcp --python python3 --profile strict --extra mcp
```

`gcl demo` runs the first command (and the strict build) with only the opening controls
of the ordinary plan, which is what makes it ~25 s per build.

The fixtures are written for the demo: `examples/portability/rules.vulnerable.yaml`
(each rule is one known divergence class), `examples/coverage/rules.english-only.yaml`
(reasonable English rules), `examples/failopen/tool_runner.py` (both policies).
