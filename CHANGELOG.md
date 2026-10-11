# Changelog

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
