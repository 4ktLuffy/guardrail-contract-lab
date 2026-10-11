"""The tester's own mistakes, stage 4: a final refusal does not hide that the provider
already saw the request, every result carries its boundary timeline, and a result that
changes with the guard's latency is reported as timing-dependent."""

import re
import threading

from gcl.enforce.contracts import latency_sweep, run_contracts

from .test_enforce import _by, _Fake


def _sid(messages) -> str:
    m = re.search(r"GCL-U-([io]\d{2})", messages[0]["content"])
    return m.group(1) if m else ""


def test_a_refusal_after_the_provider_saw_the_request_is_ordered_and_flagged(tmp_path):
    def forwards_first(g, m):
        if _sid(m) != "i04":
            return g.strict(m)
        g.forward(m)                                  # the provider sees it ...
        g.scan("input", [m[0]["content"]])            # ... before the guard is even asked
        return 400, {"error": "blocked"}

    run = run_contracts(_Fake(tmp_path, forwards_first), 5, settle_s=0.3)
    r = _by(run, "input", "error")
    assert (r["observed"], r["policy"]) == ("blocked after send", "violated")
    assert r["evidence"]["provider_before_verdict_s"] is not None
    whats = [(x["at"], x["what"]) for x in r["evidence"]["timeline"]]
    first_provider = next(i for i, (at, _) in enumerate(whats) if at == "provider")
    first_answer = next(i for i, (at, w) in enumerate(whats) if at == "guard" and "delivered" in w)
    assert first_provider < first_answer and whats[-1][0] == "client"
    assert any("before the guard answered" in n for n in r["notes"])
    # A clean block has no such flag.
    assert _by(run, "input", "block")["evidence"]["provider_before_verdict_s"] is None


def test_a_race_that_shows_only_with_a_slow_guard_is_unstable(tmp_path):
    def racing(g, m):
        """Checks and calls the model at the same time; the model call waits 0.2 s and is
        skipped if a block arrived by then (a common 'parallel guardrail' design)."""
        verdict: dict = {}

        def check():
            verdict.update(g.scan("input", [x["content"] for x in m]) or {})

        t = threading.Thread(target=check)
        t.start()
        t.join(0.2)
        if verdict.get("action") == "BLOCKED":
            return 400, {"error": "blocked"}
        reply = g.forward(m)
        t.join()
        if verdict.get("action") != "NONE":
            return 400, {"error": "blocked"}
        return 200, {"choices": [{"message": {"role": "assistant", "content": reply}}]}

    sweep = latency_sweep(_Fake(tmp_path, racing), [0.0, 0.6], 5, settle_s=0.3, only={"none"})
    block = next(x for x in sweep["stability"] if (x["stage"], x["mode"], x["role"]) == ("input", "block", "open"))
    assert not block["stable"]
    assert block["by_latency"]["0.0"]["observed"] == "stopped"
    assert block["by_latency"]["0.6"]["observed"] == "blocked after send"
    assert sweep["unstable"] >= 1


def test_cli_latency_sweep_reports_stability(tmp_path):
    import sys

    from typer.testing import CliRunner

    from gcl.cli import app

    runner = CliRunner(env={"COLUMNS": "200", "NO_COLOR": "1", "TERM": "dumb"})
    bad = runner.invoke(app, ["enforce", "reference", "--python", sys.executable, "--profile", "strict",
                              "--judge-latency", "0,x"])
    assert bad.exit_code == 2
    ok = runner.invoke(app, ["enforce", "reference", "--python", sys.executable, "--profile", "strict",
                             "--judge-latency", "0,0.1", "--scenario", "none", "--timeout", "10"])
    assert ok.exit_code == 0, ok.output
    assert "Guard latency sweep [0.0, 0.1] s: 0 result(s) change with timing" in ok.output
