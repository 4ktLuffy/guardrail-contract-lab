"""Regressions for the tenth independent review (of the checks on the tester): a leaking
control stays a violation, another run's answer decides nothing, tool markers carry the
run id, a proven tool run survives the cached-reply check, the latency sweep keeps every
run and tells language controls apart, and "before the guard answered" uses the moment
the answer went out."""

import json
import re
import sys
import urllib.request
from types import SimpleNamespace

from gcl.enforce.contracts import Scenario, _judge, _order_flags, _owner_ids, classify_output, run_contracts
from gcl.enforce.servers import MockModel

from .test_enforce import _by, _Fake
from .test_review_round9 import _A, _controls, _r


def test_a_leaking_5xx_block_control_stays_violated():
    leak = _r("input", "block", "failed after send", True, client_status=500)
    clean = _r("input", "block", "stopped", True, client_status=500)
    for ctl in (leak, clean):
        _judge([c for c in _controls() if (c.scenario.stage, c.scenario.mode) != ("input", "block")] + [ctl], _A())
    assert leak.policy == "violated"
    assert clean.policy == "unverified" and any("server error" in n for n in clean.notes)


def test_another_runs_reply_in_the_client_body_decides_nothing():
    s = Scenario("o04", "output", "error", "es", "u", "secreto del documento", run="abc123")
    obs = lambda text: SimpleNamespace(text=text, status=200, finished=True, transport=False)  # noqa: E731
    assert classify_output(s, obs("secreto del documento GCL-R-o04-def456")) is None
    assert classify_output(s, obs("secreto del documento GCL-R-o04-abc123")) == "passed"
    assert classify_output(s, obs("secreto del documento")) == "altered"   # unmarked: still a leak


def test_foreign_traffic_for_another_scenario_is_not_charged_by_time_window(tmp_path):
    def replays(g, m):
        if re.search(r"GCL-U-i04-", m[0]["content"]):
            g.forward([{"role": "user", "content": "old traffic GCL-U-i05-def456"}])
        return g.strict(m)

    run = run_contracts(_Fake(tmp_path, replays), 5, settle_s=0.3)
    if run["receipt"]["run_id"] == "def456":  # pragma: no cover - a 1 in 16 million collision
        return
    r = _by(run, "input", "error")
    assert r["observed"] == "stopped" and r["policy"] == "unverified"
    assert r["evidence"]["other_run_events"] == 1


def test_tool_markers_carry_the_run_id():
    with MockModel("hola GCL-R-i04-abc123") as m:
        m.tools_mode = True
        req = urllib.request.Request(m.openai_base + "/chat/completions", data=json.dumps({
            "model": "x", "messages": [{"role": "user", "content": "hola GCL-U-i04-abc123"}],
            "tools": [{"type": "function", "function": {"name": "probe", "parameters": {}}}]}).encode(),
            headers={"Content-Type": "application/json"})
        body = json.loads(urllib.request.urlopen(req, timeout=5).read())
    args = body["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
    assert "GCL-T-i04-abc123" in args
    assert _owner_ids("GCL-T-i04", "def456") == set() and _owner_ids("GCL-T-i04-def456", "def456") == {"i04"}


def test_a_recorded_tool_run_survives_the_cached_reply_check():
    r = _r("input", "error", "tool executed", False, reply_without_provider_call=True)
    _judge([*_controls(), r], _A())
    assert r.policy == "violated"


def test_stability_tells_language_controls_apart():
    from gcl.enforce.contracts import _stability

    def run(fr, ar):
        mk = lambda sid, lang, obs, pol: {"scenario": {"id": sid, "stage": "input", "mode": "allow",  # noqa: E731
                                                      "role": "lang", "lang": lang},
                                         "observed": obs, "policy": pol}
        return {"results": [mk("i30", "fr", *fr), mk("i31", "ar", *ar)]}

    st = _stability([0.0, 1.0], [run(("passed", "held"), ("passed", "held")),
                                 run(("stopped", "violated"), ("passed", "held"))])
    by = {x["lang"]: x["stable"] for x in st}
    assert by == {"fr": False, "ar": True}


def test_before_the_guard_answered_uses_the_moment_the_answer_went_out():
    s = Scenario("i04", "input", "error", "es", "u", "r")
    mine = [{"t": 0.0, "t_sent": 1.0, "t_done": 2.0}]
    assert _order_flags(s, mine, [{"t": 1.5}], [])["provider_before_verdict_s"] is None
    assert _order_flags(s, mine, [{"t": 0.5}], [])["provider_before_verdict_s"] == 0.5


def test_cli_sweep_keeps_every_run_and_replays_at_its_latency(tmp_path):
    from typer.testing import CliRunner

    from gcl.cli import app

    out = tmp_path / "out"
    res = CliRunner(env={"COLUMNS": "200", "NO_COLOR": "1", "TERM": "dumb"}).invoke(
        app, ["enforce", "reference", "--python", sys.executable, "--profile", "naive", "--scenario", "i04",
              "--judge-latency", "0.2,0", "--timeout", "10", "--out", str(out)])
    assert res.exit_code == 1, res.output
    doc = json.loads((out / "report.json").read_text())
    assert [r["judge_latency_s"] for r in doc["enforce_by_latency"]] == [0.2, 0.0]
    assert doc["enforce"]["judge_latency_s"] == 0.2            # the slowest run is the one shown
    replays = sorted(p.read_text() for p in out.glob("latency-*/repro/*/REPLAY.txt"))
    assert any("--judge-latency 0.2" in t for t in replays) and any("--judge-latency 0 " in t for t in replays)
    assert "Guard latency sweep" in (out / "report.html").read_text()
    dup = CliRunner().invoke(app, ["enforce", "reference", "--python", sys.executable, "--profile", "naive",
                                   "--judge-latency", "0,0"])
    assert dup.exit_code == 2
