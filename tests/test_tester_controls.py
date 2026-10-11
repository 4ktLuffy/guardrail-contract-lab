"""The tester's own mistakes, stage 2: controls that bracket the run. A setup that breaks
half-way, fails on one script, cuts answers, or crashes on a block must not turn into
"held"; a correct gateway must still hold everything."""

import sys
from pathlib import Path

from gcl.enforce.adapters import ReferenceGateway
from gcl.enforce.contracts import OBSERVE_CHARS, build_scenarios, run_contracts

from .test_enforce import _by, _Fake


def _not_held(run):
    return [(r["scenario"]["id"], r["scenario"]["mode"], r["observed"], r["notes"])
            for r in run["results"] if r["policy"] != "held"]


def test_the_plan_brackets_the_run_and_covers_every_language():
    sc = build_scenarios(ReferenceGateway(sys.executable, Path("/tmp")), "abc123")
    assert len({s.id for s in sc}) == len(sc)
    covered = {s.lang for s in sc if s.phase in ("open", "lang") and s.stage == "input" and s.mode == "allow"}
    assert {s.lang for s in sc if not s.control} <= covered
    roles = [s.role for s in sc]
    assert roles.count("close") == 3 and roles[-1] == "observe"
    assert len(sc[-1].reply_text) >= OBSERVE_CHARS
    # Ordinary scenarios keep their ids: the tail is appended, nothing before it moves.
    head = [s.id for s in sc if s.phase in ("open", "")]
    assert head == [s.id for s in sc][: len(head)]


def test_a_correct_gateway_still_holds_everything(tmp_path):
    run = run_contracts(_Fake(tmp_path, lambda g, m: g.strict(m)), 5, settle_s=0.3)
    assert not _not_held(run)


def test_a_setup_that_breaks_half_way_is_not_held(tmp_path):
    calls = {"n": 0}

    def breaks(g, m):
        calls["n"] += 1
        if calls["n"] <= 8:
            return g.strict(m)
        g.scan("input", [m[0]["content"]])       # still asks the guard...
        return 502, {"error": "upstream credentials expired"}   # ...but nothing works any more

    run = run_contracts(_Fake(tmp_path, breaks), 5, settle_s=0.3)
    late = [r for r in run["results"] if not r["scenario"]["control"] and r["observed"] == "stopped"
            and int(r["scenario"]["id"][1:]) >= 8]
    assert late, "the break produced no stopped scenario: the test does not exercise the check"
    assert all(r["policy"] == "unverified" for r in late), [(r["scenario"]["id"], r["notes"]) for r in late]


def test_a_gateway_that_fails_on_one_script_is_not_held(tmp_path):
    def no_arabic(g, m):
        if "المستند" in m[0]["content"]:
            g.scan("input", [m[0]["content"]])
            return 400, {"error": "unsupported characters"}
        return g.strict(m)

    run = run_contracts(_Fake(tmp_path, no_arabic), 5, settle_s=0.3)
    ar = [r for r in run["results"] if r["scenario"]["lang"] == "ar" and not r["scenario"]["control"]]
    assert ar and all(r["policy"] == "unverified" for r in ar)
    assert any("language (ar)" in n for r in ar for n in r["notes"])
    assert any(r["policy"] == "held" for r in run["results"] if r["scenario"]["lang"] != "ar"
               and not r["scenario"]["control"])


def test_a_driver_that_cuts_answers_cannot_hide_a_leak(tmp_path):
    def cut(obj):
        for c in obj.get("choices") or []:
            c["message"]["content"] = c["message"]["content"][:300]
        if "error" in obj:
            obj["error"] = obj["error"][:300]
        return obj

    def leaky_then_cut(g, m):
        texts = [x["content"] for x in m]
        v = g.scan("input", texts) or {}
        if v.get("action") == "BLOCKED":
            return 400, {"error": "blocked"}
        if v.get("action") != "NONE":
            return 400, {"error": "scanner"}
        reply = g.forward(m)
        o = g.scan("output", [reply]) or {}
        if o.get("action") == "NONE":
            return 200, cut({"choices": [{"message": {"role": "assistant", "content": reply}}]})
        if o.get("action") == "BLOCKED":
            return 400, {"error": "blocked"}
        # On a guard failure the reply leaks inside the error, after a long preamble the
        # "driver" cuts off: the leak is real, the client body no longer shows it.
        return 400, cut({"error": "x" * 300 + reply})

    run = run_contracts(_Fake(tmp_path, leaky_then_cut), 5, settle_s=0.3)
    out_faults = [r for r in run["results"] if r["scenario"]["stage"] == "output" and not r["scenario"]["control"]]
    assert out_faults and all(r["observed"] == "stopped" for r in out_faults)
    assert all(r["policy"] == "unverified" for r in out_faults)
    assert any("long-reply control" in n for r in out_faults for n in r["notes"])


def test_a_crash_on_the_block_answer_is_not_a_block_control(tmp_path):
    def crashes_on_block(g, m):
        return g.strict(m, on_block=lambda msgs: (500, {"error": "KeyError: 'reason'"}))

    run = run_contracts(_Fake(tmp_path, crashes_on_block), 5, settle_s=0.3)
    ctl = _by(run, "input", "block")
    assert ctl["policy"] == "unverified" and any("server error" in n for n in ctl["notes"])
    assert all(r["policy"] == "unverified" for r in run["results"]
               if r["scenario"]["stage"] == "input" and not r["scenario"]["control"])
