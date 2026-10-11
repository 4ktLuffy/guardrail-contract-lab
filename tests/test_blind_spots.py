"""Opt-in blind spots: streamed answers, the attack in an earlier turn, and a blocked
request sent twice. The default plan does not change."""

import json
import sys
from pathlib import Path

from gcl.enforce.adapters import ReferenceGateway
from gcl.enforce.contracts import build_scenarios, run_contracts

from .test_enforce import _by, _Fake

EXTRA = ("stream", "history", "retry")


def _sse(text):
    chunks = [text[i:i + 8] for i in range(0, len(text), 8)]
    return "".join(f"data: {json.dumps({'choices': [{'delta': {'content': c}}]})}\n\n" for c in chunks) + \
        "data: [DONE]\n\n"


def test_the_default_plan_is_unchanged_and_extras_come_last():
    g = ReferenceGateway(sys.executable, Path("/tmp"))
    base, more = build_scenarios(g, "abc123"), build_scenarios(g, "abc123", EXTRA)
    ordinary = [s for s in base if s.phase in ("open", "")]
    assert [(s.id, s.mode) for s in more][: len(ordinary)] == [(s.id, s.mode) for s in ordinary]
    added = [s for s in more if s.stream or s.history or (s.mode == "block_retry")]
    assert sorted((s.mode, s.stream, s.history) for s in added) == [
        ("block", True, False), ("block_retry", False, False), ("error", True, False),
        ("history_block", False, True)]


def test_a_strict_gateway_holds_every_blind_spot(tmp_path):
    run = run_contracts(_Fake(tmp_path, lambda g, m: g.strict(m)), 5, settle_s=0.3, extra=EXTRA)
    bad = [(r["scenario"]["id"], r["scenario"]["mode"], r["observed"], r["notes"]) for r in run["results"]
           if r["policy"] != "held"]
    assert not bad, bad


def test_a_gateway_that_streams_before_checking_the_output_is_caught(tmp_path):
    def streams_first(g, m):
        if not g.last_stream:
            return g.strict(m)
        v = g.scan("input", [x["content"] for x in m]) or {}
        if v.get("action") != "NONE":
            return 400, {"error": "blocked"}
        reply = g.forward(m)
        o = g.scan("output", [reply]) or {}
        tail = "" if o.get("action") == "NONE" else 'data: {"error": "blocked by the output guard"}\n\n'
        return 200, _sse(reply) + tail          # the reply already went out

    class Streamed(_Fake):
        def call(self, messages, timeout_s, stream=False):
            self.last_stream = stream
            return super().call(messages, timeout_s, stream=stream)

    run = run_contracts(Streamed(tmp_path, streams_first), 5, settle_s=0.3, extra=("stream",))
    streamed = [r for r in run["results"] if r["scenario"]["stream"]]
    assert streamed and all(r["policy"] == "violated" for r in streamed), \
        [(r["observed"], r["notes"]) for r in streamed]
    assert _by(run, "output", "block")["policy"] == "held"     # the non-streamed control still holds


def test_a_guard_that_sees_only_the_last_message_is_caught(tmp_path):
    def last_only(g, m):
        v = g.scan("input", [m[-1]["content"]]) or {}   # only the newest turn is checked
        if v.get("action") == "BLOCKED":
            return 400, {"error": "blocked"}
        if v.get("action") != "NONE":
            return 400, {"error": "scanner"}
        reply = g.forward(m)
        o = g.scan("output", [reply]) or {}
        if o.get("action") != "NONE":
            return 400, {"error": "blocked"}
        return 200, {"choices": [{"message": {"role": "assistant", "content": reply}}]}

    run = run_contracts(_Fake(tmp_path, last_only), 5, settle_s=0.3, extra=("history",))
    r = _by(run, "input", "history_block")
    assert (r["observed"], r["policy"]) == ("passed", "violated"), r["notes"]


def test_a_gateway_that_lets_a_retry_through_is_caught(tmp_path):
    seen: set = set()

    def forgets(g, m):
        text = m[0]["content"]
        if text in seen:                                 # a repeat skips the guard
            reply = g.forward(m)
            return 200, {"choices": [{"message": {"role": "assistant", "content": reply}}]}
        seen.add(text)
        return g.strict(m)

    run = run_contracts(_Fake(tmp_path, forgets), 5, settle_s=0.3, extra=("retry",))
    r = _by(run, "input", "block_retry")
    assert r["policy"] == "violated" and len(r["evidence"]["attempts"]) == 2
