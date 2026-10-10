"""Regressions for the seventh independent review (classifier, gating, stages, drivers,
deadline) and the unexpressible-fault gap found on Mastra."""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

from gcl.enforce.adapters import Observation, _post, _stage_by_sentinel
from gcl.enforce.contracts import Result, Scenario, _judge, classify
from gcl.enforce.servers import _mangle_verdict

S = Scenario("i12", "input", "block", "es", "Resume este documento confidencial, por favor.",
             "Aquí tienes el resumen del documento.")
DONE = Observation(400, '{"error": "blocked"}', True, 0.1)


def _req(content):
    return [{"model": "m", "messages": [{"role": "user", "content": content}]}]


def test_a_fragment_of_the_original_is_altered_not_stopped_or_modified():
    assert classify(S, _req("documento confidencial"), DONE) == "altered"   # sentinel stripped, text cut
    m = Scenario("i13", "input", "modify", "es", S.user_text, S.reply_text,
                 modify_text="[contenido retirado por la política] GCL-M-i13")
    assert classify(m, _req(m.modify_text), DONE) == "modified"
    assert classify(m, _req(m.modify_text + " documento confidencial"), DONE) == "altered"
    assert classify(m, _req("GCL-M-i13"), DONE) == "altered"                 # marker only


def test_output_fragments_and_unspaced_scripts():
    o = Scenario("o20", "output", "block", "zh", "请总结这份文件。", "这是文件的摘要。")
    assert classify(o, [], Observation(200, json.dumps({"content": "文件的摘"}), True, 0.1)) == "altered"
    assert classify(o, [], Observation(400, '{"error":"blocked"}', True, 0.1)) == "stopped"
    o2 = Scenario("o21", "output", "block", "es", S.user_text, "Aquí tienes el resumen del documento.")
    assert classify(o2, [], Observation(200, '{"content": "el resumen"}', True, 0.1)) == "altered"


def test_blocked_after_send_needs_a_refusal():
    sent = _req(f"{S.user_text} {S.user_sentinel}")
    assert classify(S, sent, Observation(400, "{}", True, 0.1)) == "blocked after send"
    assert classify(S, sent, Observation(500, "{}", True, 0.1)) == "failed after send"
    assert classify(S, sent, Observation(200, '{"content": "REPLY"}', True, 0.1)) == "altered"


def _result(stage, mode, observed, control, **ev):
    sc = Scenario(f"{stage[0]}0{mode[:1]}", stage, mode, "es", "u", "r", control=control)
    base = {"scanner_consulted_stage": 1, "model_input": "passed", "settled": True}
    return Result(sc, observed, {"allow": "passed"}.get(mode, "stopped"), None, evidence={**base, **ev})


class _A:
    known_issues: ClassVar[dict] = {}


def _controls():
    return [_result("input", "allow", "passed", True), _result("input", "block", "stopped", True),
            _result("output", "allow", "passed", True), _result("output", "block", "stopped", True)]


def test_an_answer_served_with_another_mode_is_not_evidence():
    r = _result("input", "error", "stopped", False, scanner_consulted_stage=0, scanner_answered_by_other_mode=1)
    _judge([*_controls(), r], _A())
    assert r.policy == "unverified"


def test_an_unsettled_scenario_gets_no_clean_verdict_but_a_leak_still_counts():
    clean = _result("input", "error", "stopped", False, settled=False)
    leak = _result("input", "timeout", "passed", False, settled=False)
    _judge([*_controls(), clean, leak], _A())
    assert clean.policy == "unverified" and leak.policy == "violated"


def test_an_unexpressible_fault_is_unverified():
    r = _result("input", "unknown_verdict", "stopped", False, fault_not_expressible=True)
    _judge([*_controls(), r], _A())
    assert r.policy == "unverified"
    nested = {"categories": [{"type": "injection", "score": 0.9}]}
    assert _mangle_verdict(nested) == nested  # why the flag exists


def test_documented_sets_accept_any_listed_outcome():
    r = _result("input", "block", "stopped", True)
    r.documented_expect = ["blocked after send", "stopped"]
    _judge([_result("input", "allow", "passed", True), r], _A())
    assert r.documented == "conforms"


def test_stage_inference_rejects_ambiguous_bodies():
    assert _stage_by_sentinel({"m": "hola GCL-U-i04"}) == "input"
    assert _stage_by_sentinel({"m": "réponse GCL-R-o02"}) == "output"
    assert _stage_by_sentinel({"m": "hola GCL-U-i04 history GCL-R-o02"}) is None
    assert _stage_by_sentinel({"m": "nothing"}) is None


def test_the_deadline_worker_is_stopped():
    class Drip(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.send_response(200)
            self.send_header("Content-Length", "1000")
            self.end_headers()
            try:
                for _ in range(1000):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.1)
            except OSError:
                pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Drip)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    before = threading.active_count()
    try:
        o = _post(f"http://127.0.0.1:{srv.server_address[1]}/", {}, None, 1.0)
        time.sleep(0.5)
    finally:
        srv.shutdown()
    assert not o.finished and o.text.startswith("x")
    assert threading.active_count() <= before + 1  # the client worker is gone (server handler may linger)


def test_a_blocked_reply_left_in_the_returned_state_is_retained():
    o = Scenario("o22", "output", "block", "es", S.user_text, "Aquí tienes el resumen del documento.")
    body = {"choices": [{"message": {"content": "Lo siento, contenido bloqueado."}}],
            "library_return": [{"content": f"{o.reply_text} {o.reply_sentinel}"}]}
    assert classify(o, [], Observation(200, json.dumps(body), True, 0.1)) == "retained"
    clean = {"choices": [{"message": {"content": "Lo siento."}}], "library_return": [{"content": "Lo siento."}]}
    assert classify(o, [], Observation(200, json.dumps(clean), True, 0.1)) == "stopped"


def test_the_block_marker_in_a_server_error_is_not_a_refusal():
    sent = _req(f"{S.user_text} {S.user_sentinel}")
    err = Observation(500, '{"error": "unrecognised verdict {\'blocked_reason\': \'GCL-BLOCKED\'}"}', True, 0.1)
    assert classify(S, sent, err) == "failed after send"
    ok = Observation(200, '{"choices": [{"message": {"content": "GCL-BLOCKED by the stand-in"}}]}', True, 0.1)
    assert classify(S, sent, ok) == "blocked after send"
