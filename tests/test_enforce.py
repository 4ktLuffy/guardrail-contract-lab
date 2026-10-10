"""`gcl enforce`: the runner, the classification and the two verdicts.

The reference gateway (examples/enforce/ref_gateway.py) runs everywhere, so CI exercises
the whole loop. Real integrations are opt-in: set GCL_INTEG_PYTHON to the python of an
environment with `litellm[proxy]` and `nemoguardrails[server]` installed.
"""

import os
import sys
from pathlib import Path
from typing import ClassVar

import pytest

from gcl.enforce.adapters import ADAPTERS, LiteLLMProxy, NemoServer, ReferenceGateway
from gcl.enforce.contracts import POLICY, build_scenarios, run_contracts
from gcl.enforce.servers import FAULTS, MockModel, StandInScanner

INTEG = os.environ.get("GCL_INTEG_PYTHON")
needs_integ = pytest.mark.skipif(not INTEG, reason="set GCL_INTEG_PYTHON to run real integrations")


def _by(run, stage, mode):
    return next(r for r in run["results"] if r["scenario"]["stage"] == stage and r["scenario"]["mode"] == mode)


def test_scenarios_cover_controls_faults_and_languages():
    sc = build_scenarios(ReferenceGateway(sys.executable, Path("/tmp")))
    modes = {(s.stage, s.mode) for s in sc}
    assert {("input", "allow"), ("input", "block"), ("output", "block")} <= modes
    assert all(("input", f) in modes and ("output", f) in modes for f in FAULTS)
    assert {s.lang for s in sc} >= {"es", "fr", "he", "pt"}
    assert all(s.lang not in ("am", "sw") for s in sc)
    assert POLICY["allow"] == "passed" and POLICY["modify"] == "modified"


def test_reference_strict_holds_everything(tmp_path):
    run = run_contracts(ReferenceGateway(sys.executable, tmp_path, "strict"), 15)
    assert run["summary"]["policy_held"] == run["summary"]["scenarios"]
    assert all(r["documented"] == "conforms" for r in run["results"])
    assert _by(run, "input", "modify")["observed"] == "modified"
    assert _by(run, "output", "modify")["observed"] == "modified"


def test_reference_naive_is_caught_as_a_deviation_from_its_own_docs(tmp_path):
    run = run_contracts(ReferenceGateway(sys.executable, tmp_path, "naive"), 15)
    for stage in ("input", "output"):
        for f in ("error", "timeout", "malformed", "empty", "wrong_schema", "unknown_verdict", "verdict_type",
                  "refused"):
            r = _by(run, stage, f)
            assert (r["observed"], r["policy"], r["documented"]) == ("passed", "violated", "deviates"), (stage, f)
    # Every control still holds, so the faults are attributable to error handling.
    assert run["summary"]["documented_deviates"] == 16
    for key in (("input", "allow"), ("input", "block"), ("output", "allow"), ("output", "block")):
        assert _by(run, *key)["policy"] == "held", key


def test_a_dead_allow_control_makes_everything_unverified(tmp_path):
    class Dead(ReferenceGateway):
        def call(self, messages, timeout_s):  # never forwards anything
            from gcl.enforce.adapters import Observation

            return Observation(200, "{}", True, 0.0)

    run = run_contracts(Dead(sys.executable, tmp_path, "strict"), 5, settle_s=0.3)
    # Nothing reached the model or the scanner: no scenario, not even the allow control
    # itself, can be judged. Never "held".
    assert run["summary"]["unverified"] == run["summary"]["scenarios"]
    assert run["summary"]["policy_held"] == 0
    assert any("never consulted" in n for n in _by(run, "input", "allow")["notes"])


def _post_json(url, obj):
    import json
    import urllib.request

    r = urllib.request.urlopen(urllib.request.Request(url, data=json.dumps(obj).encode()), timeout=3)
    return json.loads(r.read())


def test_standin_has_a_listener_per_stage_and_reopens_after_refused():

    path = LiteLLMProxy.protocol.path
    with StandInScanner(LiteLLMProxy.protocol) as sc:
        sc.configure({"input": "allow", "output": "block"})
        assert _post_json(sc.base_for("input") + path, {"input_type": "request"})["action"] == "NONE"
        assert _post_json(sc.base_for("output") + path, {"input_type": "response"})["action"] == "BLOCKED"
        # Refusing one stage leaves the other listening.
        sc.configure({"input": "allow", "output": "refused"})
        with pytest.raises(OSError):
            _post_json(sc.base_for("output") + path, {"input_type": "response"})
        assert _post_json(sc.base_for("input") + path, {"input_type": "request"})["action"] == "NONE"
        sc.configure({"input": "modify"}, "שלום [REDACTED]")
        assert _post_json(sc.base_for("input") + path,
                          {"input_type": "request", "texts": ["a"]})["texts"] == ["שלום [REDACTED]"]
        assert _post_json(sc.base_for("output") + path, {"input_type": "response"})["action"] == "NONE"


def test_standin_rejects_wrong_path_and_unknown_stage():
    import urllib.error

    path = LiteLLMProxy.protocol.path
    with StandInScanner(LiteLLMProxy.protocol) as sc:
        sc.configure({"input": "allow", "output": "allow"})
        for url, body in ((sc.base_for("input") + "/elsewhere", {"input_type": "request"}),
                          (sc.base_for("input") + path, {}),                       # no stage
                          (sc.base_for("input") + path, {"input_type": "banana"}),
                          (sc.base_for("input") + path, {"input_type": "response"})):  # wrong listener
            with pytest.raises(urllib.error.HTTPError):
                _post_json(url, body)
        assert sc.consulted("input") == 0 and sc.consulted("output") == 0
        assert len(sc.events) == 4


def test_mock_model_records_what_reaches_the_provider():
    with MockModel("réponse GCL-R") as m:
        _post_json(m.openai_base + "/chat/completions",
                   {"model": "x", "messages": [{"role": "user", "content": "hola GCL-U"}]})
        m.reset("other")
        assert "GCL-U" in m.received_text() and len(m.requests) == 1  # reset never clears


# --------------------------------------------------------------------------- fake gateways
class _Fake(ReferenceGateway):
    """An in-process gateway whose behaviour is a function, for adversarial cases."""

    name = "fake"
    documented: ClassVar[dict] = {"default": ReferenceGateway._closed}

    def __init__(self, workdir, behave):
        super().__init__(sys.executable, workdir, "default")
        self.behave = behave

    def start(self, model, scanner):
        import json
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        self.model, self.scanner = model, scanner
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                res = outer.behave(outer, body["messages"])
                if res is None:          # drop the connection without answering
                    self.close_connection = True
                    return
                code, obj = res
                b = json.dumps(obj, ensure_ascii=False).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.srv.daemon_threads = True
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()

    def scan(self, stage, texts):
        try:
            return _post_json(self.scanner.base_for(stage) + self.protocol.path,
                              {"texts": texts, "input_type": {"input": "request", "output": "response"}[stage]})
        except Exception:
            return None

    def forward(self, messages):
        r = _post_json(self.model.openai_base + "/chat/completions", {"model": "m", "messages": messages})
        return r["choices"][0]["message"]["content"]

    def strict(self, messages, on_block=None, on_modify=None):
        """Correct behaviour, with hooks to misbehave on one verdict."""
        texts = [m["content"] for m in messages]
        v = self.scan("input", texts) or {}
        if v.get("action") == "BLOCKED":
            return on_block(messages) if on_block else (400, {"error": "blocked"})
        if v.get("action") == "GUARDRAIL_INTERVENED":
            if on_modify:
                return on_modify(messages)
            messages = [{**m, "content": t} for m, t in zip(messages, v["texts"], strict=True)]
        elif v.get("action") != "NONE":
            return 400, {"error": "scanner"}
        reply = self.forward(messages)
        o = self.scan("output", [reply]) or {}
        if o.get("action") == "NONE":
            return 200, {"choices": [{"message": {"role": "assistant", "content": reply}}]}
        if o.get("action") == "GUARDRAIL_INTERVENED":
            return 200, {"choices": [{"message": {"role": "assistant", "content": o["texts"][0]}}]}
        return 400, {"error": "blocked"}


def test_fake_strict_gateway_holds_everything(tmp_path):
    run = run_contracts(_Fake(tmp_path, lambda g, m: g.strict(m)), 5, settle_s=0.3)
    assert run["summary"]["policy_held"] == run["summary"]["scenarios"], [
        (r["scenario"]["id"], r["observed"], r["notes"]) for r in run["results"] if r["policy"] != "held"]


def test_forwarding_the_text_without_its_marker_is_not_stopped(tmp_path):
    def strip(g, m):
        def leak(msgs):
            g.forward([{"role": "user", "content": msgs[0]["content"].rsplit(" GCL-U-", 1)[0]}])
            return 400, {"error": "blocked"}
        return g.strict(m, on_block=leak)

    run = run_contracts(_Fake(tmp_path, strip), 5, settle_s=0.3)
    r = _by(run, "input", "block")
    assert (r["observed"], r["policy"]) == ("altered", "violated")


def test_a_marker_only_or_mixed_rewrite_is_not_modified(tmp_path):
    def marker_only(g, m):
        def bad(msgs):
            mark = "GCL-M-" + msgs[0]["content"].rsplit("GCL-U-", 1)[1]
            reply = g.forward([{"role": "user", "content": mark}])
            return 200, {"choices": [{"message": {"content": reply}}]}
        return g.strict(m, on_modify=bad)

    run = run_contracts(_Fake(tmp_path, marker_only), 5, settle_s=0.3)
    assert _by(run, "input", "modify")["observed"] == "altered"
    assert _by(run, "input", "modify")["policy"] == "violated"


def test_a_delayed_forward_after_the_rejection_is_caught(tmp_path):
    import threading

    def late(g, m):
        def later(msgs):
            threading.Timer(1.0, g.forward, args=(msgs,)).start()
            return 400, {"error": "blocked"}
        return g.strict(m, on_block=later)

    run = run_contracts(_Fake(tmp_path, late), 5, settle_s=0.3)
    r = _by(run, "input", "block")
    # The client was refused, but the provider got the prompt a second later.
    assert (r["observed"], r["policy"]) == ("blocked after send", "violated")
    assert r["evidence"]["late_provider_calls_s"]
    assert any("after the scenario had settled" in n for n in r["notes"])


def test_unconsulted_controls_unlock_nothing(tmp_path):
    def blind(g, m):                         # never asks the scanner
        reply = g.forward(m)
        return 200, {"choices": [{"message": {"content": reply}}]}

    run = run_contracts(_Fake(tmp_path, blind), 5, settle_s=0.3)
    assert run["summary"]["policy_held"] == 0
    assert run["summary"]["unverified"] == run["summary"]["scenarios"]


def test_a_dropped_connection_is_unverified_not_stopped(tmp_path):
    run = run_contracts(_Fake(tmp_path, lambda g, m: (g.scan("input", [m[0]["content"]]), None)[1]), 5,
                        settle_s=0.3)
    r = _by(run, "input", "allow")
    assert r["observed"] == "transport failure" and r["policy"] == "unverified"
    assert run["summary"]["policy_held"] == 0


def test_output_refused_requires_a_generated_reply(tmp_path):
    run = run_contracts(ReferenceGateway(sys.executable, tmp_path, "strict"), 15)
    r = _by(run, "output", "refused")
    assert r["evidence"]["model_input"] == "passed" and r["policy"] == "held"
    # The input listener stayed up and was consulted for this scenario.
    assert any(e["listener"] == "input" and e["valid"] for e in r["evidence"]["scanner_events"])


def test_client_deadline_is_absolute(tmp_path):
    import threading
    import time
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from gcl.enforce.adapters import _post

    class Drip(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.end_headers()
            for _ in range(100):
                self.wfile.write(b"x")
                self.wfile.flush()
                time.sleep(0.2)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Drip)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        o = _post(f"http://127.0.0.1:{srv.server_address[1]}/", {}, None, 1.5)
    finally:
        srv.shutdown()
    assert not o.finished and o.elapsed_s < 2.5 and o.text.startswith("x")


def test_reference_strict_rejects_malformed_rewrites():
    import argparse
    import importlib.util

    from gcl.enforce.adapters import _ref_gateway_path

    spec = importlib.util.spec_from_file_location("ref_gateway", _ref_gateway_path())
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for texts in ([], ["only one"], ["a", "b", "c"], [1, 2]):
        mod.post = lambda url, body, timeout, t=texts: {"action": "GUARDRAIL_INTERVENED", "texts": t}
        args = argparse.Namespace(scanner="x", scanner_output="", policy="strict")
        assert mod.check(args, ["one", "two"], "request")[0] == "block", texts


def test_cli_rejects_unknown_fail_on_and_reports_incomplete_runs():
    from typer.testing import CliRunner

    from gcl.cli import _enforce_exit, app

    res = CliRunner().invoke(app, ["enforce", "reference", "--python", sys.executable, "--fail-on", "polcy"])
    assert res.exit_code == 2 and "fail-on" in res.output.lower()
    s = {"scenarios": 10, "policy_held": 8, "policy_violated": 0, "unverified": 2, "documented_deviates": 0}
    assert _enforce_exit(s, "policy", allow_incomplete=False) == 2
    assert _enforce_exit(s, "policy", allow_incomplete=True) == 0
    assert _enforce_exit({**s, "policy_violated": 1}, "policy", allow_incomplete=False) == 1
    assert _enforce_exit({**s, "policy_violated": 1}, "never", allow_incomplete=False) == 0


def test_judge_requests_are_routed_to_the_standin_and_staged_by_content():
    from gcl.enforce.adapters import OPENAI_GUARDRAILS_JUDGE as P

    with StandInScanner(P) as sc, MockModel("ok", judge=sc) as m:
        sc.configure({"input": "block", "output": "judge_refusal"})
        url = m.openai_base + "/chat/completions"
        r = _post_json(url, {"model": "gcl-judge", "messages": [{"role": "user", "content": "hola GCL-U-i01"}]})
        assert '"flagged": true' in r["choices"][0]["message"]["content"]
        r = _post_json(url, {"model": "gcl-judge", "messages": [{"role": "user", "content": "réponse GCL-R-o02"}]})
        assert r["choices"][0]["message"]["content"] is None and r["choices"][0]["message"]["refusal"]
        _post_json(url, {"model": "gcl-mock", "messages": [{"role": "user", "content": "x"}]})
        assert [e["stage"] for e in sc.events] == ["input", "output"]
        assert len(m.events) == 1  # judge calls are not provider calls


def test_shared_endpoint_guards_skip_refused_and_add_judge_faults(tmp_path):
    from gcl.enforce.adapters import OpenAIGuardrails

    sc = build_scenarios(OpenAIGuardrails(sys.executable, tmp_path))
    modes = {(s.stage, s.mode) for s in sc}
    assert ("input", "refused") not in modes and ("input", "judge_refusal") in modes
    assert POLICY["judge_refusal"] == "stopped"


def test_a_check_running_alongside_the_model_is_blocked_after_send(tmp_path):
    def parallel(g, m):
        reply = g.forward(m)                       # the model call is already out
        v = g.scan("input", [m[0]["content"]]) or {}
        if v.get("action") != "NONE":
            return 400, {"error": "blocked"}
        o = g.scan("output", [reply]) or {}
        if o.get("action") != "NONE":
            return 400, {"error": "blocked"}
        return 200, {"choices": [{"message": {"content": reply}}]}

    run = run_contracts(_Fake(tmp_path, parallel), 5, settle_s=0.3)
    r = _by(run, "input", "block")
    assert (r["observed"], r["policy"]) == ("blocked after send", "violated")


def test_type_confused_verdicts_keep_meaning_change_type():
    from gcl.enforce.servers import _type_confuse

    assert _type_confuse({"verdict": False}) == {"verdict": "false"}
    assert _type_confuse({"action": "BLOCKED", "blocked_reason": "x"}) == {"action": "blocked", "blocked_reason": "x"}
    assert _type_confuse({"jailbreak": True, "score": 0.99}) == {"jailbreak": "true", "score": 0.99}


def test_adapters_registry():
    assert set(ADAPTERS) == {"litellm", "nemo", "openai-guardrails", "portkey", "reference"}


# Real integrations: these pin what was observed on litellm 1.104.2 and nemoguardrails
# 0.24.1. A different version may legitimately change them; the run records versions.
def _controls_hold(run):
    for r in run["results"]:
        if r["scenario"]["control"]:
            assert r["policy"] == "held", (r["scenario"]["stage"], r["scenario"]["mode"], r["notes"])


@needs_integ
def test_real_litellm_default_profile(tmp_path):
    run = run_contracts(LiteLLMProxy(INTEG, tmp_path, "default"), 30)
    _controls_hold(run)
    for stage in ("input", "output"):
        for f in ("error", "malformed", "empty", "refused"):
            assert (_by(run, stage, f)["policy"], _by(run, stage, f)["documented"]) == ("held", "conforms")
        for f in ("wrong_schema", "unknown_verdict"):  # no valid action read as "NONE"
            r = _by(run, stage, f)
            assert (r["observed"], r["policy"], r["documented"]) == ("passed", "violated", "unspecified")
        assert _by(run, stage, "modify")["observed"] == "modified"


@needs_integ
def test_real_litellm_fail_open_profile(tmp_path):
    run = run_contracts(LiteLLMProxy(INTEG, tmp_path, "fail_open"), 30, only={"i10", "o18"})
    _controls_hold(run)
    for stage in ("input", "output"):
        r = _by(run, stage, "refused")
        assert (r["observed"], r["policy"], r["documented"]) == ("passed", "violated", "conforms")


@needs_integ
def test_real_nemo_jailbreak_rail(tmp_path):
    run = run_contracts(NemoServer(INTEG, tmp_path), 45)
    _controls_hold(run)
    r = _by(run, "input", "error")
    assert (r["observed"], r["policy"], r["documented"]) == ("passed", "violated", "conforms")
    assert _by(run, "input", "wrong_schema")["observed"] == "passed"


@needs_integ
def test_real_openai_guardrails_pre_flight(tmp_path):
    from gcl.enforce.adapters import OpenAIGuardrails

    run = run_contracts(OpenAIGuardrails(INTEG, tmp_path, "pre_flight"), 45)
    _controls_hold(run)
    assert _by(run, "input", "error")["observed"] == "stopped"
    # A judge that refuses, or answers nothing, reads as "not flagged" (0.3.3).
    for stage in ("input", "output"):
        for f in ("judge_refusal", "empty"):
            assert _by(run, stage, f)["observed"] == "passed", (stage, f)


NODE_ENV = os.environ.get("GCL_INTEG_NODE_ENV")  # a dir with node_modules/@portkey-ai/gateway


@pytest.mark.skipif(not NODE_ENV, reason="set GCL_INTEG_NODE_ENV to run Node integrations")
def test_real_portkey_fail_on_error(tmp_path):
    from gcl.enforce.adapters import PortkeyGateway

    run = run_contracts(PortkeyGateway(NODE_ENV, tmp_path, "fail_on_error"), 20)
    _controls_hold(run)
    for stage in ("input", "output"):
        assert _by(run, stage, "error")["observed"] == "stopped"
        assert _by(run, stage, "modify")["observed"] == "modified"
        # {"verdict": "false"} — a string — reads as a pass (1.15.2).
        assert _by(run, stage, "verdict_type")["observed"] == "passed"
