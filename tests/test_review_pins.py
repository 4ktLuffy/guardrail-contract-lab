"""Pins for earlier review fixes that had no test of their own: single-listener staging,
stand-in snapshots and settle timing, tool-run attribution, JS driver serialisation, and
the one deadline across an MCP session."""

import json
import re
import shutil
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

import pytest

from gcl.enforce.adapters import LITELLM_GENERIC
from gcl.enforce.contracts import build_scenarios, run_contracts
from gcl.enforce.servers import MockModel, Protocol, StandInScanner
from tests.test_enforce import _Fake, _post_json


def _scan(sc, text, stage="input"):
    kind = {"input": "request", "output": "response"}[stage]
    return _post_json(sc.base_for(stage) + LITELLM_GENERIC.path, {"texts": [text], "input_type": kind})


def test_a_single_listener_guard_gets_no_output_refused_scenario():
    def plan(single):
        proto = Protocol(name="p", verdicts={}, single_listener=single)
        adapter = SimpleNamespace(capabilities={"input", "output"}, protocol=proto)
        return {(s.stage, s.mode) for s in build_scenarios(adapter)}

    assert ("input", "refused") in plan(True) and ("output", "refused") not in plan(True)
    assert ("output", "refused") in plan(False)


def test_a_slow_answer_keeps_the_configuration_it_was_received_under():
    with StandInScanner(LITELLM_GENERIC) as sc:
        sc.latency_s = 0.4
        sc.configure({"input": "modify"}, "REWRITE-A")
        got = []
        t = threading.Thread(target=lambda: got.append(_scan(sc, "hola GCL-U-i01")))
        t.start()
        time.sleep(0.15)
        sc.configure({"input": "allow"}, "REWRITE-B")  # the run moves on while the answer sleeps
        t.join(5)
        assert got and got[0]["texts"] == ["REWRITE-A"]


def test_quiet_time_counts_from_completion_and_includes_tool_runs():
    with StandInScanner(LITELLM_GENERIC) as sc:
        sc.latency_s = 0.3
        sc.configure({"input": "allow"})
        _scan(sc, "hola GCL-U-i01")
        ev = sc.events[0]
        assert sc.last_activity() >= ev["t"] + 0.25, "last activity is the arrival, not the completion"
    with MockModel("r") as m:
        assert m.last_activity() == 0.0
        _post_json(m.tool_url, {"note": "GCL-T-i01"})
        assert m.last_activity() == m.tool_events[-1]["t"] > 0


class _Tooled(_Fake):
    """A fake agent integration: advertises the probe tool; `behave` decides what runs."""

    capabilities: ClassVar[set] = {"input", "output", "tools"}


def _tool_runs(run, sid):
    return next(r for r in run["results"] if r["scenario"]["id"] == sid)["evidence"]["tool_runs"]


def test_tool_runs_are_attributed_by_exact_marker_then_by_time_window(tmp_path):
    def behave(g, msgs):
        if "GCL-U-o02" in msgs[0]["content"]:
            _post_json(g.model.tool_url, {"note": "GCL-T-i010"})  # not scenario i01's marker
        return g.strict(msgs)

    run = run_contracts(_Tooled(tmp_path, behave), 5, settle_s=0.3, only={"none"})
    assert _tool_runs(run, "i01") == []
    assert [e["body"] for e in _tool_runs(run, "o02")] == ['{"note": "GCL-T-i010"}']  # unmarked: its window


def test_an_agent_integration_must_run_the_probe_tool_on_the_input_allow_control(tmp_path):
    def idle(g, msgs):
        return g.strict(msgs)

    def uses_tool(g, msgs):
        tag = re.search(r"GCL-U-(i00(?:-[0-9a-f]{6})?)\b", msgs[0]["content"])
        if tag:  # echo the tool marker the model would send: the scenario's full tag
            _post_json(g.model.tool_url, {"note": f"GCL-T-{tag.group(1)}"})
        return g.strict(msgs)

    def notes(behave):
        run = run_contracts(_Tooled(tmp_path, behave), 5, settle_s=0.3, only={"none"})
        return next(r for r in run["results"] if r["scenario"]["id"] == "i00")["notes"]

    assert any("the probe tool never ran" in n for n in notes(idle))
    assert not any("the probe tool never ran" in n for n in notes(uses_tool))


# --------------------------------------------------------------------------- JS drivers
DRIVERS = Path(__file__).resolve().parent.parent / "gcl" / "enforce" / "drivers"


@pytest.mark.parametrize("driver", ["openai_agents_js_driver.cjs", "openai_guardrails_js_driver.cjs"])
def test_js_drivers_serialise_nested_state_recursively(driver):
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    src = (DRIVERS / driver).read_text()
    m = re.search(r"^const safe = .*?^};$", src, re.S | re.M)
    assert m, "the driver has no safe() serialiser"
    script = m.group(0) + """
const a = { state: { items: [{ role: "user", content: "hola" }] }, big: 10n };
a.self = a;
process.stdout.write(JSON.stringify(safe(a)));
"""
    out = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=30, check=True).stdout
    got = json.loads(out)
    assert got["state"]["items"][0]["content"] == "hola"
    assert got["self"] == "[cycle]" and got["big"] == "10"


# --------------------------------------------------------------------------- MCP deadline
def test_the_mcp_session_shares_one_deadline_across_its_steps(tmp_path):
    from gcl.enforce.adapters import InvariantMCP

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            raw = self.rfile.read(int(self.headers["Content-Length"]))
            time.sleep(0.5)  # each step is well inside the per-step limit below
            body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Mcp-Session-Id", "s1")
            self.send_header("Content-Length", str(len(body) if json.loads(raw).get("id") else 0))
            self.end_headers()
            if json.loads(raw).get("id"):
                self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    srv.handle_error = lambda *a: None  # the client gives up on the slow answer
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        a = InvariantMCP(sys.executable, tmp_path)
        a.port, a._mcp_base = srv.server_address[1], "http://127.0.0.1:1"
        started = time.perf_counter()
        obs = a.call([{"role": "user", "content": "hola GCL-U-i00"}], 1.2)  # 3 x 0.5 s > 1.2 s
        assert not obs.finished and "deadline" in (obs.error or ""), (obs.status, obs.error)
        assert time.perf_counter() - started < 2.5
    finally:
        srv.shutdown()
        srv.server_close()
