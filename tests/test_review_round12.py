"""Regressions for the twelfth independent review (record, CI, attack mode): no secret
reaches a recording, the proxy is transparent, records keep their identity, recorded
replies are literal and count only for matching requests, compare and SARIF see every
latency and every attack, attack ids and faults cannot collide, attack runs replay the
same plan, and the Action passes arguments as given."""

import copy
import json
import subprocess
import sys
import urllib.request
from types import SimpleNamespace

import pytest

from gcl.compare import compare
from gcl.enforce.adapters import vendor_protocol
from gcl.enforce.contracts import Result, Scenario, _stand_in_confidence, attack_matrix, build_attack_scenarios
from gcl.record import RecordingProxy, load, to_spec

from .test_ci import ROOT, _write
from .test_record import _Vendor


def _raw(url, path, data, ctype):
    req = urllib.request.Request(url + path, data=data, headers={"Content-Type": ctype})
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.headers, r.read()


def test_no_secret_reaches_the_recording(tmp_path):
    out = tmp_path / "rec.jsonl"
    with _Vendor() as v, RecordingProxy(v.url, out) as p:
        _raw(p.url, "/v1/check?api_key=QUERY_SECRET", json.dumps(
            {"messages": [{"content": "hi"}], "nested": [{"key": "KEY_SECRET"}]}).encode(), "application/json")
        with pytest.raises(urllib.error.HTTPError):
            _raw(p.url, "/v1/check", b"password=FORM_SECRET&u=1", "application/x-www-form-urlencoded")
        with pytest.raises(urllib.error.HTTPError):
            _raw(p.url, "/v1/check", b"\x00SESSION_SECRET\x01", "application/octet-stream")
    text = out.read_text()
    assert "SECRET" not in text, text
    assert "[omitted: " in text


def test_the_proxy_forwards_response_headers_and_continues_numbering(tmp_path):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(200)
            self.send_header("X-Vendor-Verdict", "block")
            self.send_header("Set-Cookie", "session=SESSION_SECRET")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    up = f"http://127.0.0.1:{srv.server_address[1]}"
    out = tmp_path / "rec.jsonl"
    try:
        for _ in range(2):  # two sessions appending to one file
            with RecordingProxy(up, out) as p:
                headers, _ = _raw(p.url, "/x", b'{"messages": []}', "application/json")
                assert headers["X-Vendor-Verdict"] == "block"
    finally:
        srv.shutdown()
        srv.server_close()
    assert [r["n"] for r in load(out)] == [1, 2] and "SESSION_SECRET" not in out.read_text()
    dup = [*load(out), dict(load(out)[0])]
    with pytest.raises(ValueError, match="appears twice"):
        to_spec(dup, {"vendor": "v"}, 1, 2)


def test_recorded_replies_are_served_literally():
    spec = {"vendor": "v", "allow_response": {"ok": 1}, "block_response": {"x": 1},
            "recorded": {"block": {"flagged": True, "reason": "ECHO_TEXT MODIFY_TEXT"},
                         "request_shape": {"messages": 1}}}
    assert vendor_protocol(spec).verdicts["block"]({"text": "t"}, "m")["reason"] == "ECHO_TEXT MODIFY_TEXT"


def _res(events, mode="block"):
    return Result(Scenario("i01", "input", mode, "es", "u", "r"), "stopped", "stopped", None, policy="held",
                  evidence={"scanner_events": events})


def test_every_served_request_must_match_the_recorded_shape():
    spec = {"vendor": "v", "allow_response": {"a": 1}, "block_response": {"b": 1},
            "recorded": {"allow": {"a": 2}, "block": {"b": 2},
                         "request_shape": {"messages": 1, "content": ["str"], "path": "/v1/check"}}}
    adapter = SimpleNamespace(protocol=vendor_protocol(spec), harness_supplies_guard=False)
    ok = {"mode": "block", "path": "/v1/check", "body": {"messages": [{"content": "hi"}]}}
    mixed = _res([ok, {"mode": "block", "path": "/v1/check", "body": {"input": "attack"}}])
    multimodal = _res([dict(ok, body={"messages": [{"content": [{"type": "text"}]}]})])
    other_path = _res([dict(ok, path="/v2/other")])
    good = _res([ok])
    _stand_in_confidence([mixed, multimodal, other_path, good], adapter)
    assert [r.evidence["confidence"] for r in (mixed, multimodal, other_path, good)] == \
        ["guessed", "guessed", "guessed", "verified"]


def _attack_run(lat=None, cells=None):
    cells = cells or {}
    results = []
    for i, (aid, policy) in enumerate(cells.items()):
        results.append({"scenario": {"id": f"i{i:02d}", "stage": "input", "mode": "error", "role": "", "lang": "en",
                                     "attack": aid, "attack_flagged": True, "user_text": aid},
                        "observed": "passed" if policy == "violated" else "stopped", "policy": policy,
                        "documented": "unspecified", "evidence": {}, "notes": []})
    return {"integration": {"integration": "ref", "profile": "p", "versions": {}}, "judge_latency_s": lat,
            "results": results, "summary": {"scenarios": len(results), "unverified": 0}}


def test_compare_tells_attacks_apart_and_sees_every_latency(tmp_path):
    old = _write(tmp_path, "o", _attack_run(cells={"A": "held", "B": "held"}))
    new = _write(tmp_path, "n", _attack_run(cells={"A": "violated", "B": "held"}))
    assert [r["scenario"] for r in compare(old, new)["regressions"]] == ["input/error/en/A"]
    so, sn = tmp_path / "so" / "report.json", tmp_path / "sn" / "report.json"
    for p, _slow in ((so, "held"), (sn, "held")):
        p.parent.mkdir()
    fast_old, fast_new = _attack_run(0.0, {"A": "held"}), _attack_run(0.0, {"A": "violated"})
    so.write_text(json.dumps({"enforce": _attack_run(1.0, {"A": "held"}),
                              "enforce_by_latency": [fast_old, _attack_run(1.0, {"A": "held"})]}))
    sn.write_text(json.dumps({"enforce": _attack_run(1.0, {"A": "held"}),
                              "enforce_by_latency": [fast_new, _attack_run(1.0, {"A": "held"})]}))
    assert [r["scenario"] for r in compare(so, sn)["regressions"]] == ["input/error/en/A @0s"]


def test_sarif_keeps_every_attack_and_latency_apart():
    from gcl.report.sarif import enforce_sarif

    runs = [_attack_run(0.0, {"A": "violated", "B": "violated"}), _attack_run(1.0, {"A": "violated"})]
    res = enforce_sarif(runs, "x.yml")["runs"][0]["results"]
    hashes = {r["partialFingerprints"]["primaryLocationLineHash"] for r in res}
    assert len(res) == 3 and len(hashes) == 3
    assert {r["properties"]["attack"] for r in res} == {"A", "B"}


def test_attack_ids_and_faults_cannot_collide():
    adapter = SimpleNamespace(capabilities={"input", "output"}, protocol=SimpleNamespace(
        shared_endpoint=False, extra_faults={}, get_routes={}, single_listener=False))
    one = [{"id": 1, "lang": "en", "text": "a"}, {"id": "1", "lang": "en", "text": "b"}]
    with pytest.raises(ValueError, match="distinct"):
        build_attack_scenarios(adapter, one, {1: True, "1": False}, ["error"], {"en": "hi"})
    with pytest.raises(ValueError, match="each fault once"):
        build_attack_scenarios(adapter, one[:1], {1: True}, ["error", "error"], {"en": "hi"})
    m = attack_matrix([{"scenario": {"attack": "1", "lang": "en", "attack_flagged": True, "user_text": "a",
                                     "mode": "block"}, "observed": "passed", "policy": "violated"}])
    assert m["summary"]["detected_not_enforced"] == 1


def test_an_attack_run_replays_its_frozen_plan(tmp_path):
    from typer.testing import CliRunner

    from gcl.cli import app

    from .test_attacks import ATTACKS, DETECTOR

    f = tmp_path / "a b.jsonl"
    f.write_text(json.dumps(ATTACKS[0]) + "\n")
    out = tmp_path / "out dir"
    res = CliRunner().invoke(app, ["enforce", "reference", "--python", sys.executable, "--profile", "naive",
                                   "--timeout", "10", "--attacks", str(f), "--detector", str(DETECTOR),
                                   "--attack-faults", "error", "--out", str(out)])
    assert res.exit_code == 1, res.output
    plan = json.loads((out / "attack-plan.json").read_text())
    assert plan["flagged"] == {"a-en": True}
    replays = [p.read_text() for p in out.glob("repro/*/REPLAY.txt")]
    assert replays and all("--attack-plan" in t and "'" in t for t in replays)  # quoted paths with spaces


def test_the_action_keeps_each_argument_line_whole():
    script = (ROOT / "action.yml").read_text()
    loop = script[script.index("extra=()"):script.index('gcl "${args[@]}"')]
    r = subprocess.run(["bash", "-c", loop + 'printf "<%s>" "${extra[@]}"'], capture_output=True, text=True,
                       env={"GCL_EXTRA": "--sarif-anchor\nspecs/vendor config.yml\n\n--attack-limit\n2"}, timeout=10)
    assert r.stdout == "<--sarif-anchor><specs/vendor config.yml><--attack-limit><2>"


def test_dropped_integer_ids_render(tmp_path):
    from gcl.report.terminal import render_enforce

    run = copy.deepcopy(_attack_run(None, {"A": "held"}))
    run.update(receipt={}, known_issues={}, attack_matrix={**attack_matrix(run["results"]),
               "detector": {"name": "d"}, "faults": ["error"], "dropped": [2]})
    run["summary"].update(policy_held=1, policy_violated=0, documented_deviates=0,
                          documented_unspecified_violations=0)
    run["integration"].update(config={}, documented_source={})
    run["results"] = []  # only the attack summary is rendered here
    assert "2 (not sent)" in render_enforce(run)
