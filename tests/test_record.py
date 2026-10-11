"""`gcl record`: real vendor replies, captured through a proxy, become recorded stand-in
answers — and only for requests shaped like the ones they answered."""

import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from gcl.enforce.adapters import vendor_protocol
from gcl.enforce.contracts import Result, Scenario, _stand_in_confidence
from gcl.record import RecordingProxy, load, to_spec


class _Vendor:
    """A fake vendor whose answer depends on the request (it points at the last message),
    like a real analyzer that locates a violation."""

    def __enter__(self):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                msgs = body.get("messages") or []
                bad = any("attack" in m.get("content", "") for m in msgs)
                out = {"flagged": bad, "location": f"messages.{len(msgs) - 1}" if bad else None,
                       "seen_auth": bool(self.headers.get("Authorization"))}
                b = json.dumps(out).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        return self

    def __exit__(self, *exc):
        self.srv.shutdown()
        self.srv.server_close()


def _post(url, body):
    req = urllib.request.Request(url + "/v1/check", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "Authorization": "Bearer sk-SECRET-1"})
    return json.loads(urllib.request.urlopen(req, timeout=5).read())


def _record(tmp_path):
    out = tmp_path / "rec.jsonl"
    with _Vendor() as v, RecordingProxy(v.url, out) as p:
        a = _post(p.url, {"messages": [{"role": "user", "content": "hello"}], "api_key": "sk-SECRET-2"})
        b = _post(p.url, {"messages": [{"role": "user", "content": "attack"}], "api_key": "sk-SECRET-2"})
    return out, a, b


def test_the_proxy_is_transparent_and_keeps_no_secrets(tmp_path):
    out, a, b = _record(tmp_path)
    assert a["flagged"] is False and b["flagged"] is True and b["seen_auth"] is True  # forwarded unchanged
    text = out.read_text()
    assert "sk-SECRET" not in text and "Authorization" not in text
    recs = load(out)
    assert [r["n"] for r in recs] == [1, 2] and recs[1]["request_shape"] == {"messages": 1}
    assert recs[0]["request"]["api_key"] == "[redacted]"


SPEC = {"vendor": "acme", "requests": [{"path": "/v1/check"}], "allow_response": {"flagged": False},
        "block_response": {"flagged": True, "location": "messages.0"}}


def test_recorded_replies_become_a_spec_and_count_only_for_their_shape(tmp_path):
    out, _, _ = _record(tmp_path)
    spec = to_spec(load(out), SPEC, allow=1, block=2)
    proto = vendor_protocol(spec)
    assert proto.recorded_modes == ("allow", "block") and proto.recorded_shape == {"messages": 1}
    assert proto.verdicts["block"]({}, "")["seen_auth"] is True       # the real answer, not the guess
    adapter = SimpleNamespace(protocol=proto, harness_supplies_guard=False)

    def res(mode, n):
        served = "block" if mode == "block_retry" else mode
        return Result(Scenario("i01", "input", mode, "es", "u", "r"), "stopped", "stopped", None, policy="held",
                      evidence={"scanner_events": [{"mode": served, "body": {"messages": [{}] * n}}]})

    same, longer, retry = res("block", 1), res("block", 3), res("block_retry", 1)
    _stand_in_confidence([same, longer, retry], adapter)
    assert same.evidence["confidence"] == "verified" and same.evidence["stand_in"] == "recorded"
    assert longer.evidence["confidence"] == "guessed" and retry.evidence["confidence"] == "guessed"


def test_to_spec_refuses_records_that_cannot_stand_for_a_verdict(tmp_path):
    out, _, _ = _record(tmp_path)
    recs = load(out)
    with pytest.raises(ValueError, match="identical"):
        to_spec(recs, SPEC, allow=1, block=1)
    with pytest.raises(ValueError, match="no record"):
        to_spec(recs, SPEC, allow=1, block=9)
    two = [*recs, dict(recs[1], n=3, request_shape={"messages": 2})]
    with pytest.raises(ValueError, match="same, known shape"):
        to_spec(two, SPEC, allow=1, block=3)
    failed = [*recs, dict(recs[1], n=4, status=500)]
    with pytest.raises(ValueError, match="not a successful"):
        to_spec(failed, SPEC, allow=1, block=4)
    redacted = [*recs, dict(recs[1], n=5, response={"flagged": True, "token": "[redacted]"})]
    with pytest.raises(ValueError, match="redacted"):
        to_spec(redacted, SPEC, allow=1, block=5)


def test_cli_to_spec(tmp_path):
    from typer.testing import CliRunner

    from gcl.cli import app

    out, _, _ = _record(tmp_path)
    spec = tmp_path / "acme.json"
    spec.write_text(json.dumps(SPEC))
    res = CliRunner().invoke(app, ["record", "to-spec", str(out), "--spec", str(spec), "--allow", "1",
                                   "--block", "2", "--out", str(tmp_path / "acme.recorded.json")])
    assert res.exit_code == 0, res.output
    assert json.loads((tmp_path / "acme.recorded.json").read_text())["recorded"]["request_shape"] == {"messages": 1}
