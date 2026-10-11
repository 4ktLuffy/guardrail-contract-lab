"""The tester's own mistakes, stage 3: a fault counts only if it reached the integration,
a provider call that cannot be tied to a scenario decides nothing, background traffic is
recorded, and a fault that a truthiness or prefix parser absorbs by accident has a twin
that it cannot (null)."""

import contextlib
import json
import re
import sys
import urllib.request

from gcl.enforce.adapters import ReferenceGateway
from gcl.enforce.contracts import run_contracts
from gcl.enforce.servers import _fault_on_operative

from .test_enforce import _by, _Fake


def _sid(messages) -> str:
    m = re.search(r"GCL-U-([io]\d{2})", messages[0]["content"])
    return m.group(1) if m else ""


def test_an_answer_written_after_the_integration_hung_up_was_not_delivered(tmp_path):
    def impatient(g, m):
        if _sid(m) != "i04":                       # i04: the input "error" fault
            return g.strict(m)
        req = urllib.request.Request(g.scanner.base_for("input") + g.protocol.path,
                                     data=json.dumps({"texts": [m[0]["content"]], "input_type": "request"}).encode())
        with contextlib.suppress(Exception):
            urllib.request.urlopen(req, timeout=0.1)  # gives up before the slow stand-in answers
        return 400, {"error": "guard unavailable"}

    fake = _Fake(tmp_path, impatient)
    fake.scanner_latency_s = 0.4
    run = run_contracts(fake, 5, settle_s=0.3)
    r = _by(run, "input", "error")
    assert r["scenario"]["id"] == "i04" and r["observed"] == "stopped"
    assert r["evidence"]["scanner_answers_undelivered"] >= 1
    assert r["policy"] == "unverified" and any("hung up" in n for n in r["notes"])
    assert _by(run, "input", "block")["policy"] == "held"   # delivered answers still count


def test_an_unlabelled_background_call_is_not_a_violation(tmp_path):
    def chatty(g, m):
        if _sid(m) == "i04":                       # a health check lands in i04's window
            g.forward([{"role": "user", "content": "ping"}])
        return g.strict(m)

    run = run_contracts(_Fake(tmp_path, chatty), 5, settle_s=0.3)
    r = _by(run, "input", "error")
    assert r["evidence"]["unlabelled_provider_calls"] == 1
    assert r["observed"] == "stopped" and r["policy"] == "unverified"


def test_background_traffic_before_the_first_scenario_is_in_the_receipt(tmp_path):
    class Noisy(_Fake):
        def start(self, model, scanner):
            super().start(model, scanner)
            self.forward([{"role": "user", "content": "warm-up"}])

    run = run_contracts(Noisy(tmp_path, lambda g, m: g.strict(m)), 5, settle_s=0.3, only={"none"})
    assert run["receipt"]["background_before_run"]["provider_calls"] == 1


def test_a_stall_records_who_ended_it(tmp_path):
    run = run_contracts(ReferenceGateway(sys.executable, tmp_path, "strict"), 15, only={"i05"})
    r = _by(run, "input", "timeout")
    stalls = [e["stall"] for e in r["evidence"]["scanner_events"] if e.get("stall")]
    assert stalls and stalls[0]["ended"] in ("integration gave up", "released by gcl") and stalls[0]["s"] > 0


def test_null_verdict_defeats_a_truthiness_parser_that_unknown_does_not():
    block, allow = {"flagged": True, "reason": "x"}, {"flagged": False}
    unknown, _ = _fault_on_operative(block, allow, "unknown_verdict")
    null, changed = _fault_on_operative(block, allow, "null_verdict")
    assert changed and null["flagged"] is None
    naive = lambda resp: "block" if resp["flagged"] else "allow"  # noqa: E731
    assert naive(unknown) == "block" and naive(null) == "allow"


def test_a_truthiness_gateway_is_caught_by_null_verdict(tmp_path):
    def truthy(g, m):
        texts = [x["content"] for x in m]
        v = g.scan("input", texts) or {}
        if v.get("action") and v.get("action") != "NONE":
            return 400, {"error": "blocked"}          # any truthy action blocks, a falsy one allows
        reply = g.forward(m)
        return 200, {"choices": [{"message": {"role": "assistant", "content": reply}}]}

    run = run_contracts(_Fake(tmp_path, truthy), 5, settle_s=0.3)
    assert _by(run, "input", "unknown_verdict")["policy"] == "held"     # absorbed by accident
    assert _by(run, "input", "null_verdict")["policy"] == "violated"    # the twin it cannot absorb


def test_a_leak_that_follows_gcl_releasing_a_stall_is_not_a_timeout_result(tmp_path):
    # The integration waits on the guard far longer than the client; once gcl lets the
    # stalled call go (the connection closes), it fails open. That is the error path, not
    # a guard that timed out: the timeout scenario must not be credited with the leak.
    def patient(g, m):
        req = urllib.request.Request(g.scanner.base_for("input") + g.protocol.path, data=json.dumps(
            {"texts": [m[0]["content"]], "input_type": "request"}).encode())
        try:
            v = json.loads(urllib.request.urlopen(req, timeout=120).read())
        except Exception:
            v = {"action": "NONE"}                       # any failure: let it through
        if v.get("action") == "BLOCKED":
            return 400, {"error": "blocked"}
        reply = g.forward(m)
        return 200, {"choices": [{"message": {"role": "assistant", "content": reply}}]}

    run = run_contracts(_Fake(tmp_path, patient), 3, settle_s=0.3, only={"i05"})
    r = _by(run, "input", "timeout")
    assert r["evidence"]["after_gcl_released_stall"] is True
    assert r["policy"] == "unverified" and any("closed connection" in n for n in r["notes"])
