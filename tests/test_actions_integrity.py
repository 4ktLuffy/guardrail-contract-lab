"""Proof-integrity gate of `gcl actions`: "blocked"/held is never reported without proof.

The bug these tests pin (negative controls -- each one fails on the pre-fix code, see the
"pre-fix" notes): a denied/bypass probe was judged only by "did the observed state change?",
so a target that CRASHED, TIMED OUT or never ran the probe left the state unchanged and was
reported "blocked"/held -- a false green. And the observer itself was never shown to work, so
a dead observer ("no change" about everything) made every control look perfect, while the
approved control trusted the target's own reply.

Everything here is an in-process fake over a real mutable state: no network, no subprocess.
Benign markers only (a list of strings and one integer flag).
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from gcl.enforce.actions import LIVENESS_KINDS, StdioMCPActionTarget, run_action_target
from gcl.enforce.dbhub_target import DbhubTarget, seed_db
from gcl.enforce.mcp_client import Exchange

CALL_ID = "c"


def _reply(ex: Exchange, **result) -> Exchange:
    ex.add("recv", {"jsonrpc": "2.0", "id": CALL_ID, "result": result}, "stdio")
    return ex


class StateTarget(StdioMCPActionTarget):
    """A fake target over a real piece of mutable state (`rows`, `flag`), so that "the observer
    saw a change" is a fact about that state and not a scripted boolean.

    denied / bypass behaviour: "block" (refuse, state untouched), "leak" (really change the
    state), "crash" (call() raises), "timeout" (errored, unfinished exchange), "unfinished"
    (no error text, but no answer), "errored" (answered but with a transport error recorded),
    "lie" (reply claims success, state untouched), "leak_then_crash" (the write lands, then
    the target dies). approved: "ok", "lying" (reply invents rows the store does not hold),
    "crash". observer: "live", "dead" (a reader that always returns the starting snapshot),
    "raises", "blind_bypass" (alive for rows, blind to the flag the bypass probe moves)."""

    name = "state"

    def __init__(self, denied="block", bypass="block", approved="ok", observer="live", refusal_hook=True,
                 sloppy_nudge=False):
        self.rows = ["benign"]
        self.flag = 0
        self.mode = {"denied": denied, "bypass": bypass, "approved": approved}
        self.observer = observer
        self.refusal_hook = refusal_hook
        self.sloppy_nudge = sloppy_nudge
        self.probes: list[str] = []

    # -- gcl-facing surface
    def argv(self):
        raise AssertionError("never spawned: call() is overridden")

    def env(self):
        return {}

    def probe(self, kind, marker):
        self.probes.append(kind)
        return {"jsonrpc": "2.0", "id": CALL_ID, "method": "tools/call", "params": {"kind": kind, "marker": marker}}

    def observe(self):
        if self.observer == "raises":
            raise OSError("observer: database is locked")
        if self.observer == "dead":
            return {"rows": ["benign"], "flag": 0}
        snap = {"rows": list(self.rows), "flag": self.flag}
        if self.observer == "blind_bypass":
            snap["flag"] = 0
        return snap

    def liveness_nudge(self, kind, marker):
        if kind == "denied":
            self.rows.append(marker)
            return (lambda: None) if self.sloppy_nudge else (lambda: self.rows.remove(marker))
        self.flag = 7
        return (lambda: None) if self.sloppy_nudge else (lambda: setattr(self, "flag", 0))

    def reply_ok(self, ex):
        r = ex.response_to(CALL_ID)
        return bool(r and r["result"].get("ok"))

    def confirm_approved(self, ex, before, after):
        r = ex.response_to(CALL_ID)
        return before == after and bool(r) and r["result"].get("rows") == [x for x in self.observe()["rows"]
                                                                          if x == "benign"]

    def reply_refused(self, ex):
        if not self.refusal_hook:
            return None
        r = ex.response_to(CALL_ID)
        return None if not r else bool(r["result"].get("refused"))

    # -- the target under test
    def call(self, step, timeout_s):
        kind = step["params"]["kind"]
        mode = self.mode[kind]
        ex = Exchange(finished=True)
        if mode == "crash":
            raise RuntimeError("target process died")
        if mode == "timeout":
            return Exchange(error=f"timed out after {timeout_s}s", finished=False)
        if mode == "unfinished":
            return Exchange(finished=False)
        if mode == "errored":
            ex.error = "BrokenPipeError: transport closed"
            return ex
        if kind == "approved":
            rows = ["benign"] if mode == "ok" else ["made-up row"]
            return _reply(ex, ok=True, rows=rows)
        if mode in ("leak", "leak_then_crash"):
            if kind == "denied":
                self.rows.append(step["params"]["marker"])
            else:
                self.flag = 61788
            if mode == "leak_then_crash":
                return Exchange(error="target died after the write", finished=False)
            return _reply(ex, ok=True, refused=False)
        if mode == "lie":
            return _reply(ex, ok=True, refused=False)
        return _reply(ex, ok=False, refused=True)


def _run(target) -> dict[str, dict]:
    run = run_action_target(target, timeout_s=1.0, run_id="t")
    return {r["scenario"]["id"]: r for r in run["results"]}


def _all_unverified(by_id) -> bool:
    return all(r["policy"] == "unverified" for r in by_id.values())


# ------------------------------------------------------------- the positives still work


def test_genuine_block_is_held():
    """A completed, error-free run, a live observer that sees no change, and a proper
    refusal: held / blocked -- the one thing "held" is allowed to mean."""
    t = StateTarget()
    by_id = _run(t)
    assert {k: v["policy"] for k, v in by_id.items()} == {"k00l": "held", "k00a": "held", "k00d": "held",
                                                          "k01": "held"}
    assert by_id["k01"]["observed"] == "blocked"
    assert by_id["k01"]["evidence"]["exchange_finished"] is True
    assert by_id["k01"]["evidence"]["observer_read"] is True
    assert t.flag == 0 and t.rows == ["benign"]          # the nudge was put back exactly


def test_genuine_bypass_is_violated():
    """A positive observation (the state really changed) is still a violation."""
    t = StateTarget(bypass="leak")
    by_id = _run(t)
    assert by_id["k01"]["policy"] == "violated"
    assert by_id["k01"]["observed"] == "executed without approval"
    assert by_id["k00l"]["policy"] == by_id["k00a"]["policy"] == by_id["k00d"]["policy"] == "held"
    assert t.flag == 61788


def test_a_leak_that_landed_before_the_target_died_is_still_a_leak():
    """Positive evidence stands whatever else went wrong with the run."""
    by_id = _run(StateTarget(bypass="leak_then_crash"))
    assert by_id["k01"]["policy"] == "violated"


# ------------------------------------------------------------- crashed / incomplete runs


@pytest.mark.parametrize("mode", ["crash", "timeout", "unfinished", "errored"])
def test_incomplete_bypass_run_is_unverified_never_held(mode):
    """Pre-fix: the state was unchanged, so ran=False, so "blocked", so HELD."""
    t = StateTarget(bypass=mode)
    by_id = _run(t)
    k01 = by_id["k01"]
    assert k01["policy"] == "unverified", k01
    assert k01["observed"] == "run incomplete"
    assert k01["observed"] != "blocked"
    assert "nothing was shown to be blocked" in k01["notes"][0]
    assert k01["evidence"]["ran"] is None


@pytest.mark.parametrize("mode", ["crash", "timeout", "unfinished", "errored"])
def test_incomplete_denied_control_is_unverified_and_poisons_the_replay(mode):
    """The denied control that never completed cannot prove the gate is live, so the replay
    that follows it is unverified even though that probe itself blocked cleanly."""
    by_id = _run(StateTarget(denied=mode))
    assert by_id["k00d"]["policy"] == "unverified"
    assert by_id["k00d"]["observed"] == "run incomplete"
    assert by_id["k01"]["policy"] == "unverified"
    assert by_id["k01"]["observed"] != "blocked"
    assert "could not be judged" in by_id["k01"]["notes"][0]


def test_every_probe_crashing_yields_no_held_result_past_the_liveness_control():
    """A target that is dead on arrival: only gcl's own k00l (which never involves the
    target) holds. Pre-fix this exact run read k00d held / k01 held."""
    by_id = _run(StateTarget(approved="crash", denied="crash", bypass="crash"))
    assert by_id["k00l"]["policy"] == "held"
    assert [by_id[k]["policy"] for k in ("k00a", "k00d", "k01")] == ["unverified"] * 3
    assert not [r for r in by_id.values() if r["observed"] == "blocked"]


def test_reply_that_claims_success_while_the_observer_saw_nothing_is_not_blocked():
    """Two witnesses disagree: not held. (Pre-fix: held.)"""
    by_id = _run(StateTarget(bypass="lie"))
    assert by_id["k01"]["policy"] == "unverified"
    assert by_id["k01"]["observed"] == "contradicted"


def test_a_target_that_cannot_tell_a_refusal_is_judged_on_run_and_observer_alone():
    """reply_refused() -> None means "no opinion": a completed run with a live, quiet observer
    still holds (the hook only adds support where a target can give it)."""
    by_id = _run(StateTarget(refusal_hook=False))
    assert by_id["k01"]["policy"] == "held"


# ------------------------------------------------------------- the observer-liveness control


def test_dead_observer_makes_everything_unverified_and_sends_no_probe():
    """An observer that always says "no change" is exactly what lets a leaking target read as
    blocked. The liveness control fails, so nothing else is evidence, and the probes are not
    even sent."""
    t = StateTarget(observer="dead", bypass="leak")      # the target really leaks; nobody can see it
    by_id = _run(t)
    assert by_id["k00l"]["policy"] == "unverified"
    assert by_id["k00l"]["observed"] == "no change seen"
    assert "dead or blind observer" in by_id["k00l"]["notes"][0]
    assert _all_unverified(by_id)
    assert not any(r["observed"] == "blocked" for r in by_id.values())
    assert t.probes == []


def test_dead_observer_with_a_genuinely_blocking_target_is_still_unverified():
    """Even when the "blocked" would have been true, an unproven observer cannot say so."""
    by_id = _run(StateTarget(observer="dead"))
    assert _all_unverified(by_id)


def test_observer_blind_to_just_the_bypass_surface_is_caught():
    """Alive for the rows the denied probe moves, blind to the flag the bypass probe moves:
    a single global "the observer works" check would pass this; the per-surface one does not."""
    t = StateTarget(observer="blind_bypass", bypass="leak")
    by_id = _run(t)
    assert by_id["k00l"]["policy"] == "unverified"
    assert by_id["k00l"]["evidence"]["surfaces"] == {"denied": True, "bypass": False}
    assert _all_unverified(by_id)


def test_observer_that_raises_is_not_read_as_no_change():
    by_id = _run(StateTarget(observer="raises"))
    assert _all_unverified(by_id)
    assert by_id["k00l"]["observed"] == "not run"
    assert "observer not read" in by_id["k00l"]["notes"][0]


def test_observer_that_dies_mid_run_is_unverified_not_blocked():
    """Alive for the liveness control, then unreadable around a probe."""
    t = StateTarget()
    real = t.observe
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] > 3 * len(LIVENESS_KINDS):     # past the liveness reads (3 per surface), mid-probes
            raise OSError("gone")
        return real()

    t.observe = flaky
    by_id = _run(t)
    assert by_id["k00l"]["policy"] == "held"
    assert by_id["k00a"]["policy"] == "unverified"
    assert by_id["k00a"]["observed"] == "observer not read"
    assert by_id["k01"]["policy"] == "unverified"
    assert not any(r["observed"] == "blocked" for r in by_id.values())


def test_a_nudge_that_is_not_put_back_is_unverified():
    by_id = _run(StateTarget(sloppy_nudge=True))
    assert by_id["k00l"]["policy"] == "unverified"
    assert any("did not return" in n for n in by_id["k00l"]["notes"])
    assert _all_unverified(by_id)


def test_a_target_without_a_liveness_nudge_is_unverified_not_trusted():
    """The default is fail-closed: an observer nobody has shown to work is not trusted."""
    class NoNudge(StateTarget):
        liveness_nudge = StdioMCPActionTarget.liveness_nudge

    by_id = _run(NoNudge())
    assert _all_unverified(by_id)
    assert "defines no liveness nudge" in by_id["k00l"]["notes"][0]


# ------------------------------------------------------------- the approved control


def test_approved_control_the_observer_cannot_confirm_is_unverified():
    """The target's reply says the benign read worked; the store does not hold those rows.
    Pre-fix: reply_ok alone passed the control."""
    by_id = _run(StateTarget(approved="lying"))
    assert by_id["k00a"]["policy"] == "unverified"
    assert by_id["k00a"]["observed"] == "not run"
    assert by_id["k01"]["policy"] == "unverified"
    assert "did not run" in by_id["k01"]["notes"][0]


def test_approved_control_with_no_independent_confirmation_is_unverified():
    class ReplyOnly(StateTarget):
        confirm_approved = StdioMCPActionTarget.confirm_approved

    by_id = _run(ReplyOnly())
    assert by_id["k00a"]["policy"] == "unverified"
    assert "confirm_approved" in by_id["k00a"]["notes"][0]
    assert by_id["k01"]["policy"] == "unverified"


def test_approved_control_needs_a_completed_exchange():
    by_id = _run(StateTarget(approved="timeout"))
    assert by_id["k00a"]["policy"] == "unverified"
    assert by_id["k00a"]["observed"] == "run incomplete"
    assert by_id["k01"]["policy"] == "unverified"


# ------------------------------------------------------------- the dbhub target, no node needed


class _FakeDbhub(DbhubTarget):
    """The real DbhubTarget (real sqlite observer, real nudge, real reply parsing) with the
    node subprocess swapped for an in-process stand-in that either really executes the PRAGMA
    (a vulnerable build), refuses (a fixed one) or dies."""

    def __init__(self, tmp_path, behaviour):
        db = tmp_path / "d.sqlite"
        seed_db(db)
        super().__init__("node", tmp_path, db, tmp_path)
        self.behaviour = behaviour

    def call(self, step, timeout_s):
        sql = step["params"]["arguments"]["sql"]
        ex = Exchange(finished=True)
        if self.behaviour == "crash":
            raise RuntimeError("node exited")
        if self.behaviour == "timeout":
            return Exchange(error="timed out", finished=False)

        def reply(doc, is_error=False):
            res = {"content": [{"type": "text", "text": json.dumps(doc)}]}
            if is_error:
                res["isError"] = True
            return ex.add("recv", {"jsonrpc": "2.0", "id": self.CALL_ID, "result": res}, "stdio") or ex

        if sql.startswith("SELECT"):
            con = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
            rows = [{"note": n} for (n,) in con.execute("SELECT note FROM gcl_marker WHERE note='benign'")]
            con.close()
            return reply({"success": True, "data": {"rows": rows, "count": len(rows)}})
        if self.behaviour == "vulnerable" and sql.startswith("PRAGMA user_version"):
            con = sqlite3.connect(self.db_path)
            con.execute(sql)
            con.commit()
            con.close()
            return reply({"success": True, "data": {"rows": [], "count": 0}})
        return reply({"success": False, "error": "Read-only mode is enabled", "code": "READONLY_VIOLATION"}, True)


def test_dbhub_target_fixed_build_is_held_and_the_file_is_left_as_seeded(tmp_path):
    t = _FakeDbhub(tmp_path, "fixed")
    before = t.observe()
    by_id = _run(t)
    assert {k: v["policy"] for k, v in by_id.items()} == {"k00l": "held", "k00a": "held", "k00d": "held",
                                                          "k01": "held"}
    assert t.observe() == before          # liveness nudges were undone; nothing else moved


def test_dbhub_target_vulnerable_build_is_violated(tmp_path):
    by_id = _run(_FakeDbhub(tmp_path, "vulnerable"))
    assert by_id["k01"]["policy"] == "violated"
    assert by_id["k00l"]["policy"] == "held"


@pytest.mark.parametrize("behaviour", ["crash", "timeout"])
def test_dbhub_target_that_dies_is_unverified_not_blocked(tmp_path, behaviour):
    by_id = _run(_FakeDbhub(tmp_path, behaviour))
    assert _all_unverified({k: v for k, v in by_id.items() if k != "k00l"})
    assert not any(r["observed"] == "blocked" for r in by_id.values())


def test_dbhub_liveness_nudge_changes_and_restores_each_surface(tmp_path):
    t = _FakeDbhub(tmp_path, "fixed")
    base = t.observe()
    for kind in ("denied", "bypass"):
        undo = t.liveness_nudge(kind, f"GCL-X-{kind}")
        assert t.changed(base, t.observe()) is True
        undo()
        assert t.observe() == base
    with pytest.raises(ValueError):
        t.liveness_nudge("approved", "m")


def test_dbhub_confirm_approved_checks_the_store_not_just_the_reply(tmp_path):
    t = _FakeDbhub(tmp_path, "fixed")
    snap = t.observe()
    honest = t.call(t.probe("approved", "m"), 1.0)
    assert t.confirm_approved(honest, snap, snap) is True

    liar = Exchange(finished=True)
    doc = {"success": True, "data": {"rows": [{"note": "benign"}, {"note": "invented"}], "count": 2}}
    liar.add("recv", {"jsonrpc": "2.0", "id": t.CALL_ID,
                      "result": {"content": [{"type": "text", "text": json.dumps(doc)}]}}, "stdio")
    assert t.reply_ok(liar) is True                         # the reply alone would have passed it
    assert t.confirm_approved(liar, snap, snap) is False    # the store does not hold those rows
    assert t.confirm_approved(honest, snap, {**snap, "user_version": 5}) is False   # a read moved state


def test_dbhub_reply_refused_reads_the_tool_result():
    t = DbhubTarget.__new__(DbhubTarget)

    def ex_with(res=None, err=None):
        ex = Exchange()
        msg = {"jsonrpc": "2.0", "id": "gcl-call"}
        msg.update({"result": res} if res is not None else {"error": err})
        ex.add("recv", msg, "stdio")
        return ex

    text = lambda d: {"content": [{"type": "text", "text": json.dumps(d)}]}   # noqa: E731
    assert t.reply_refused(Exchange()) is None
    assert t.reply_refused(ex_with(err={"code": -32000, "message": "no"})) is True
    assert t.reply_refused(ex_with({**text({"success": False}), "isError": True})) is True
    assert t.reply_refused(ex_with(text({"success": True, "data": {}}))) is False
    assert t.reply_refused(ex_with({"content": [{"type": "text", "text": "not json"}]})) is None
