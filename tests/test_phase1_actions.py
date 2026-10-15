"""Phase 1 (agent actions): the ledger's pure verdict logic, the stand-in sinks, and the
Phase-1 controls gate. No network, no subprocess -- everything here is synthetic events
and an in-process fake target. The real target (dbhub, over a real stdio subprocess) is in
test_dbhub.py, opt-in.
"""

from __future__ import annotations

import os

from gcl.enforce.actions import StdioMCPActionTarget, run_action_target
from gcl.enforce.ledger import ActionLedger, LedgerEvent, executed, judge
from gcl.enforce.mcp_client import Exchange
from gcl.enforce.sinks import FakeDBSink, FakeFileSink, FakeShell, SqliteStateObserver

# --------------------------------------------------------------------------- ledger: pure verdicts


def _event(**kw) -> LedgerEvent:
    base = dict(id="x", proposed_action={"sql": "DROP TABLE users"}, marker="GCL-M")
    base.update(kw)
    return LedgerEvent(**base)


def test_held_no_receipt_at_all():
    e = _event(approval_decision="denied")  # args_executed and receipt both default None
    assert executed(e) is False
    assert judge(e) == ("blocked", "held",
                        ["no executor receipt: the action did not run"])


def test_executed_without_approval_never_asked():
    e = _event(args_executed={"sql": "DROP TABLE users"}, approval_decision=None,
               receipt={"marker": "GCL-M", "ran": True})
    observed, policy, notes = judge(e)
    assert (observed, policy) == ("executed without approval", "violated")
    assert "no approval was ever asked" in notes[0]


def test_executed_without_approval_explicitly_denied():
    e = _event(args_executed={"sql": "DROP TABLE users"}, approval_decision="denied",
               receipt={"marker": "GCL-M"})
    observed, policy, _ = judge(e)
    assert (observed, policy) == ("executed without approval", "violated")


def test_ran_with_no_model_turn():
    e = _event(args_executed={"sql": "SELECT 1"}, approval_decision="approved",
               args_shown_to_approver={"sql": "SELECT 1"}, model_turn_occurred=False,
               receipt={"marker": "GCL-M"})
    assert judge(e) == ("ran with no model turn", "violated",
                        ["the executor ran it although no model turn ever proposed it"])


def test_swapped_args_toctou():
    e = _event(args_shown_to_approver={"sql": "SELECT 1"}, args_executed={"sql": "DROP TABLE users"},
               approval_decision="approved", receipt={"marker": "GCL-M"})
    observed, policy, notes = judge(e)
    assert (observed, policy) == ("approved args != executed args", "violated")
    assert "TOCTOU" in notes[0]


def test_executed_as_approved_holds():
    e = _event(args_shown_to_approver={"sql": "SELECT 1"}, args_executed={"sql": "SELECT 1"},
               approval_decision="approved", receipt={"marker": "GCL-M"})
    assert judge(e) == ("executed as approved", "held",
                        [("the executor's receipt matches what the approver was shown, after a model turn "
                          "proposed it")])


def test_claimed_execution_without_a_receipt_is_unverified_not_held():
    """A claim that something ran, with nothing behind it, is never read as a block."""
    e = _event(args_executed={"sql": "DROP TABLE users"}, receipt=None)
    _observed, policy, notes = judge(e)
    assert policy == "unverified"
    assert "not evidence either way" in notes[0]


def test_receipt_missing_this_events_marker_does_not_count():
    """A receipt that is really someone else's (no marker match) is not this event's proof."""
    e = _event(args_executed={"sql": "x"}, receipt={"marker": "SOMEONE-ELSE"}, marker="GCL-M")
    assert executed(e) is False
    assert judge(e)[:2] == ("blocked", "held")


def test_ledger_is_append_only_and_orders_events():
    ledger = ActionLedger()
    e1 = ledger.record(_event(id="a"))
    e2 = ledger.record(_event(id="b"))
    assert ledger.events == [e1, e2]
    dicts = ledger.to_list()
    assert [d["id"] for d in dicts] == ["a", "b"]


# --------------------------------------------------------------------------- sinks: record, never act


def test_fake_shell_records_argv_and_never_executes(tmp_path):
    import subprocess

    marker_file = tmp_path / "proof-of-real-execution"
    sh = FakeShell(tmp_path, name="sh")
    env = sh.env({"PATH": "/usr/bin:/bin"})
    assert env["PATH"].split(os.pathsep)[0] == str(sh.workdir)
    # Invoked the way a target would: by name, through PATH -- the fake shell's directory
    # is first on PATH, so this never reaches a real "rm".
    r = subprocess.run(["sh", "rm", "-rf", str(marker_file), "--no-preserve-root"], env=env)
    assert r.returncode == 0
    assert not marker_file.exists()          # nothing it was handed ever ran for real
    calls = sh.calls()
    assert len(calls) == 1
    assert calls[0]["argv"] == ["rm", "-rf", str(marker_file), "--no-preserve-root"]
    assert calls[0]["marker"] == sh.marker


def test_fake_shell_answers_to_any_name(tmp_path):
    sh = FakeShell(tmp_path, name="bash")
    assert sh.exe.name == "bash"
    assert os.access(sh.exe, os.X_OK)


def test_fake_db_sink_records_and_never_opens_a_connection(tmp_path):
    db_path = tmp_path / "should-never-exist.sqlite"
    sink = FakeDBSink()

    def naive_classifier(sql: str) -> bool:
        return sql.strip().split()[0].lower() in ("select", "pragma")

    receipt = sink.execute(f"PRAGMA user_version = 1 -- would touch {db_path}", readonly=True,
                           classify=naive_classifier)
    assert receipt["would_run"] is True          # the naive classifier is fooled, same as dbhub's
    assert receipt["classified_read_only"] is True
    assert not db_path.exists()                  # and nothing was ever opened to prove it
    assert sink.calls == [receipt]


def test_fake_db_sink_marker_is_in_every_receipt():
    sink = FakeDBSink(marker="GCL-DB-TEST")
    r = sink.execute("SELECT 1", readonly=False, classify=lambda s: True)
    assert r["marker"] == "GCL-DB-TEST"


def test_fake_file_sink_records_and_touches_nothing(tmp_path):
    target = tmp_path / "real-file.txt"
    target.write_text("do not delete me")
    sink = FakeFileSink()
    receipt = sink.op("delete", str(target))
    assert receipt == {"t": receipt["t"], "action": "delete", "path": str(target), "marker": sink.marker}
    assert target.exists() and target.read_text() == "do not delete me"


def test_sqlite_state_observer_is_read_only(tmp_path):
    import sqlite3

    db = tmp_path / "ro.sqlite"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE t (n INTEGER)")
    con.execute("INSERT INTO t VALUES (1)")
    con.commit()
    con.close()
    obs = SqliteStateObserver(db)
    assert obs.read("SELECT n FROM t") == [(1,)]
    try:
        obs.read("INSERT INTO t VALUES (2)")
        raised = False
    except sqlite3.OperationalError:
        raised = True
    assert raised, "a read-only connection must refuse a write"
    assert obs.read("SELECT n FROM t") == [(1,)]  # unchanged


# --------------------------------------------------------------------------- the controls gate


class _ScriptedTarget(StdioMCPActionTarget):
    """An in-process action target for testing `run_action_target`'s control gate: no
    subprocess, no stdio -- `probe`/`observe`/`changed`/`reply_ok` are driven entirely from
    a script the test hands in, keyed by check kind."""

    name = "scripted"

    def __init__(self, ran: dict[str, bool]):
        self.ran = ran
        self.calls: list[str] = []

    def argv(self):
        raise AssertionError("never spawned: call() is overridden for this test double")

    def env(self):
        return {}

    def probe(self, kind, marker):
        self.calls.append(kind)
        return {"jsonrpc": "2.0", "id": "x", "method": "tools/call", "params": {"kind": kind}}

    def observe(self):
        return {"n": len(self.calls)}

    def changed(self, before, after):
        return self.ran[self._last_kind()]

    def reply_ok(self, ex):
        return self.ran["approved"]

    def _last_kind(self):
        return self.calls[-1]

    def call(self, step, timeout_s):
        return Exchange(finished=True)


def test_controls_hold_and_bypass_is_judged():
    target = _ScriptedTarget({"approved": True, "denied": False, "bypass": True})
    run = run_action_target(target, timeout_s=1.0)
    by_id = {r["scenario"]["id"]: r for r in run["results"]}
    assert by_id["k00a"]["policy"] == "held"
    assert by_id["k00d"]["policy"] == "held"
    assert by_id["k01"]["policy"] == "violated"
    assert by_id["k01"]["observed"] == "executed without approval"
    assert run["summary"] == {"checks": 3, "held": 2, "violated": 1, "unverified": 0,
                              "scenarios": 3, "policy_held": 2, "policy_violated": 1,
                              "documented_deviates": 0, "documented_unspecified_violations": 1}


def test_broken_approved_control_makes_the_replay_unverified():
    """The approved/benign action never runs: the harness itself is broken, so the bypass
    check must not be trusted either way."""
    target = _ScriptedTarget({"approved": False, "denied": False, "bypass": True})
    run = run_action_target(target, timeout_s=1.0)
    by_id = {r["scenario"]["id"]: r for r in run["results"]}
    assert by_id["k00a"]["policy"] == "unverified"
    assert by_id["k01"]["policy"] == "unverified"
    assert by_id["k01"]["observed"] == "not run"
    assert "did not run" in by_id["k01"]["notes"][0] and "not evidence" in by_id["k01"]["notes"][0]
    assert target.calls == ["approved", "denied"]  # the bypass probe was never even sent


def test_broken_denied_control_also_makes_the_replay_unverified():
    """The gate is not live at all (even an obvious write got through): nothing past this
    is evidence, including a clean-looking bypass result."""
    target = _ScriptedTarget({"approved": True, "denied": True, "bypass": False})
    run = run_action_target(target, timeout_s=1.0)
    by_id = {r["scenario"]["id"]: r for r in run["results"]}
    assert by_id["k00d"]["policy"] == "unverified"
    assert by_id["k00d"]["observed"] == "executed without approval"
    assert by_id["k01"]["policy"] == "unverified"
    assert "the gate is not live" in by_id["k01"]["notes"][0]


def test_clean_target_holds_everywhere():
    target = _ScriptedTarget({"approved": True, "denied": False, "bypass": False})
    run = run_action_target(target, timeout_s=1.0)
    assert run["summary"]["held"] == 3
    assert run["summary"]["violated"] == 0
    assert run["summary"]["unverified"] == 0


def test_run_carries_an_integration_shaped_receipt_for_findings_and_sarif():
    """`gcl findings add` and `report.sarif.enforce_sarif` key off run["integration"] and
    run["receipt"]; an actions run must look like an ordinary enforce run to them."""
    target = _ScriptedTarget({"approved": True, "denied": False, "bypass": True})
    run = run_action_target(target, timeout_s=1.0)
    assert run["integration"]["integration"] == "scripted"
    assert run["receipt"]["run_id"]
    assert run["receipt"]["gcl"]["source_sha256"]
    assert run["receipt"]["problems"] == []
