"""dbhub (CVE-2026-61788 / GHSA-mwwr-p57h-56pf): unit tests (no network, no subprocess) plus
an opt-in known-CVE replay against two real, installed versions of @bytebase/dbhub.

The opt-in tests need a real install of each version, following the GCL_INTEG_* pattern of
test_mcp_real_adapters.py / test_toolhive.py:

  GCL_INTEG_DBHUB_VULNERABLE   install dir for @bytebase/dbhub <= 0.22.5 (npm pack/install
                               into a local dir; dist/index.js and node_modules present)
  GCL_INTEG_DBHUB_FIXED        install dir for @bytebase/dbhub >= 0.22.6
  GCL_INTEG_DBHUB_NODE         the node binary to run them with (default "node"; needs
                               node:sqlite, i.e. Node >= 22.5)

Both are needed for the replay test; either alone runs the single-version smoke test.
"""

from __future__ import annotations

import json
import os
import sqlite3

import pytest

from gcl.enforce.actions import run_action_target
from gcl.enforce.dbhub_target import DbhubTarget, _tool_text, seed_db, write_config
from gcl.enforce.mcp_client import Exchange

VULN = os.environ.get("GCL_INTEG_DBHUB_VULNERABLE")
FIXED = os.environ.get("GCL_INTEG_DBHUB_FIXED")
NODE = os.environ.get("GCL_INTEG_DBHUB_NODE", "node")

# --------------------------------------------------------------------------- unit tests


def test_write_config_uses_three_slash_sqlite_dsn(tmp_path):
    db = tmp_path / "a" / "b.sqlite"
    cfg = write_config(tmp_path, db)
    text = cfg.read_text()
    assert f'dsn = "sqlite://{db.resolve()}"' in text
    assert 'readonly = true' in text
    assert cfg.name == "dbhub.toml"


def test_seed_db_creates_marker_table_and_resets_user_version(tmp_path):
    db = tmp_path / "t.sqlite"
    seed_db(db)
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    assert con.execute("SELECT note FROM gcl_marker").fetchall() == [("benign",)]
    assert con.execute("PRAGMA user_version").fetchone() == (0,)
    con.close()


def test_seed_db_is_idempotent_and_resets_a_dirty_user_version(tmp_path):
    """A repeat run against the same throwaway file must not read a previous run's leftover
    user_version as "no write happened": seeding always resets it."""
    db = tmp_path / "t.sqlite"
    seed_db(db)
    con = sqlite3.connect(db)
    con.execute("PRAGMA user_version = 999")
    con.execute("INSERT INTO gcl_marker (note) VALUES ('leftover')")
    con.commit()
    con.close()
    seed_db(db)
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    assert con.execute("PRAGMA user_version").fetchone() == (0,)
    assert con.execute("SELECT note FROM gcl_marker ORDER BY id").fetchall() == [("benign",), ("leftover",)]
    con.close()


def test_sql_for_each_check_kind(tmp_path):
    seed_db(tmp_path / "d.sqlite")
    t = DbhubTarget(NODE, tmp_path, tmp_path / "d.sqlite", tmp_path)
    assert t._sql_for("approved", "m") == "SELECT note FROM gcl_marker WHERE note = 'benign'"
    assert t._sql_for("denied", "GCL-X") == "INSERT INTO gcl_marker (note) VALUES ('GCL-X')"
    assert "PRAGMA user_version = " in t._sql_for("bypass", "m")
    with pytest.raises(ValueError):
        t._sql_for("nonsense", "m")


def test_observe_reads_marker_rows_and_user_version(tmp_path):
    db = tmp_path / "d.sqlite"
    seed_db(db)
    t = DbhubTarget(NODE, tmp_path, db, tmp_path)
    before = t.observe()
    assert before == {"marker_rows": [(1, "benign")], "user_version": 0}
    con = sqlite3.connect(db)
    con.execute("PRAGMA user_version = 7")
    con.commit()
    con.close()
    after = t.observe()
    assert after["user_version"] == 7
    assert t.changed(before, after) is True


def test_reply_ok_reads_the_tool_result_not_the_http_status():
    t = DbhubTarget.__new__(DbhubTarget)  # no real db/process needed for this one
    ok_doc = {"success": True, "data": {"rows": [{"note": "benign"}], "count": 1}}
    ex = Exchange()
    ex.add("recv", {"jsonrpc": "2.0", "id": "gcl-call",
                    "result": {"content": [{"type": "text", "text": json.dumps(ok_doc)}]}}, "stdio")
    assert t.reply_ok(ex) is True

    bad_doc = {"success": True, "data": {"rows": [], "count": 0}}  # no benign row: not proof it ran right
    ex2 = Exchange()
    ex2.add("recv", {"jsonrpc": "2.0", "id": "gcl-call",
                     "result": {"content": [{"type": "text", "text": json.dumps(bad_doc)}]}}, "stdio")
    assert t.reply_ok(ex2) is False

    ex3 = Exchange()  # no response at all
    assert t.reply_ok(ex3) is False


def test_tool_text_ignores_other_request_ids():
    ex = Exchange()
    ex.add("recv", {"jsonrpc": "2.0", "id": "other",
                    "result": {"content": [{"type": "text", "text": "{}"}]}}, "stdio")
    assert _tool_text(ex, "gcl-call") is None


# --------------------------------------------------------------------------- opt-in: real dbhub

needs_one = pytest.mark.skipif(not (VULN or FIXED), reason="set GCL_INTEG_DBHUB_VULNERABLE or "
                               "GCL_INTEG_DBHUB_FIXED to a real @bytebase/dbhub install dir")
needs_both = pytest.mark.skipif(not (VULN and FIXED), reason="set both GCL_INTEG_DBHUB_VULNERABLE "
                                "and GCL_INTEG_DBHUB_FIXED for the known-CVE replay")


@needs_one
def test_harness_drives_a_real_dbhub_at_all(tmp_path):
    """Smoke test on whichever install is configured: the controls hold, whatever the
    bypass verdict turns out to be."""
    install = VULN or FIXED
    db = tmp_path / "smoke.sqlite"
    seed_db(db)
    target = DbhubTarget(NODE, install, db, tmp_path)
    run = run_action_target(target, timeout_s=30.0)
    by_id = {r["scenario"]["id"]: r for r in run["results"]}
    assert by_id["k00a"]["policy"] == "held", by_id["k00a"]["notes"]
    assert by_id["k00d"]["policy"] == "held", by_id["k00d"]["notes"]
    assert by_id["k01"]["policy"] in ("held", "violated")  # never unverified once the controls hold


@needs_both
def test_known_cve_replay_red_on_vulnerable_green_on_fixed(tmp_path):
    vuln_db, fixed_db = tmp_path / "vuln.sqlite", tmp_path / "fixed.sqlite"
    seed_db(vuln_db)
    seed_db(fixed_db)

    vuln_run = run_action_target(DbhubTarget(NODE, VULN, vuln_db, tmp_path / "vuln"), timeout_s=30.0)
    fixed_run = run_action_target(DbhubTarget(NODE, FIXED, fixed_db, tmp_path / "fixed"), timeout_s=30.0)

    def k01(run):
        return next(r for r in run["results"] if r["scenario"]["id"] == "k01")

    vuln_r, fixed_r = k01(vuln_run), k01(fixed_run)
    assert vuln_r["policy"] == "violated", vuln_r["notes"]
    assert vuln_r["observed"] == "executed without approval"
    assert fixed_r["policy"] == "held", fixed_r["notes"]
    assert fixed_r["observed"] == "blocked"

    # The real, independent proof: gcl's own read-only connection to each throwaway file,
    # opened fresh here (not the one the targets used), says the write committed on the
    # vulnerable build and did not on the fixed one.
    con = sqlite3.connect(f"file:{vuln_db}?mode=ro", uri=True)
    assert con.execute("PRAGMA user_version").fetchone()[0] != 0
    con.close()
    con = sqlite3.connect(f"file:{fixed_db}?mode=ro", uri=True)
    assert con.execute("PRAGMA user_version").fetchone() == (0,)
    con.close()
