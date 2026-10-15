"""`gcl breach postgres` (step 3): crystaldba/postgres-mcp's `--access-mode=restricted` behind the
step-1 Target/Observer interfaces. Unit tests (no Postgres, no subprocess) always run; the opt-in
tests drive a real, installed postgres-mcp against a THROWAWAY Postgres the caller started:

  GCL_INTEG_PGMCP_BIN     the postgres-mcp executable (own venv; pin mcp<2 -- 0.3.0 breaks on mcp 2.x)
  GCL_INTEG_PGMCP_PSQL    the psql binary
  GCL_INTEG_PGMCP_PORT    the throwaway server's (non-standard) port, listening on 127.0.0.1
  GCL_INTEG_PGMCP_DB      the one throwaway database
  GCL_INTEG_PGMCP_USER    role (default "gcl")

Benign marker only: every real round writes one harmless derived integer into `gcl_marker`.
"""

from __future__ import annotations

import os

import pytest

from gcl.enforce.breach.postgres_breach import (
    CALL_ID,
    G8_STATEMENT,
    PROBE_FORMS,
    KillMidStepTarget,
    PgBreachTarget,
    PgStateObserver,
    TimeoutTarget,
    config_cell_target,
    config_scenario,
    marker_value,
    probe_sql,
)
from gcl.enforce.breach.runner import run_paired_trial

BIN = os.environ.get("GCL_INTEG_PGMCP_BIN")
PSQL = os.environ.get("GCL_INTEG_PGMCP_PSQL")
PORT = os.environ.get("GCL_INTEG_PGMCP_PORT")
DB = os.environ.get("GCL_INTEG_PGMCP_DB")
USER = os.environ.get("GCL_INTEG_PGMCP_USER", "gcl")
live = pytest.mark.skipif(not (BIN and PSQL and PORT and DB), reason="set GCL_INTEG_PGMCP_BIN/_PSQL/_PORT/_DB "
                          "to a real postgres-mcp, psql and a throwaway Postgres database")


def _dsn(db=None):
    return {"host": "127.0.0.1", "port": int(PORT), "user": USER, "dbname": db or DB}


FAKE = {"host": "127.0.0.1", "port": 1, "user": "u", "dbname": "d"}

# --------------------------------------------------------------------------- unit


def test_scenarios_are_labelled_config_and_distinct_per_form():
    ids = {config_scenario(f).id for f in PROBE_FORMS}
    assert len(ids) == len(PROBE_FORMS)
    for f in PROBE_FORMS:
        s = config_scenario(f)
        assert s.calibration_kind == "config"
        assert s.protection_variable == "access_mode"
        assert f in s.forbidden_effect
        assert "gcl's own read-only psql connection" in s.terminal_event


def test_unknown_form_is_refused():
    with pytest.raises(ValueError):
        config_scenario("drop_everything")
    with pytest.raises(ValueError):
        probe_sql("nope", 1)


def test_g8_statement_says_n_a_and_why():
    assert "N/A" in G8_STATEMENT and "engine-level" in G8_STATEMENT


def test_marker_value_is_deterministic_and_avoids_reserved_values():
    assert marker_value("GCL-BRE-x-r1") == marker_value("GCL-BRE-x-r1")
    vals = {marker_value(f"GCL-BRE-x-r{i}") for i in range(20)}
    assert len(vals) > 1
    assert all(10_000 <= v <= 99_999 for v in vals)  # never the seed row (7) or the nudge (1)


@pytest.mark.parametrize("form", PROBE_FORMS)
def test_probe_sql_writes_only_the_derived_value(form):
    sql = probe_sql(form, 54321)
    assert "54321" in sql
    low = sql.lower()
    for forbidden in ("drop ", "delete ", "truncate ", "update ", "alter ", "copy ", "program"):
        assert forbidden not in low
    assert "gcl_" in low  # only ever gcl's own throwaway marker objects


def test_probe_forms_cover_the_known_slip_past_spellings():
    assert "WITH x AS (INSERT" in probe_sql("writable_cte", 1)
    assert probe_sql("function_write", 1).startswith("SELECT gcl_write_marker(")
    assert "INTO gcl_marker_into" in probe_sql("select_into", 1)
    assert probe_sql("commit_escape", 1).startswith("COMMIT;")
    assert probe_sql("set_rw_escape", 1).startswith("SET TRANSACTION READ WRITE;")


def test_manifest_differs_only_in_access_mode():
    t = PgBreachTarget("/x/postgres-mcp", "/x/psql", FAKE, "writable_cte")
    t.protection = False
    off = t.manifest()
    t.protection = True
    on = t.manifest()
    assert off["access_mode"] == "unrestricted" and on["access_mode"] == "restricted"
    assert {k for k in off if off[k] != on[k]} == {"access_mode"}
    assert t.calibration_kind == "config"
    assert "--access-mode=restricted" in t.argv()


def test_relay_binds_the_step_to_the_marker_and_sql_carries_the_derived_value():
    t = PgBreachTarget("/x/postgres-mcp", "/x/psql", FAKE, "writable_cte")
    t.protection = True
    sc = config_scenario("writable_cte")
    rt, sql = t._relay(sc, "r1")
    value = marker_value(sc.marker("r1"))
    assert rt.bound_ok and rt.marker_seen
    assert sql == probe_sql("writable_cte", value)
    assert t.last_expected_value == value


def test_observer_saw_effect_requires_the_exact_value_in_either_table():
    t = PgBreachTarget("/x/postgres-mcp", "/x/psql", FAKE)
    t.last_expected_value = 54321
    obs = PgStateObserver("/x/psql", FAKE, t)
    sc = config_scenario()
    base = {"marker_values": [7], "into_values": []}
    assert not obs.saw_effect(base, base, sc)
    assert not obs.saw_effect(base, {"marker_values": [7, 11111], "into_values": []}, sc)
    assert obs.saw_effect(base, {"marker_values": [7, 54321], "into_values": []}, sc)
    assert obs.saw_effect(base, {"marker_values": [7], "into_values": [54321]}, sc)
    assert not obs.saw_effect({"marker_values": [54321], "into_values": []},
                              {"marker_values": [54321], "into_values": []}, sc)  # stale, not new


def test_call_id_is_distinct_from_dbhubs():
    from gcl.enforce.breach.dbhub_breach import CALL_ID as DBHUB

    assert CALL_ID != DBHUB


# --------------------------------------------------------------------------- opt-in: CONFIG cell per form


@live
@pytest.mark.parametrize("form", PROBE_FORMS)
def test_config_cell_per_form_off_commits_and_on_contains(form):
    target = config_cell_target(BIN, PSQL, _dsn(), form)
    obs = PgStateObserver(PSQL, _dsn(), target)
    report = run_paired_trial(config_scenario(form), target, [obs], repeats=3)
    t = report["trial"]
    assert t["cell"] == "calibrated+held", (form, t, report["results"])
    assert t["policy"] == "held" and t["stable"] is True
    verdict = next(r for r in report["results"] if r["scenario"]["id"] == config_scenario(form).id)
    rep = verdict["evidence"]["repeats"][0]
    assert rep["off"]["effect_observed"] is True   # unrestricted commits the marker: calibrated escape
    assert rep["on"]["effect_observed"] is False   # restricted contains it


# --------------------------------------------------------------------------- opt-in: faults


@live
def test_killed_mid_step_is_unverified_never_a_false_held():
    target = KillMidStepTarget(BIN, PSQL, _dsn(), "writable_cte")
    report = run_paired_trial(config_scenario("writable_cte"), target, [PgStateObserver(PSQL, _dsn(), target)],
                              repeats=1)
    assert report["trial"]["policy"] == "unverified", (report["trial"], report["results"])


@live
def test_timeout_is_unverified_never_a_false_held():
    target = TimeoutTarget(BIN, PSQL, _dsn(), "writable_cte", timeout_override_s=0.02)
    report = run_paired_trial(config_scenario("writable_cte"), target, [PgStateObserver(PSQL, _dsn(), target)],
                              repeats=1)
    assert report["trial"]["policy"] == "unverified", (report["trial"], report["results"])


@live
def test_dead_observer_is_unverified_never_a_false_held():
    """The observer reads `postgres` (never written by the target, and without gcl_marker): the
    k00l nudge cannot be seen, so nothing may be executed."""
    target = config_cell_target(BIN, PSQL, _dsn(), "writable_cte")
    dead = PgStateObserver(PSQL, _dsn("postgres"), target)
    report = run_paired_trial(config_scenario("writable_cte"), target, [dead], repeats=1)
    t = report["trial"]
    assert t["policy"] == "unverified" and t["gate"] == "k00l", (t, report["results"])
