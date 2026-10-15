"""`gcl breach dbhub` (step 3): the real `@bytebase/dbhub` behind the step-1 Target/Observer
interfaces. Unit tests (no network, no subprocess, no node) always run; the opt-in tests drive a
real, installed dbhub and need the SAME env vars as `test_dbhub.py`:

  GCL_INTEG_DBHUB_FIXED        install dir for @bytebase/dbhub >= 0.22.6 (readonly's real fix)
  GCL_INTEG_DBHUB_VULNERABLE   install dir for @bytebase/dbhub <= 0.22.5 (CVE-2026-61788)
  GCL_INTEG_DBHUB_NODE         the node binary to run them with (default "node")

FIXED alone is enough for the CONFIG cell and the fault-injection tests; both are needed for the
VERSION cell. Benign marker only: every real round is `PRAGMA user_version = <n>` on a throwaway
file this test creates and never anything else.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from gcl.enforce.breach.dbhub_breach import (
    CALL_ID,
    G8_STATEMENT,
    DbhubStoreObserver,
    KillMidStepTarget,
    TimeoutTarget,
    config_cell_target,
    config_scenario,
    pragma_value,
    version_cell_target,
    version_scenario,
    write_breach_config,
)
from gcl.enforce.breach.runner import run_paired_trial
from gcl.enforce.dbhub_target import seed_db

FIXED = os.environ.get("GCL_INTEG_DBHUB_FIXED")
VULN = os.environ.get("GCL_INTEG_DBHUB_VULNERABLE")
NODE = os.environ.get("GCL_INTEG_DBHUB_NODE", "node")

needs_fixed = pytest.mark.skipif(not FIXED, reason="set GCL_INTEG_DBHUB_FIXED to a real "
                                 "@bytebase/dbhub >=0.22.6 install dir")
needs_both = pytest.mark.skipif(not (FIXED and VULN), reason="set both GCL_INTEG_DBHUB_FIXED and "
                                "GCL_INTEG_DBHUB_VULNERABLE for the VERSION cell")


def _fake_install(tmp_path, name: str, version: str, js: bytes = b"// fake dbhub\n") -> Path:
    d = tmp_path / name
    (d / "dist").mkdir(parents=True)
    (d / "package.json").write_text(f'{{"name": "@bytebase/dbhub", "version": "{version}"}}', encoding="utf-8")
    (d / "dist" / "index.js").write_bytes(js)
    return d


# --------------------------------------------------------------------------- unit: scenarios


def test_scenarios_are_labelled_distinctly_and_never_confused():
    cfg, ver = config_scenario(), version_scenario()
    assert cfg.calibration_kind == "config"
    assert ver.calibration_kind == "version"
    assert cfg.calibration_kind != ver.calibration_kind
    assert cfg.protection_variable == "readonly"
    assert ver.protection_variable == "version"
    assert cfg.id != ver.id
    # same narrow terminal event (gcl's own read, never dbhub's reply) -- the claim differs only
    # in WHAT is toggled, never in what counts as "it happened"
    assert "gcl's own read-only connection" in cfg.terminal_event
    assert "gcl's own read-only connection" in ver.terminal_event


def test_g8_statement_says_n_a_and_why():
    assert "N/A" in G8_STATEMENT
    assert "engine-level" in G8_STATEMENT


# --------------------------------------------------------------------------- unit: pragma_value


def test_pragma_value_is_deterministic_from_the_marker():
    v1 = pragma_value("GCL-BRE-dbhub-config-run123")
    v2 = pragma_value("GCL-BRE-dbhub-config-run123")
    assert v1 == v2


def test_pragma_value_differs_for_different_markers_and_avoids_reserved_values():
    values = {pragma_value(f"GCL-BRE-dbhub-config-run{i}") for i in range(20)}
    assert len(values) > 1  # not a constant
    for v in values:
        assert 10_000 <= v <= 99_999
        assert v not in (0, 1)  # 0 is SQLite's default; 1 is gcl's own k00l nudge value


# --------------------------------------------------------------------------- unit: config generation


def test_write_breach_config_readonly_true(tmp_path):
    cfg = write_breach_config(tmp_path, tmp_path / "x.sqlite", readonly=True)
    assert "readonly = true" in cfg.read_text()
    assert cfg.name == "dbhub.toml"


def test_write_breach_config_readonly_false(tmp_path):
    cfg = write_breach_config(tmp_path, tmp_path / "x.sqlite", readonly=False)
    assert "readonly = false" in cfg.read_text()


# --------------------------------------------------------------------------- unit: manifest diff


def test_config_cell_manifest_differs_only_in_readonly(tmp_path):
    install = _fake_install(tmp_path, "install", "0.22.6")
    target = config_cell_target(NODE, install, tmp_path / "db.sqlite", tmp_path / "work")
    target.start(False, "r1")
    off = target.manifest()
    target.start(True, "r1")
    on = target.manifest()
    assert off["readonly"] is False and on["readonly"] is True
    assert off["version"] == on["version"]  # same install both sides: nothing else differs
    for key in ("transport", "node", "db_path", "config_shape"):
        assert off[key] == on[key]


def test_version_cell_manifest_differs_only_in_version(tmp_path):
    install_on = _fake_install(tmp_path, "on", "0.22.6", js=b"// patched\n")
    install_off = _fake_install(tmp_path, "off", "0.22.5", js=b"// vulnerable\n")
    target = version_cell_target(NODE, install_on, install_off, tmp_path / "db.sqlite", tmp_path / "work")
    target.start(False, "r1")
    off = target.manifest()
    target.start(True, "r1")
    on = target.manifest()
    assert off["readonly"] is True and on["readonly"] is True  # same both sides: not the toggle
    assert off["version"] != on["version"]  # the ONE thing that differs
    assert off["version"]["pkg_version"] == "0.22.5"
    assert on["version"]["pkg_version"] == "0.22.6"
    assert off["version"]["dist_sha256_16"] != on["version"]["dist_sha256_16"]
    for key in ("transport", "node", "db_path", "config_shape"):
        assert off[key] == on[key]


def test_calibration_kind_is_read_from_the_install_dicts_not_declared(tmp_path):
    install = _fake_install(tmp_path, "shared", "0.22.6")
    cfg_target = config_cell_target(NODE, install, tmp_path / "a.sqlite", tmp_path / "wa")
    assert cfg_target.calibration_kind == "config"
    install2 = _fake_install(tmp_path, "other", "0.22.5")
    ver_target = version_cell_target(NODE, install, install2, tmp_path / "b.sqlite", tmp_path / "wb")
    assert ver_target.calibration_kind == "version"


# --------------------------------------------------------------------------- unit: the relay


def test_relay_binds_the_step_to_the_marker_and_the_sql_carries_the_derived_value(tmp_path):
    install = _fake_install(tmp_path, "install", "0.22.6")
    target = config_cell_target(NODE, install, tmp_path / "db.sqlite", tmp_path / "work")
    target.start(True, "r1")
    scenario = config_scenario()
    rt, sql = target._relay(scenario, "r1")
    assert rt.bound_ok is True
    assert rt.marker_seen is True
    value = pragma_value(scenario.marker("r1"))
    assert sql == f"PRAGMA user_version = {value}"
    assert target.last_expected_pragma_value == value


# --------------------------------------------------------------------------- unit: the observer


def test_store_observer_saw_effect_requires_the_exact_expected_value(tmp_path):
    db = tmp_path / "d.sqlite"
    seed_db(db)
    install = _fake_install(tmp_path, "install", "0.22.6")
    target = config_cell_target(NODE, install, db, tmp_path / "work")
    target.last_expected_pragma_value = 54321
    obs = DbhubStoreObserver(db, target)
    before = obs.snapshot()
    assert obs.saw_effect(before, before, config_scenario()) is False  # nothing changed yet
    import sqlite3

    con = sqlite3.connect(db)
    con.execute("PRAGMA user_version = 11111")  # SOME change, but not the expected one
    con.commit()
    con.close()
    wrong = obs.snapshot()
    assert obs.saw_effect(before, wrong, config_scenario()) is False
    con = sqlite3.connect(db)
    con.execute("PRAGMA user_version = 54321")
    con.commit()
    con.close()
    right = obs.snapshot()
    assert obs.saw_effect(before, right, config_scenario()) is True


# --------------------------------------------------------------------------- opt-in: CONFIG cell


@needs_fixed
def test_config_cell_holds_with_readonly_true_and_off_calibrates_the_escape(tmp_path):
    target = config_cell_target(NODE, FIXED, tmp_path / "config.sqlite", tmp_path / "work",
                                timeout_s=30.0)
    obs = DbhubStoreObserver(tmp_path / "config.sqlite", target)
    report = run_paired_trial(config_scenario(), target, [obs], repeats=3)
    t = report["trial"]
    assert t["cell"] == "calibrated+held", (t, report["results"])
    assert t["policy"] == "held"
    assert t["stable"] is True
    verdict = next(r for r in report["results"] if r["scenario"]["id"] == "dbhub-config")
    assert verdict["evidence"]["calibration_kind"] == "config"
    assert verdict["evidence"]["repeats"][0]["off"]["effect_observed"] is True  # OFF escapes
    assert verdict["evidence"]["repeats"][0]["on"]["effect_observed"] is False  # ON contains it


# --------------------------------------------------------------------------- opt-in: VERSION cell


@needs_both
def test_version_cell_holds_on_patched_and_vulnerable_calibrates_the_escape(tmp_path):
    target = version_cell_target(NODE, FIXED, VULN, tmp_path / "version.sqlite", tmp_path / "work",
                                 timeout_s=30.0)
    obs = DbhubStoreObserver(tmp_path / "version.sqlite", target)
    report = run_paired_trial(version_scenario(), target, [obs], repeats=3)
    t = report["trial"]
    assert t["cell"] == "calibrated+held", (t, report["results"])
    assert t["policy"] == "held"
    assert t["stable"] is True
    verdict = next(r for r in report["results"] if r["scenario"]["id"] == "dbhub-version")
    assert verdict["evidence"]["calibration_kind"] == "version"
    assert verdict["evidence"]["repeats"][0]["off"]["effect_observed"] is True  # 0.22.5 escapes
    assert verdict["evidence"]["repeats"][0]["on"]["effect_observed"] is False  # 0.22.6 contains it


# --------------------------------------------------------------------------- opt-in: fault injection


@needs_fixed
def test_killed_mid_step_is_unverified_never_a_false_held(tmp_path):
    target = KillMidStepTarget(NODE, {True: FIXED, False: FIXED}, {True: True, False: False},
                               tmp_path / "kill.sqlite", tmp_path / "work", timeout_s=30.0)
    obs = DbhubStoreObserver(tmp_path / "kill.sqlite", target)
    report = run_paired_trial(config_scenario(), target, [obs], repeats=1)
    t = report["trial"]
    assert t["policy"] != "held", (t, report["results"])
    assert t["policy"] == "unverified", (t, report["results"])


@needs_fixed
def test_timeout_is_unverified_never_a_false_held(tmp_path):
    target = TimeoutTarget(NODE, {True: FIXED, False: FIXED}, {True: True, False: False},
                          tmp_path / "timeout.sqlite", tmp_path / "work", timeout_s=30.0,
                          timeout_override_s=0.02)
    obs = DbhubStoreObserver(tmp_path / "timeout.sqlite", target)
    report = run_paired_trial(config_scenario(), target, [obs], repeats=1)
    t = report["trial"]
    assert t["policy"] != "held", (t, report["results"])
    assert t["policy"] == "unverified", (t, report["results"])


@needs_fixed
def test_dead_observer_is_unverified_never_a_false_held(tmp_path):
    real_db = tmp_path / "real.sqlite"
    decoy_db = tmp_path / "decoy.sqlite"
    seed_db(decoy_db)  # a valid file, just never written by the target: the "wrong file" fault
    target = config_cell_target(NODE, FIXED, real_db, tmp_path / "work", timeout_s=30.0)
    dead_obs = DbhubStoreObserver(decoy_db, target)
    report = run_paired_trial(config_scenario(), target, [dead_obs], repeats=1)
    t = report["trial"]
    assert t["policy"] != "held", (t, report["results"])
    assert t["policy"] == "unverified"
    assert t["gate"] == "k00l"  # caught before anything was even executed


@needs_fixed
def test_config_cell_stable_over_repeats(tmp_path):
    """Explicit stability check beyond the default repeats=3 already exercised above."""
    target = config_cell_target(NODE, FIXED, tmp_path / "stab.sqlite", tmp_path / "work", timeout_s=30.0)
    obs = DbhubStoreObserver(tmp_path / "stab.sqlite", target)
    report = run_paired_trial(config_scenario(), target, [obs], repeats=3)
    assert report["trial"]["stable"] is True
    assert report["receipt"]["repeats"] == 3


def test_call_id_is_not_the_actions_phase_call_id():
    """Keeps breach's own stdio requests tellable apart from `gcl actions`' in a shared log."""
    from gcl.enforce.dbhub_target import DbhubTarget

    assert CALL_ID != DbhubTarget.CALL_ID
