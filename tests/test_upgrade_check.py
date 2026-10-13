"""`gcl upgrade-check`: the regression logic on synthetic reports, and the command end to end on the
reference gateway (strict -> naive is an upgrade that broke fail-closed; strict -> strict is none)."""

import copy
import json
import sys

import pytest
from typer.testing import CliRunner

from gcl.cli import app
from gcl.enforce.receipt import docs_versions
from gcl.upgrade import check_files, controls_usable, guard_consulted, render, upgrade_check


def _res(sid, stage, mode, policy="held", observed="stopped", role="", documented="conforms", events=1):
    return {"scenario": {"id": sid, "stage": stage, "mode": mode, "lang": "en", "role": role,
                         "control": bool(role) and role in ("open", "close"), "attack": ""},
            "observed": observed, "policy": policy, "documented": documented,
            "evidence": {"scanner_events": [{"valid": True}] * events}}


def _run(profile="strict", versions=None, read_for="", **over):
    results = [_res("i00", "input", "allow", observed="passed", role="open"),
               _res("i01", "input", "block", role="open"),
               _res("o02", "output", "allow", observed="passed", role="open"),
               _res("o03", "output", "block", role="open"),
               _res("i04", "input", "error"), _res("o05", "output", "timeout")]
    return {"integration": {"integration": "x", "profile": profile, "versions": versions or {},
                            "documented_source": {"read_for": read_for}, "config": {"p": profile}},
            "receipt": {"run_id": "aaaaaa", "problems": []}, "results": results, **over}


def _set(run, sid, **kw):
    for r in run["results"]:
        if r["scenario"]["id"] == sid:
            r.update(kw)
    return run


def _rows(d, cat):
    return [r["scenario"] for r in d["rows"] if r["category"] == cat]


def test_identical_runs_have_no_regression():
    d = upgrade_check(_run(), _run())
    assert d["exit_code"] == 0 and d["verdict"] == "no regression" and d["regression_count"] == 0
    assert d["counts"]["unchanged"] == 6


def test_held_to_violated_is_a_regression_and_violated_to_held_an_improvement():
    after = _set(_run(), "i04", policy="violated", observed="passed", documented="deviates")
    d = upgrade_check(_run(), after)
    assert d["exit_code"] == 1 and _rows(d, "regressions") == ["input/error/en"]
    back = upgrade_check(after, _run())
    assert back["exit_code"] == 0 and _rows(back, "improvements") == ["input/error/en"]


def test_held_to_unverified_is_a_regression_when_the_after_controls_hold():
    after = _set(_run(), "o05", policy="unverified", observed="unclear", documented="unverified")
    d = upgrade_check(_run(), after)
    assert d["exit_code"] == 1 and _rows(d, "unverified_regressions") == ["output/timeout/en"]
    assert "held -> unverified" in render(d)


def test_unverified_to_held_is_not_a_regression():
    before = _set(_run(), "o05", policy="unverified", observed="unclear", documented="unverified")
    d = upgrade_check(before, _run())
    assert d["exit_code"] == 0 and _rows(d, "now_verified") == ["output/timeout/en"]


def test_broken_after_controls_make_the_comparison_unverified_not_regressed():
    after = _run()
    for sid in ("i01", "i04", "o05"):  # the setup stopped working: nothing in this run is evidence
        _set(after, sid, policy="unverified", observed="unclear", documented="unverified")
    d = upgrade_check(_run(), after)
    assert controls_usable(after) == (False, ["i01"])
    assert d["regression_count"] == 0 and d["exit_code"] == 2 and d["verdict"] == "unverified"
    assert len(_rows(d, "unverified_comparison")) == 3 and not _rows(d, "unverified_regressions")
    assert any("after: controls not usable" in x for x in d["unverified_reasons"])


def test_a_proven_leak_survives_broken_controls():
    after = _set(_set(_run(), "i01", policy="unverified", observed="unclear", documented="unverified"),
                 "i04", policy="violated", observed="passed", documented="deviates")
    d = upgrade_check(_run(), after)
    assert d["exit_code"] == 1 and _rows(d, "regressions") == ["input/error/en"]


def test_a_guard_gone_silent_is_a_regression_even_if_everything_still_looks_held():
    after = _run()
    for r in after["results"]:
        if r["scenario"]["stage"] == "output":
            r["evidence"]["scanner_events"] = []  # still "held": nothing leaked in what was sent
    assert guard_consulted(after) == {"input": 2, "output": 0}
    d = upgrade_check(_run(), after)
    assert d["guard"]["output"]["status"] == "absent_after" and d["guard"]["input"]["status"] == "ok"
    assert d["exit_code"] == 1 and d["regression_count"] == 1
    assert "GUARD ABSENT" in render(d)


def test_a_guard_never_consulted_in_either_run_proves_nothing():
    quiet = _run()
    for r in quiet["results"]:
        r["evidence"]["scanner_events"] = []
    d = upgrade_check(copy.deepcopy(quiet), quiet)
    assert d["exit_code"] == 2 and d["regression_count"] == 0
    assert {g["status"] for g in d["guard"].values()} == {"never_consulted"}


def test_scenarios_on_one_side_only_are_unverified():
    after = _run()
    after["results"].append(_res("i06", "input", "malformed"))
    d = upgrade_check(_run(), after)
    assert d["exit_code"] == 2 and d["only_after"] == ["input/malformed/en"]


def test_different_integrations_are_refused():
    other = _run()
    other["integration"]["integration"] = "y"
    with pytest.raises(ValueError, match="different"):
        upgrade_check(_run(), other)


def test_profiles_may_differ_between_the_sides():
    d = upgrade_check(_run("strict"), _run("naive"))
    assert d["before"]["profile"] == "strict" and d["after"]["profile"] == "naive"


def test_docs_due_when_the_after_install_moved_past_the_docs():
    rf = "litellm 1.104.2 (docs page read 2026-10-10)"
    d = upgrade_check(_run(versions={"litellm": "1.99.0"}, read_for=rf),
                      _run(versions={"litellm": "1.105.0"}, read_for=rf))
    (row,) = d["docs"]
    assert row["docs_due"] and row["relation_before"] == "before" and row["relation_after"] == "past"
    assert "DOCS RE-READ DUE" in render(d)
    same = upgrade_check(_run(versions={"litellm": "1.104.2"}, read_for=rf),
                         _run(versions={"litellm": "1.104.2"}, read_for=rf))
    assert not same["docs"][0]["docs_due"]


def test_docs_read_for_two_versions_are_both_listed_and_the_stale_one_is_due():
    a = _run(versions={"litellm": "1.105.0"}, read_for="litellm 1.104.2")
    a["integration"]["config_documented_source"] = [{"read_for": "litellm 1.105.0"}]
    d = upgrade_check(a, copy.deepcopy(a))
    assert [(r["docs_read_for"], r["docs_due"]) for r in d["docs"]] == [("1.104.2", True), ("1.105.0", False)]


def test_docs_versions_relations():
    src = {"read_for": "nemoguardrails 0.24.1, langchain 1.4.4"}
    got = {d["package"]: d["relation"] for d in docs_versions(
        src, {"nemoguardrails": "0.25.0", "langchain": "1.4.4", "python": "3.13"})}
    assert got == {"nemoguardrails": "past", "langchain": "matches"}
    assert docs_versions(src, {"nemoguardrails": "weird"})[0]["relation"] == "differs"


def test_check_files_refuses_a_latency_sweep(tmp_path):
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"enforce_by_latency": [_run(), _run()]}))
    with pytest.raises(ValueError, match="latency sweeps"):
        check_files(p, p)


# --------------------------------------------------------------------------- end to end
def _cli(tmp_path, before, after):
    out = tmp_path / "out"
    res = CliRunner().invoke(app, ["upgrade-check", "reference", "--before", sys.executable, "--after", sys.executable,
                                   "--before-profile", before, "--after-profile", after, "--timeout", "10",
                                   "--scenario", "i04", "--scenario", "o13", "--out", str(out)])
    return res, out


def test_strict_to_naive_is_flagged_and_exits_non_zero(tmp_path):
    res, out = _cli(tmp_path, "strict", "naive")
    assert res.exit_code == 1, res.output
    d = json.loads((out / "upgrade-check.json").read_text())
    assert _rows(d, "regressions") == ["input/error/de", "output/error/he"]
    assert d["guard"]["input"]["status"] == "ok" and d["guard"]["output"]["status"] == "ok"
    assert d["before"]["controls_usable"] and d["after"]["controls_usable"]
    assert (out / "before" / "report.json").exists() and (out / "after" / "report.json").exists()
    assert "REGRESSIONS (held -> violated)" in res.output


def test_strict_to_strict_shows_no_regression(tmp_path):
    res, out = _cli(tmp_path, "strict", "strict")
    assert res.exit_code == 0, res.output
    d = json.loads((out / "upgrade-check.json").read_text())
    assert d["regression_count"] == 0 and d["verdict"] == "no regression"
    assert d["counts"]["unchanged"] == len(d["rows"])
