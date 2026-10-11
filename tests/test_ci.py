"""CI: SARIF for enforce, `gcl compare` across versions, and the GitHub Action."""

import copy
import json
import re
import sys
from pathlib import Path

import pytest

from gcl.compare import compare
from gcl.enforce.adapters import ReferenceGateway
from gcl.enforce.contracts import run_contracts
from gcl.report.sarif import enforce_sarif

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("ci")
    naive = run_contracts(ReferenceGateway(sys.executable, tmp / "n", "naive"), 15, only={"i04", "i09"})
    strict = run_contracts(ReferenceGateway(sys.executable, tmp / "s", "strict"), 15, only={"i04", "i09"})
    return {"naive": naive, "strict": strict, "tmp": tmp}


def test_sarif_has_a_result_for_every_scenario_that_did_not_cleanly_hold(runs):
    doc = enforce_sarif(runs["naive"], "specs/reference.json")
    res = doc["runs"][0]["results"]
    bad = [r for r in runs["naive"]["results"] if not (r["policy"] == "held" and r["documented"] != "deviates")]
    assert len(res) == len(bad) >= 2
    assert {r["level"] for r in res} == {"error"}
    assert all(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "specs/reference.json" for r in res)
    assert len({r["partialFingerprints"]["gclScenario"] for r in res}) == len(res)
    rule_ids = {d["id"] for d in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in res} <= rule_ids
    assert enforce_sarif(runs["strict"], "x")["runs"][0]["results"] == []


def _write(tmp, name, run):
    p = tmp / name / "report.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"enforce": run}))
    return p


def test_compare_finds_regressions_fixes_and_unverified_changes(runs):
    tmp, base = runs["tmp"], runs["naive"]
    old = _write(tmp, "old", base)
    newer = copy.deepcopy(base)
    for r in newer["results"]:
        if r["scenario"]["mode"] == "error" and r["scenario"]["stage"] == "input":
            r["observed"], r["policy"] = "stopped", "held"           # fixed upstream
        if r["scenario"]["mode"] == "unknown_verdict":
            r["policy"] = "unverified"                               # this run could not judge it
    d = compare(old, _write(tmp, "new", newer))
    assert [x["scenario"] for x in d["fixes"]] == ["input/error/de"]
    assert d["unverified_changes"] and not d["regressions"]
    back = compare(_write(tmp, "fixed", newer), old)                # and the other way round
    assert [x["scenario"] for x in back["regressions"]] == ["input/error/de"]


def test_compare_refuses_different_integrations_and_the_cli_fails_on_a_regression(runs):
    from typer.testing import CliRunner

    from gcl.cli import app

    tmp = runs["tmp"]
    with pytest.raises(ValueError, match="different"):
        compare(_write(tmp, "a", runs["naive"]), _write(tmp, "b", runs["strict"]))
    held = copy.deepcopy(runs["naive"])
    for r in held["results"]:
        if r["scenario"]["mode"] == "error":
            r["observed"], r["policy"] = "stopped", "held"
    res = CliRunner().invoke(app, ["compare", str(_write(tmp, "h", held)), str(_write(tmp, "v", runs["naive"]))])
    assert res.exit_code == 1 and "REGRESSIONS" in res.output


def test_cli_writes_sarif(tmp_path):
    from typer.testing import CliRunner

    from gcl.cli import app

    out = tmp_path / "out"
    res = CliRunner().invoke(app, ["enforce", "reference", "--python", sys.executable, "--profile", "naive",
                                   "--scenario", "i04", "--timeout", "10", "--out", str(out),
                                   "--format", "json,sarif", "--sarif-anchor", "gcl/reference.yaml"])
    assert res.exit_code == 1, res.output
    sarif = json.loads((out / "report.sarif").read_text())
    assert sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] \
        == "gcl/reference.yaml"


def test_the_action_passes_inputs_as_data_not_script():
    yaml = pytest.importorskip("yaml")
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    assert action["runs"]["using"] == "composite"
    for step in action["runs"]["steps"]:
        script = step["run"]
        assert not re.search(r"\$\{\{\s*inputs\.", script.replace('"${{ github.action_path }}"', "")), script
    watch = yaml.safe_load((ROOT / "examples/ci/version-watch.yml").read_text())
    assert "gcl compare" in json.dumps(watch)


@pytest.mark.parametrize("cmd", ["compare", "findings", "record", "enforce"])
def test_every_command_is_registered_when_run_as_a_module(cmd):
    import subprocess

    r = subprocess.run([sys.executable, "-m", "gcl.cli", cmd, "--help"], capture_output=True, text=True,
                       cwd=ROOT, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
