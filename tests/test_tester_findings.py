"""The tester's own mistakes, stage 6: a findings ledger that only holds what runs can
back. Findings come from stored runs, repeat with separate runs, confirm only with an
independent reproduction, and are re-checked against their reports and newer runs."""

import copy
import json
import sys
from pathlib import Path

import pytest

from gcl import findings as F
from gcl.enforce.adapters import ReferenceGateway
from gcl.enforce.contracts import run_contracts


def _report(tmp: Path, name: str, profile: str = "naive", clean: bool = True, edit=None) -> Path:
    """A stored report of a real reference-gateway run. Its receipt is set explicitly, so
    the test does not depend on whether this checkout happens to be clean: `clean` is a
    run from a committed checkout, otherwise one with uncommitted gcl files."""
    run = run_contracts(ReferenceGateway(sys.executable, tmp / name, profile), 15, only={"i04"})
    run["receipt"]["problems"] = [] if clean else ["gcl has 1 uncommitted or untracked file(s)"]
    if edit:
        edit(run)
    p = tmp / name / "report.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"tool": "guardrail-contract-lab", "command": "enforce", "enforce": run}))
    return p


@pytest.fixture(scope="module")
def reports(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("runs")
    return {"a": _report(tmp, "a"), "b": _report(tmp, "b"), "dirty": _report(tmp, "dirty", clean=False),
            "strict": _report(tmp, "strict", "strict"), "tmp": tmp}


def test_a_finding_comes_only_from_a_backed_result(reports):
    doc = F.load(Path("/nonexistent"))
    f = F.add(doc, reports["a"], "i04", "error passes")
    assert f["status"] == "proposed" and f["runs"][0]["run_id"] and not f["guessed"]
    with pytest.raises(F.LedgerError, match="already exists"):
        F.add(doc, reports["b"], "i04", "again")
    with pytest.raises(F.LedgerError, match="nothing to report"):
        F.add(F.load(Path("/x")), reports["strict"], "i04", "held")
    with pytest.raises(F.LedgerError, match="receipt lists problems"):
        F.add(F.load(Path("/x")), reports["dirty"], "i04", "from a dirty checkout")

    def unverified(run):
        for r in run["results"]:
            if r["scenario"]["id"] == "i04":
                r["policy"] = r["documented"] = "unverified"

    with pytest.raises(F.LedgerError, match="unverified"):
        F.add(F.load(Path("/x")), _report(reports["tmp"], "u", edit=unverified), "i04", "not evidence")


def test_repeat_needs_a_separate_run_and_confirm_an_independent_reproduction(reports, tmp_path):
    doc = F.load(Path("/x"))
    fid = F.add(doc, reports["a"], "i04", "error passes")["id"]
    with pytest.raises(F.LedgerError, match="separate run"):
        F.repeat(doc, fid, reports["a"])
    with pytest.raises(F.LedgerError, match="confirm needs a repeated"):
        F.confirm(doc, fid, reports["a"], "recorded", "x")
    assert F.repeat(doc, fid, reports["b"])["status"] == "repeated"
    lazy = tmp_path / "repro_lazy.py"
    lazy.write_text('ANSWER = {"action": "BLOCKED", "blocked_reason": "GCL-BLOCKED by the stand-in"}\n')
    with pytest.raises(F.LedgerError, match="reuses gcl's stand-in"):
        F.confirm(doc, fid, lazy, "recorded", "x")
    with pytest.raises(F.LedgerError, match="declare where"):
        F.confirm(doc, fid, lazy, "stand-in", "x")
    good = tmp_path / "repro.py"
    good.write_text("# the guard returns HTTP 500; the proxy forwards the prompt\n")
    f = F.confirm(doc, fid, good, "vendor-docs", "500 from the guard, prompt forwarded")
    assert f["status"] == "confirmed" and [h["to"] for h in f["history"]] == ["proposed", "repeated", "confirmed"]


def test_a_guessed_finding_needs_real_vendor_answers_to_be_confirmed(reports, tmp_path):
    doc = F.load(Path("/x"))
    f = F.add(doc, reports["a"], "i04", "x")
    f["guessed"] = True  # as if the stand-in were rebuilt from client code
    F.repeat(doc, f["id"], reports["b"])
    repro = tmp_path / "r.py"
    repro.write_text("# reproduction\n")
    with pytest.raises(F.LedgerError, match="guessed stand-in"):
        F.confirm(doc, f["id"], repro, "vendor-docs", "x")
    assert F.confirm(doc, f["id"], repro, "recorded", "captured reply")["status"] == "confirmed"


def test_a_different_outcome_contradicts_and_a_retraction_keeps_the_record(reports):
    tmp = reports["tmp"]

    def held(run):
        for r in run["results"]:
            if r["scenario"]["id"] == "i04":
                r["observed"], r["policy"] = "stopped", "held"

    other = _report(tmp, "c", edit=held)
    doc = F.load(Path("/x"))
    fid = F.add(doc, reports["a"], "i04", "x")["id"]
    assert F.repeat(doc, fid, other)["status"] == "contradicted"
    f = F.retract(doc, fid, "the guard answer was unrealistic")
    assert f["status"] == "retracted" and len(f["history"]) == 3 and f["runs"]


def test_check_catches_edited_or_missing_reports_and_newer_disagreeing_runs(reports, tmp_path):
    a = tmp_path / "a" / "report.json"
    a.parent.mkdir()
    a.write_bytes(reports["a"].read_bytes())
    doc = F.load(Path("/x"))
    F.add(doc, a, "i04", "x")
    assert F.check(doc) == []
    newer = tmp_path / "newer"
    d = json.loads(reports["a"].read_text())
    d2 = copy.deepcopy(d)
    d2["enforce"]["receipt"]["run_id"] = "ffffff"
    for r in d2["enforce"]["results"]:
        if r["scenario"]["id"] == "i04":
            r["observed"], r["policy"] = "stopped", "held"
    d2["enforce"]["receipt"]["gcl"]["source_sha256"] = "0" * 64
    (newer / "x").mkdir(parents=True)
    (newer / "x" / "report.json").write_text(json.dumps(d2))
    problems = [p["problem"] for p in F.check(doc, newer)]
    assert any("contradicted by run ffffff" in p for p in problems)
    assert any(p.startswith("stale") for p in problems)
    a.write_text(a.read_text().replace('"passed"', '"stopped"', 1))
    assert any("changed since it was added" in p["problem"] for p in F.check(doc))
    a.unlink()
    assert any("missing" in p["problem"] for p in F.check(doc))


def test_the_ledger_may_not_live_in_gcls_checkout(tmp_path):
    from typer.testing import CliRunner

    from gcl.cli import app

    inside = Path(F.__file__).resolve().parent.parent / "findings-ledger.json"
    res = CliRunner().invoke(app, ["findings", "render", str(inside)])
    assert res.exit_code == 2 and not inside.exists()
    outside = tmp_path / "ledger.json"
    assert CliRunner().invoke(app, ["findings", "render", str(outside)]).exit_code == 0


def test_render_keeps_every_qualifier(reports):
    doc = F.load(Path("/x"))
    f = F.add(doc, reports["a"], "i04", "error passes")
    f["guessed"] = True
    table = F.render(doc)
    assert "| proposed |" in table and "GUESSED" in table and "reference (naive)" in table
    assert "end-to-end run" in table
