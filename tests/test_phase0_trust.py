"""Phase 0, "make adapters safe to believe": the mutation control (`enforce --attest`), the
control-path attestation in the receipt, and `gcl replay`.

The test that matters is the negative control: an adapter that is NOT wired to the integration's
control but passes every ordinary control must go red. _Sneaky below is such an adapter. It asks
the stand-in a question (so the scanner is "consulted") and then ignores the answer, deciding by a
table it took from gcl's own plan. Without --attest its run is a perfect score; with it, nothing is
believed. If that test ever goes green on the sneaky adapter, the gate is broken.
"""

import contextlib
import json
import re
import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path
from typing import ClassVar

import pytest

from gcl.enforce import contracts as C
from gcl.enforce.adapters import ADAPTERS, ReferenceGateway
from gcl.enforce.contracts import POLICY, Scenario, build_scenarios, run_contracts, write_bundles
from gcl.enforce.replay import MANIFEST, replay, seal_bundle, verify_seal

from .test_enforce import _Fake


# --------------------------------------------------------------------------- stub adapters
def _reply(content: str) -> tuple[int, dict]:
    return 200, {"choices": [{"message": {"role": "assistant", "content": content}}]}


def _ping(g, stage: str, texts: list[str]) -> None:
    """Ask the stand-in, so it records a consultation, and throw the answer away."""
    path = g.protocol.path
    body = json.dumps({"texts": texts, "input_type": {"input": "request", "output": "response"}[stage]}).encode()
    with contextlib.suppress(Exception):   # a stalled or refused stand-in: still consulted, still ignored
        urllib.request.urlopen(urllib.request.Request(g.scanner.base_for(stage) + path, data=body), timeout=0.5).read()


def _sneaky(g, messages):
    """Not wired to anything: decides from a table built from gcl's own plan (what each scenario
    id is supposed to get), after pretending to ask the scanner."""
    table = {s.id: s.mode for s in build_scenarios(g)}
    text = messages[-1]["content"]
    sid = re.search(r"GCL-U-([io]\d{2})", text).group(1)
    mode = table[sid]
    _ping(g, "input", [m["content"] for m in messages])
    if sid.startswith("o"):   # output stage: the model is called either way, then the reply is judged
        reply = g.forward(messages)
        _ping(g, "output", [reply])
        return _reply(reply) if mode == "allow" else (400, {"error": "blocked"})
    return _reply(g.forward(messages)) if mode == "allow" else (400, {"error": "blocked"})


def _always_forward(g, messages):
    """The plain stub: never asks anyone, forwards everything."""
    return _reply(g.forward(messages))


class _Stub(_Fake):
    """An in-process gateway driven by a function, with only the capabilities of the table."""

    capabilities: ClassVar[set[str]] = {"input", "output"}
    behaviour = staticmethod(_sneaky)

    def __init__(self, python, workdir, profile="default"):
        super().__init__(Path(workdir), type(self).behaviour)


class _Sneaky(_Stub):
    name = "sneaky"
    behaviour = staticmethod(_sneaky)


class _Forwarder(_Stub):
    name = "forwarder"
    behaviour = staticmethod(_always_forward)


def _states(run):
    return {r["policy"] for r in run["results"]}


# --------------------------------------------------------------------------- mutation control
def test_mutation_control_passes_on_reference_strict_and_flips_every_control(tmp_path):
    run = run_contracts(ReferenceGateway(sys.executable, tmp_path, "strict"), 15, only={"i04"}, attest=True,
                        settle_s=0.3)
    mc = run["mutation_control"]
    assert mc["state"] == "passed", mc
    flipped = [p for p in mc["probes"] if p["mutated"]]
    # Input and output, allow and block: a block control made to pass, an allow control made to stop.
    assert {(p["stage"], p["control"], p["forced"]) for p in flipped} == {
        ("input", "block", "allow"), ("output", "block", "allow"),
        ("input", "allow", "block"), ("output", "allow", "block")}
    assert all(p["ok"] and p["scanner_consulted"] for p in mc["probes"])
    # A pass changes nothing: the verdicts are the ones an unattested run gives.
    assert _states(run) == {"held"}
    assert not [p for p in run["receipt"]["problems"] if "mutation" in p or "control" in p]


def test_mutation_control_passes_on_naive_and_does_not_hide_its_violations(tmp_path):
    """The naive gateway IS wired to the control (it violates the fault contract, not the verdict
    contract): the mutation control must pass and must not launder or demote its findings."""
    run = run_contracts(ReferenceGateway(sys.executable, tmp_path, "naive"), 15, only={"i04", "o14"}, attest=True,
                        settle_s=0.3)
    assert run["mutation_control"]["state"] == "passed", run["mutation_control"]
    by = {r["scenario"]["id"]: r for r in run["results"]}
    assert by["i04"]["policy"] == "violated" and by["o14"]["policy"] == "violated"


def test_a_sneaky_adapter_scores_perfectly_without_the_mutation_control(tmp_path):
    """The blind spot the mutation control exists for: every ordinary control and fault passes."""
    run = run_contracts(_Sneaky(sys.executable, tmp_path), 5, only={"i04"}, settle_s=0.3)
    assert _states(run) == {"held"}, [(r["scenario"]["id"], r["observed"], r["policy"], r["notes"])
                                      for r in run["results"] if r["policy"] != "held"]
    assert run["mutation_control"]["state"] == "n/a" and run["mutation_control"]["requested"] is False


def test_NEGATIVE_CONTROL_a_sneaky_adapter_fails_the_mutation_control_and_nothing_is_believed(tmp_path):
    """The key test: the gate can go red. The same adapter, run with --attest."""
    run = run_contracts(_Sneaky(sys.executable, tmp_path), 5, only={"i04"}, attest=True, settle_s=0.3)
    mc = run["mutation_control"]
    assert mc["state"] == "failed"
    bad = {(p["scenario"], p["forced"]) for p in mc["probes"] if not p["ok"]}
    assert ("i01", "allow") in bad and ("i00", "block") in bad, bad   # blocks that cannot pass, allows that cannot stop
    # Every scenario, controls included, is unverified; none is held or violated.
    assert _states(run) == {"unverified"}
    assert run["summary"]["policy_held"] == 0 and run["summary"]["policy_violated"] == 0
    assert run["summary"]["unverified"] == run["summary"]["scenarios"]
    assert all(any("adapter did not reach the control" in n for n in r["notes"]) for r in run["results"])
    assert all(r["evidence"]["owasp"] == [] and r["evidence"]["confidence"] is None for r in run["results"])
    assert any("mutation control failed" in p for p in run["receipt"]["problems"])


def test_NEGATIVE_CONTROL_an_always_forward_adapter_also_fails_it(tmp_path):
    run = run_contracts(_Forwarder(sys.executable, tmp_path), 5, only={"i04"}, attest=True, settle_s=0.3)
    assert run["mutation_control"]["state"] == "failed"
    assert any("never asked" in (p["why"] or "") for p in run["mutation_control"]["probes"])
    assert _states(run) == {"unverified"}


def test_a_failed_mutation_control_exits_2_whatever_fail_on_says(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from gcl.cli import app

    monkeypatch.setitem(ADAPTERS, "sneaky", _Sneaky)
    args = ["enforce", "sneaky", "--python", sys.executable, "--profile", "default", "--scenario", "i04"]
    # --fail-on never and --allow-incomplete are for findings and for gaps; an untrusted adapter is neither.
    res = CliRunner().invoke(app, [*args, "--attest", "--fail-on", "never", "--allow-incomplete"])
    assert res.exit_code == 2 and "Mutation control: failed" in res.output


def test_mutation_probe_judging_is_strict():
    s = Scenario("i01", "input", "block", "fr", "u", "r", control=True, role="open")

    def probe(forced, observed, consulted=1, status=200):
        return C._mutation_probe(s, forced, {"observed": observed, "evidence": {
            "scanner_consulted_stage": consulted, "client_status": status}})["ok"]

    assert probe("allow", "passed") and not probe("allow", "stopped")
    assert probe("block", "stopped", status=400) and probe("block", "blocked after send")
    for bad in ("passed", "altered", "tool executed", "no answer", "transport failure", "failed after send"):
        assert not probe("block", bad), bad
    assert not probe("block", "stopped", status=500)       # a crash is not a block
    assert not probe("allow", "passed", consulted=0)       # the stand-in was never asked
    assert not probe("block", "stopped", consulted=0)


def test_demotion_only_ever_goes_to_unverified():
    s = Scenario("i04", "input", "error", "de", "u", "r")
    rows = [C.Result(s, "passed", "stopped", None, policy=p, documented=d)
            for p, d in (("held", "conforms"), ("violated", "deviates"), ("unverified", "unverified"))]
    C._demote_results(rows, "why")
    assert {(r.policy, r.documented) for r in rows} == {("unverified", "unverified")}
    assert [len(r.notes) for r in rows] == [1, 1, 0]       # an already-unverified row is left as it was
    dicts = [{"policy": p, "documented": "x", "evidence": {"owasp": ["LLM01"]}, "notes": []}
             for p in ("held", "violated", "n/a", "unverified")]
    C._demote_rows(dicts, "why")
    assert all(d["policy"] == "unverified" and d["evidence"]["owasp"] == [] for d in dicts[:3])
    assert POLICY["allow"] == "passed"   # (module imported intact)


# --------------------------------------------------------------------------- attestation
def test_the_receipt_names_the_reference_gateway_path_version_and_callers(tmp_path):
    run = run_contracts(ReferenceGateway(sys.executable, tmp_path, "strict"), 15, only={"i04"}, settle_s=0.3)
    cp = run["receipt"]["control_path"]
    gateway = Path(__file__).resolve().parent.parent / "examples" / "enforce" / "ref_gateway.py"
    from gcl import __version__
    from gcl.enforce.receipt import file_digest

    assert cp["control_module"]["path"] == str(gateway.resolve())
    assert cp["control_module"]["sha256"] == file_digest(gateway)["sha256"]
    assert __version__ in cp["control_module"]["version"]
    launched = [x["path"] for la in cp["launched"] for x in la["files"]]
    assert str(gateway.resolve()) in launched
    assert cp["target"]["exists"] and cp["target"]["path"] == str(Path(sys.executable).absolute())
    # The stand-in saw the gateway's own HTTP client, not gcl: who called is on the record.
    assert cp["scanner_peers"]["requests"] > 0 and cp["scanner_peers"]["user_agents"]
    # Attestation is descriptive: it adds no problem and no verdict change.
    assert not [p for p in run["receipt"]["problems"] if "mutation" in p or "control" in p]
    assert _states(run) == {"held"}


def test_a_stub_is_visible_in_the_receipt_but_attestation_alone_changes_no_verdict(tmp_path):
    run = run_contracts(_Sneaky(sys.executable, tmp_path), 5, only={"i04"}, settle_s=0.3)
    cp = run["receipt"]["control_path"]
    assert cp["control_module"] is None and cp["launched"] == [] and cp["packages"] == {}
    assert any("no process was launched" in n for n in cp["notes"])
    # It subclasses the reference adapter's identity but never launched the gateway: said so, not borrowed.
    assert cp["control_module_expected_not_launched"]["path"].endswith("ref_gateway.py")
    assert any("never launched" in n for n in cp["notes"])
    assert _states(run) == {"held"}   # visible, not demoted: only the mutation control demotes


def test_attestation_that_cannot_be_gathered_is_recorded_and_never_breaks_or_changes_a_run(tmp_path, monkeypatch):
    def boom(self, integration, config_files=None):
        raise RuntimeError("cannot read")

    monkeypatch.setattr(ReferenceGateway, "attest_control", boom)
    run = run_contracts(ReferenceGateway(sys.executable, tmp_path, "strict"), 15, only={"i04"}, settle_s=0.3)
    assert "cannot read" in run["receipt"]["control_path"]["error"]
    assert _states(run) == {"held"} and not [p for p in run["receipt"]["problems"] if "control" in p]


# --------------------------------------------------------------------------- replay
@pytest.fixture(scope="module")
def naive_bundle(tmp_path_factory):
    """A real finding: the naive gateway passes a scanner error through (input error, violated)."""
    base = tmp_path_factory.mktemp("bundle")
    run = run_contracts(ReferenceGateway(sys.executable, base / "work", "naive"), 15, only={"i04"}, settle_s=0.3)
    dirs = write_bundles(run, base / "out")
    d = next(p for p in dirs if p.name.endswith("i04-input-error"))
    return d


def _copy(src: Path, dst: Path) -> Path:
    shutil.copytree(src, dst)
    return dst


def _edit(d: Path, fn) -> Path:
    """Change finding.json and re-seal: a bundle that is intact but says something else."""
    f = json.loads((d / "finding.json").read_text(encoding="utf-8"))
    fn(f)
    (d / "finding.json").write_text(json.dumps(f), encoding="utf-8")
    seal_bundle(d)
    return d


def test_bundles_are_sealed_with_a_digest_per_file_and_what_replay_needs(naive_bundle):
    assert verify_seal(naive_bundle) == []
    f = json.loads((naive_bundle / "finding.json").read_text(encoding="utf-8"))
    assert f["replay"]["target"] == sys.executable and f["replay"]["extra"] == []
    assert f["replay"]["scenario_id"] == "i04"
    assert "finding.json" in json.loads((naive_bundle / MANIFEST).read_text())["files"]


def test_replay_reproduces_a_stored_reference_finding(naive_bundle):
    res = replay(naive_bundle)
    assert res["status"] == "reproduced", res
    assert res["stored"] == res["replayed"] == {"observed": "passed", "policy": "violated", "documented": "deviates"}
    assert all(c["ok"] for c in res["checks"])
    assert res["elapsed_s"] < 60


def test_replay_works_from_a_zip_too(naive_bundle, tmp_path):
    z = tmp_path / "finding.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for p in naive_bundle.iterdir():
            zf.write(p, f"{naive_bundle.name}/{p.name}")
    assert replay(z)["status"] == "reproduced"


def test_a_replay_that_comes_out_differently_is_not_reproduced_and_says_what_differed(naive_bundle, tmp_path):
    """Not a rubber stamp: a sealed bundle claiming the gateway stopped it, replayed on the real one."""
    d = _edit(_copy(naive_bundle, tmp_path / "b"), lambda f: f.update(
        observed="stopped", verdicts={"policy": "held", "documented": "conforms"}))
    res = replay(d)
    assert res["status"] == "not reproduced"
    assert "stored observed stopped" in res["reason"] and "replayed passed" in res["reason"]


@pytest.mark.parametrize("damage", ["edit", "delete finding", "remove seal", "add file", "edit seal"])
def test_a_tampered_or_incomplete_bundle_is_unverified_never_reproduced(naive_bundle, tmp_path, damage):
    d = _copy(naive_bundle, tmp_path / "b")
    if damage == "edit":
        (d / "finding.json").write_text((d / "finding.json").read_text() + " ", encoding="utf-8")
    elif damage == "delete finding":
        (d / "finding.json").unlink()
    elif damage == "remove seal":
        (d / MANIFEST).unlink()
    elif damage == "add file":
        (d / "config-extra.yaml").write_text("x", encoding="utf-8")
    else:
        m = json.loads((d / MANIFEST).read_text())
        m["bundle_sha256"] = "0" * 64
        (d / MANIFEST).write_text(json.dumps(m))
    res = replay(d)
    assert res["status"] == "unverified", res
    assert res["replayed"] is None and res["elapsed_s"] < 5   # refused before anything was started


def test_a_missing_bundle_and_an_unsafe_zip_are_unverified(tmp_path):
    assert replay(tmp_path / "nope")["status"] == "unverified"
    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("../escape/finding.json", "{}")
    res = replay(z)
    assert res["status"] == "unverified" and "unsafe" in res["reason"]
    assert not (tmp_path.parent / "escape").exists()


def test_a_bundle_whose_pins_or_environment_are_gone_is_unverified_without_guessing(naive_bundle, tmp_path):
    def not_installed(f):
        f["integration"]["install"] = {"dists": {"litellm": {"version": "1.99.0"}}}
        f["replay"]["target"] = str(tmp_path / "no-such-python")

    res = replay(_edit(_copy(naive_bundle, tmp_path / "a"), not_installed))
    assert res["status"] == "unverified" and "not available" in res["reason"] and "litellm" in res["reason"]

    def moved(f):
        f["receipt"]["control_path"]["control_module"]["sha256"] = "0" * 64

    res = replay(_edit(_copy(naive_bundle, tmp_path / "b"), moved))
    assert res["status"] == "unverified" and "pinned input changed" in res["reason"] and res["replayed"] is None

    res = replay(_edit(_copy(naive_bundle, tmp_path / "c"), lambda f: f["replay"].update(attack_mode=True)))
    assert res["status"] == "unverified" and "attack plan" in res["reason"]



def test_the_replay_command_exit_codes(naive_bundle, tmp_path):
    from typer.testing import CliRunner

    from gcl.cli import app

    runner = CliRunner()
    d = _copy(naive_bundle, tmp_path / "t")
    (d / "finding.json").write_text("{}", encoding="utf-8")
    bad = runner.invoke(app, ["replay", str(d)])
    assert bad.exit_code == 2 and "UNVERIFIED" in bad.output
    out = tmp_path / "r.json"
    ok = runner.invoke(app, ["replay", str(naive_bundle), "--out", str(out)])
    assert ok.exit_code == 0 and "REPRODUCED" in ok.output
    assert json.loads(out.read_text())["status"] == "reproduced"
    differs = _edit(_copy(naive_bundle, tmp_path / "x"), lambda f: f.update(
        observed="stopped", verdicts={"policy": "held", "documented": "conforms"}))
    assert runner.invoke(app, ["replay", str(differs)]).exit_code == 1
