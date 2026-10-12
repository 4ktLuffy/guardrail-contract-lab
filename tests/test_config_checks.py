"""Config applied (`--extra config`): the verdict logic on synthetic probes, then the reference gateway
end to end. Profile strict keeps the policy-file contract (every check held); profile naive breaks it
the way real issues do (a policy that fails to load allows everything, edits are ignored, a scoped
guard matches nothing), which is also the proof that the checks can go red."""
import json
import sys
from pathlib import Path
from typing import ClassVar

import pytest

from gcl.cli import _enforce_exit
from gcl.enforce import config_checks as cc
from gcl.enforce.adapters import ADAPTERS, Observation, ReferenceGateway, StartRefused
from gcl.enforce.contracts import run_contracts
from gcl.enforce.servers import MockModel

REF = ReferenceGateway(sys.executable, Path("."), "strict")
IDS = [c.id for c in cc.plan(REF)]
ONLY = {"none", *IDS}   # the ordinary plan shrinks to its opening controls: the config phase is the subject
ROOT = Path(__file__).resolve().parent.parent


def P(outcome, a=0, b=0, scope="gcl-x"):
    """A synthetic probe."""
    return {"sentinel": "GCL-K-t-run", "scope": scope, "client_status": 200, "client_error": "",
            "client_complete": outcome != "no answer", "model_received": outcome == "passed",
            "consulted": {"A": a, "B": b}, "outcome": outcome}


# --------------------------------------------------------------------------- verdict logic
def test_outcome_needs_a_complete_answer_to_call_it_stopped():
    assert cc.outcome_of(True, False) == "stopped"
    assert cc.outcome_of(False, False) == "no answer"   # a timeout is not a stop
    assert cc.outcome_of(False, True) == "passed"       # the provider got it, whatever the client saw


def test_controls_hold_only_with_the_scanners_receipt():
    ok, why = cc.judge_controls(P("stopped", b=1), [P("passed", a=1), P("passed", a=1, scope="gcl-y")])
    assert ok and not why
    ok, why = cc.judge_controls(P("stopped", b=0), [P("passed", a=1), P("passed", a=1, scope="gcl-y")])
    assert not ok and "B consulted" in why[0]            # stopped by something else
    ok, why = cc.judge_controls(P("stopped", b=1), [P("passed", a=1), P("passed", a=0, scope="gcl-y")])
    assert not ok and "gcl-y" in why[0]
    assert not cc.judge_controls(None, [])[0]


def test_load_failure_verdicts():
    assert cc.judge_load(True, None)[:2] == ("refused to start", "held")
    assert cc.judge_load(False, P("stopped"))[1] == "held"
    obs, pol, notes = cc.judge_load(False, P("passed"))
    assert (obs, pol) == ("passed", "violated") and "everything allowed" in notes[0]
    assert "B was consulted" in cc.judge_load(False, P("passed", b=1))[2][0]
    assert cc.judge_load(False, P("no answer"))[1] == "unverified"


def test_tighten_verdicts():
    pre, ack = P("passed", a=1), {"acknowledged": True, "mechanism": "m", "detail": "d"}
    assert cc.judge_edit("tighten", pre, ack, P("stopped", b=1))[:2] == ("stopped", "held")
    obs, pol, notes = cc.judge_edit("tighten", pre, ack, P("passed", a=1))
    assert (obs, pol) == ("passed", "violated")
    assert "old policy kept running" in notes[0] and "worst case" in notes[0]
    assert cc.judge_edit("tighten", pre, ack, P("stopped", b=0))[1] == "unverified"   # stopped by what?
    assert cc.judge_edit("tighten", pre, ack, P("no answer"))[1] == "unverified"
    assert cc.judge_edit("tighten", pre, {"acknowledged": False, "detail": "HTTP 409"}, None)[:2] == \
        ("edit rejected", "n/a")
    assert cc.judge_edit("tighten", P("passed", a=0), ack, None)[1] == "unverified"   # its own control failed
    assert cc.judge_edit("tighten", P("stopped", b=1), ack, None)[1] == "unverified"


def test_loosen_verdicts_and_a_stricter_than_configured_outcome():
    pre, ack = P("stopped", b=1), {"acknowledged": True, "mechanism": "m", "detail": "d"}
    assert cc.judge_edit("loosen", pre, ack, P("passed", a=1))[:2] == ("passed", "held")
    obs, pol, notes = cc.judge_edit("loosen", pre, ack, P("stopped", b=1))
    assert (obs, pol) == ("stopped", "violated") and "not a leak" in notes[0]
    assert cc.judge_edit("loosen", pre, ack, P("passed", a=0))[1] == "unverified"
    assert cc.judge_edit("loosen", P("passed", a=1), ack, None)[1] == "unverified"


def test_scope_verdicts():
    assert cc.judge_scope("in", P("stopped", b=1))[:2] == ("stopped", "held")
    obs, pol, notes = cc.judge_scope("in", P("passed"))
    assert (obs, pol) == ("passed", "violated") and "did not apply to its scope" in notes[0]
    assert cc.judge_scope("in", P("stopped", b=0))[1] == "unverified"
    assert cc.judge_scope("out", P("passed", b=0, scope="gcl-y"))[1] == "held"
    assert cc.judge_scope("out", P("stopped", b=1, scope="gcl-y"))[1] == "violated"
    assert cc.judge_scope("out", P("passed", b=1, scope="gcl-y"))[1] == "violated"
    obs, pol, notes = cc.judge_scope("out", P("stopped", b=0))   # stopped by something else: not proof
    assert (obs, pol) == ("stopped", "unverified") and "something else stopped it" in notes[0]
    assert cc.judge_scope("out", P("no answer"))[1] == "unverified"


def test_owasp_tags_only_where_something_leaked():
    leaks = {"load_failure:missing", "load_failure:malformed", "load_failure:unknown_guard",
             "live_tighten:file", "scope_in"}
    checks = cc.plan(REF)
    assert {c.kind for c in checks} - leaks == {"live_loosen:file", "scope_out"}
    for c in checks:
        d = cc._result(c, "abc123", "GCL-K-x", "passed", "violated", cc._evidence({}, []), [])
        assert bool(d["evidence"]["owasp"]) == (c.kind in leaks), c.kind
        assert d["evidence"]["check"] == c.kind
    held = cc._result(checks[0], "abc123", "GCL-K-x", "stopped", "held", cc._evidence({}, []), [])
    assert held["evidence"]["owasp"] == []


def test_the_plan_follows_what_the_adapter_declares():
    assert [(c.id, c.kind) for c in cc.plan(REF)] == [
        ("k01", "load_failure:missing"), ("k02", "load_failure:malformed"), ("k03", "load_failure:unknown_guard"),
        ("k04", "live_tighten:file"), ("k05", "live_loosen:file"), ("k06", "scope_in"), ("k07", "scope_out")]

    class Two(ReferenceGateway):
        load_failures: ClassVar[dict] = {"no_api_base": "no api_base"}
        edit_mechanisms: ClassVar[tuple] = ("PATCH", "PUT")

    assert [(c.id, c.kind) for c in cc.plan(Two(sys.executable, Path("."), "strict"))] == [
        ("k01", "load_failure:no_api_base"), ("k02", "live_tighten:PATCH"), ("k03", "live_loosen:PATCH"),
        ("k04", "live_tighten:PUT"), ("k05", "live_loosen:PUT"), ("k06", "scope_in"), ("k07", "scope_out")]


def test_the_filter_selects_checks_and_a_filter_naming_none_selects_nothing():
    assert [c.id for c in cc.selected(REF, None)] == IDS
    assert [c.id for c in cc.selected(REF, {"k04", "none"})] == ["k04"]
    assert cc.selected(REF, {"none"}) == []


# --------------------------------------------------------------------------- the reference gateway
def _by_id(run):
    return {r["scenario"]["id"]: r for r in run["results"] if r["scenario"]["mode"] == "config"}


@pytest.fixture(scope="module")
def strict(tmp_path_factory):
    return run_contracts(ReferenceGateway(sys.executable, tmp_path_factory.mktemp("s"), "strict"), 10,
                         extra=("config",), only=ONLY, settle_s=0.2)


@pytest.fixture(scope="module")
def naive(tmp_path_factory):
    return run_contracts(ReferenceGateway(sys.executable, tmp_path_factory.mktemp("n"), "naive"), 10,
                         extra=("config",), only=ONLY, settle_s=0.2)


def test_strict_holds_every_config_check(strict):
    res = _by_id(strict)
    assert set(res) == {"k00c", *IDS}
    assert {k: r["policy"] for k, r in res.items()} == {k: "held" for k in res}
    assert strict["config_checks"]["summary"] == {"checks": 7, "held": 7, "violated": 0, "unverified": 0,
                                                  "n/a": 0, "controls": "held"}
    assert strict["summary"]["policy_violated"] == 0 and strict["summary"]["unverified"] == 0
    assert _enforce_exit(strict["summary"], "policy", False) == 0


def test_strict_evidence_names_who_was_asked(strict):
    res = _by_id(strict)
    assert res["k01"]["observed"] == "refused to start" and res["k01"]["evidence"]["start"] == "refused"
    assert "policy file" in res["k01"]["evidence"]["log_tail"] or res["k01"]["evidence"]["log_tail"]
    k04 = res["k04"]["evidence"]
    assert k04["edit"]["acknowledged"] and k04["edit"]["mechanism"] == "policy file rewrite"
    assert [p["outcome"] for p in k04["probes"]] == ["passed", "stopped"]
    assert k04["scanner_b_consulted"] == 1 and not k04["model_received"]
    k07 = res["k07"]["evidence"]
    assert k07["scanner_b_consulted"] == 0 and k07["model_received"]
    assert res["k07"]["evidence"]["probes"][0]["scope"] == "gcl-y"
    assert res["k06"]["scenario"]["user_sentinel"].startswith("GCL-K-k06-")


def test_naive_breaks_the_configured_policy_contract(naive):
    res = _by_id(naive)
    assert res["k00c"]["policy"] == "held"                       # the controls hold: the reds are real
    assert {k: res[k]["policy"] for k in IDS} == {"k01": "violated", "k02": "violated", "k03": "violated",
                                                  "k04": "violated", "k05": "violated", "k06": "violated",
                                                  "k07": "held"}
    assert "everything allowed" in res["k01"]["notes"][0]
    assert "old policy kept running" in res["k04"]["notes"][0]
    assert res["k05"]["observed"] == "stopped" and "not a leak" in res["k05"]["notes"][0]
    assert res["k05"]["evidence"]["owasp"] == []                  # stricter than configured: no leak
    assert res["k04"]["evidence"]["owasp"] and res["k06"]["evidence"]["owasp"]
    assert naive["config_checks"]["summary"]["violated"] == 6
    assert naive["summary"]["policy_violated"] == 6
    assert _enforce_exit(naive["summary"], "policy", False) == 1


def test_a_broken_control_makes_every_check_unverified_never_held(tmp_path):
    class Silent(ReferenceGateway):
        """Every probe is answered 200 without the request reaching the gateway: the controls cannot hold."""
        def call_scope(self, scope, messages, timeout_s):
            return Observation(200, "{}", True, 0.0)

    with MockModel("ok") as model:
        res = cc.run_config(Silent(sys.executable, tmp_path, "strict"), model, "abc123", 5)
    assert [r["scenario"]["id"] for r in res] == ["k00c", *IDS]
    assert all(r["policy"] == "unverified" for r in res), [(r["scenario"]["id"], r["policy"]) for r in res]
    assert "controls did not hold" in res[1]["notes"][0]
    assert cc.summarize(res)["held"] == 0


def test_one_check_that_fails_is_unverified_and_the_others_still_run(tmp_path):
    class Flaky(ReferenceGateway):
        def edit_policy(self, policy, mechanism):
            raise OSError("management API down")

    with MockModel("ok") as model:
        res = {r["scenario"]["id"]: r for r in cc.run_config(Flaky(sys.executable, tmp_path, "strict"), model,
                                                              "abc123", 5, only={"k04", "k07"})}
    assert res["k04"]["policy"] == "unverified" and "management API down" in res["k04"]["notes"][0]
    assert res["k07"]["policy"] == "held"


def test_a_rejected_edit_is_not_a_violation(tmp_path):
    class Rejecting(ReferenceGateway):
        def edit_policy(self, policy, mechanism):
            return {"mechanism": "management API", "acknowledged": False, "detail": "HTTP 409 conflict"}

    with MockModel("ok") as model:
        res = {r["scenario"]["id"]: r for r in cc.run_config(Rejecting(sys.executable, tmp_path, "naive"), model,
                                                              "abc123", 5, only={"k04"})}
    assert (res["k04"]["observed"], res["k04"]["policy"]) == ("edit rejected", "n/a")
    assert "HTTP 409" in res["k04"]["notes"][0]


def test_a_check_the_adapter_cannot_run_is_unverified_with_the_reason(tmp_path):
    from gcl.enforce.adapters import CheckUnavailable

    class NoDatabase(ReferenceGateway):
        def start_policy(self, model, scanners, policy):
            if policy["guards"][0]["scope"] != "*":
                raise CheckUnavailable("needs a database URL")
            super().start_policy(model, scanners, policy)

    with MockModel("ok") as model:
        res = {r["scenario"]["id"]: r for r in cc.run_config(NoDatabase(sys.executable, tmp_path, "strict"), model,
                                                              "abc123", 5, only={"k01", "k06"})}
    assert res["k01"]["policy"] == "held"
    assert (res["k06"]["policy"], res["k06"]["observed"]) == ("unverified", "unavailable")
    assert "needs a database URL" in res["k06"]["notes"][0]


def test_an_adapter_without_a_property_gets_no_checks_for_it(tmp_path):
    class LoadOnly(ReferenceGateway):
        config_checks = ("load_failure",)

    assert [c.kind for c in cc.plan(LoadOnly(sys.executable, tmp_path, "strict"))] == [
        "load_failure:missing", "load_failure:malformed", "load_failure:unknown_guard"]


def test_start_refused_is_not_a_gcl_error(tmp_path):
    adapter = ReferenceGateway(sys.executable, tmp_path, "strict")
    with MockModel("ok") as model, pytest.raises(StartRefused) as e:
        adapter.start_policy(model, {}, {"guards": [], "broken": "missing"})
    assert not isinstance(e.value, RuntimeError) and "policy file" in e.value.log_tail


# --------------------------------------------------------------------------- refusal, reports
def test_an_adapter_without_config_support_refuses_the_extra(tmp_path):
    supported = {n for n, a in ADAPTERS.items() if a.config_checks}
    assert supported == {"reference", "litellm"}
    with pytest.raises(ValueError, match=r"--extra config.*reference"):
        run_contracts(ADAPTERS["reference-mcp"](sys.executable, tmp_path, "strict"), 5, extra=("config",))


def test_the_cli_refuses_the_extra_and_lists_the_adapters_that_have_it():
    from typer.testing import CliRunner

    from gcl.cli import app

    res = CliRunner().invoke(app, ["enforce", "reference-mcp", "--python", sys.executable, "--profile", "strict",
                                   "--extra", "config"])
    assert res.exit_code == 2
    assert "config checks run on: litellm, reference" in res.output.replace("\n", " ").replace("│", "")


def test_the_naive_run_exits_1_and_renders_in_every_report(tmp_path):
    from typer.testing import CliRunner

    from gcl.cli import app

    out = tmp_path / "out"
    res = CliRunner().invoke(app, ["enforce", "reference", "--python", sys.executable, "--profile", "naive",
                                   "--timeout", "10", "--extra", "config", "--scenario", "k01", "--scenario", "k05",
                                   "--scenario", "k07", "--format", "json,html,sarif", "--out", str(out)])
    assert res.exit_code == 1, res.output
    assert "Config applied: 1 held, 2 violated" in res.output and "k05" in res.output
    doc = json.loads((out / "report.json").read_text())
    assert doc["enforce"]["config_checks"]["summary"]["violated"] == 2
    assert "Config applied" in (out / "report.html").read_text()
    sarif = json.loads((out / "report.sarif").read_text())
    rules = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert {"GCL-E-config-k01", "GCL-E-config-k05"} <= rules
    assert "--extra config" in next(out.glob("repro/*/REPLAY.txt")).read_text()
    from gcl.compare import compare

    cmp = compare(out / "report.json", out / "report.json")
    assert cmp["regressions"] == cmp["only_old"] == cmp["only_new"] == []


# --------------------------------------------------------------------------- documented verdict, severity, OWASP
def test_documented_verdict_follows_the_adapters_expectation():
    checks = {c.kind: c for c in cc.plan(REF)}
    ev = cc._evidence({}, [])
    exp = lambda kind: cc.documented_for(REF, kind)  # noqa: E731
    assert exp("load_failure:missing") == ["refused to start", "stopped"] and exp("scope_out") == ["passed"]
    d = cc._result(checks["scope_in"], "r", "s", "passed", "violated", ev, [], exp("scope_in"))
    assert d["documented"] == "deviates" and d["documented_expect"] == ["stopped"]
    d = cc._result(checks["scope_in"], "r", "s", "stopped", "held", ev, [], exp("scope_in"))
    assert d["documented"] == "conforms"
    d = cc._result(checks["scope_in"], "r", "s", "no answer", "unverified", ev, [], exp("scope_in"))
    assert d["documented"] == "unverified"
    d = cc._result(checks["live_tighten:file"], "r", "s", "edit rejected", "n/a", ev, [], ["stopped"])
    assert d["documented"] == "n/a"
    d = cc._result(checks["scope_in"], "r", "s", "passed", "violated", ev, [], None)   # the docs say nothing
    assert d["documented"] == "unspecified" and "not covered" in d["notes"][-1]


def test_a_full_kind_beats_its_prefix_and_a_missing_kind_is_unspecified():
    class Docs(ReferenceGateway):
        config_documented: ClassVar[dict] = {"strict": {"live_tighten": "stopped", "live_tighten:PUT": "passed"}}

    a = Docs(sys.executable, Path("."), "strict")
    assert cc.documented_for(a, "live_tighten:PATCH") == ["stopped"]
    assert cc.documented_for(a, "live_tighten:PUT") == ["passed"]
    assert cc.documented_for(a, "scope_in") is None


def test_the_reference_runs_carry_documented_verdicts_and_the_source(strict, naive):
    assert {r["documented"] for r in _by_id(strict).values() if not r["scenario"]["role"]} == {"conforms"}
    assert _by_id(strict)["k00c"]["documented"] == "unspecified"
    nv = _by_id(naive)
    assert nv["k01"]["documented"] == "deviates" and nv["k07"]["documented"] == "conforms"
    assert strict["integration"]["config_documented_source"][0]["source"].startswith("examples/enforce/ref_gateway")


def test_config_severity_and_owasp_mapping():
    from gcl.severity import TRIGGER_POINTS, trigger_of
    from gcl.standards import config_risks

    assert trigger_of("config") == "configuration not applied" and TRIGGER_POINTS["configuration not applied"] == 0
    assert trigger_of("policy_missing") == "operator misconfiguration"
    assert config_risks("load_failure:missing") == ["LLM01:2025", "ASI08:2026"]
    assert config_risks("live_tighten:PATCH") == ["LLM01:2025"] and config_risks("scope_in") == ["LLM01:2025"]
    assert config_risks("scope_out") == config_risks("live_loosen:PUT") == []
