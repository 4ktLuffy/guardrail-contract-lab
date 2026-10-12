"""LiteLLM's `--extra config` adapter, offline: the config it writes for each neutral policy and each
broken variant, the management API calls an edit makes, and the refusal to run an edit check without
a database. A real proxy is opt-in (GCL_INTEG_PYTHON, plus GCL_LITELLM_DATABASE_URL for the edits)."""
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from gcl.enforce import config_checks as cc
from gcl.enforce.adapters import CheckUnavailable, LiteLLMProxy
from gcl.enforce.contracts import run_contracts

SCANNERS = {"A": SimpleNamespace(base_for=lambda stage: f"http://127.0.0.1:1111/{stage}"),
            "B": SimpleNamespace(base_for=lambda stage: f"http://127.0.0.1:2222/{stage}")}
MODEL = SimpleNamespace(model="mock-1", openai_base="http://127.0.0.1:3333/v1")
INTEG = os.environ.get("GCL_INTEG_PYTHON")
DB = os.environ.get("GCL_LITELLM_DATABASE_URL")


def adapter(tmp_path, profile="default"):
    return LiteLLMProxy(sys.executable, tmp_path, profile)


def config(tmp_path, pol):
    return adapter(tmp_path)._policy_config(MODEL, SCANNERS, pol)


def test_plan_and_declarations(tmp_path):
    a = adapter(tmp_path)
    assert [(c.id, c.kind) for c in cc.plan(a)] == [
        ("k01", "load_failure:missing_file"), ("k02", "load_failure:unknown_guard"),
        ("k03", "load_failure:no_api_base"), ("k04", "load_failure:malformed_entry"),
        ("k05", "live_tighten:PATCH"), ("k06", "live_loosen:PATCH"),
        ("k07", "live_tighten:PUT"), ("k08", "live_loosen:PUT"), ("k09", "scope_in"), ("k10", "scope_out")]
    assert a.config_scopes == ("gcl-x", "gcl-y")


def test_a_global_guard_is_a_plain_default_on_guardrail_pointing_at_the_scanner(tmp_path):
    cfg = config(tmp_path, cc.policy("B"))
    assert [m["model_name"] for m in cfg["model_list"]] == ["gcl-x", "gcl-y"]
    assert {m["litellm_params"]["api_base"] for m in cfg["model_list"]} == {MODEL.openai_base}
    assert cfg["guardrails"] == [{"guardrail_name": "gcl-b", "litellm_params": {
        "guardrail": "generic_guardrail_api", "mode": "pre_call", "default_on": True,
        "api_base": "http://127.0.0.1:2222/input"}}]
    assert "policies" not in cfg and cfg["general_settings"]["master_key"] == "sk-gcl-master"
    assert config(tmp_path, cc.policy("A"))["guardrails"][0]["litellm_params"]["api_base"].endswith("1111/input")


def test_a_scoped_guard_is_a_policy_with_a_model_attachment_and_not_default_on(tmp_path):
    cfg = config(tmp_path, cc.policy("B", scope="gcl-x"))
    assert cfg["guardrails"][0]["litellm_params"]["default_on"] is False
    assert cfg["policies"] == {"policy-gcl-b": {"guardrails": {"add": ["gcl-b"]}}}
    assert cfg["policy_attachments"] == [{"policy": "policy-gcl-b", "models": ["gcl-x"]}]


@pytest.mark.parametrize("broken,check", [
    ("unknown_guard", lambda g: g["litellm_params"]["guardrail"] == "gcl-unknown-type"),
    ("no_api_base", lambda g: "api_base" not in g["litellm_params"]
     and g["litellm_params"]["guardrail"] == "generic_guardrail_api"),
    ("malformed_entry", lambda g: "litellm_params" not in g and g["guardrail_name"] == "gcl-b")])
def test_each_broken_variant_breaks_exactly_one_thing(tmp_path, broken, check):
    g = config(tmp_path, cc.policy("B", broken=broken))["guardrails"][0]
    assert check(g)


def test_an_editable_policy_has_no_guard_in_the_file(tmp_path):
    assert config(tmp_path, cc.policy("A", editable=True))["guardrails"] == []


def test_the_edit_checks_are_unavailable_without_a_database(tmp_path, monkeypatch):
    monkeypatch.delenv("GCL_LITELLM_DATABASE_URL", raising=False)
    with pytest.raises(CheckUnavailable, match="needs a database: set GCL_LITELLM_DATABASE_URL"):
        adapter(tmp_path).start_policy(MODEL, SCANNERS, cc.policy("A", editable=True))


def test_the_edit_checks_refuse_a_database_not_named_for_gcl(tmp_path, monkeypatch):
    # gcl deletes every guardrail in that database: a name without "gcl" may be someone's real one.
    monkeypatch.setenv("GCL_LITELLM_DATABASE_URL", "postgresql://u@localhost:5432/litellm_prod?sslmode=disable")
    with pytest.raises(CheckUnavailable, match=r"'litellm_prod'.*must contain 'gcl'"):
        adapter(tmp_path).start_policy(MODEL, SCANNERS, cc.policy("A", editable=True))


class FakeApi(LiteLLMProxy):
    """The management API, recorded: `table` is what the guardrail table holds."""

    def __init__(self, tmp_path, table=(), answer=(200, '{"ok": true}')):
        super().__init__(sys.executable, tmp_path, "default")
        self.calls, self.table, self.answer = [], list(table), answer
        self._scanners = SCANNERS
        self._guard_id, self._guard_name = "gid-1", "gcl-a"

    def _api(self, method, path, body=None, timeout_s=30.0):
        self.calls.append((method, path, body))
        if method == "GET":
            return 200, json.dumps({"guardrails": [{"guardrail_id": i, "guardrail_name": n} for i, n in self.table]})
        if method == "DELETE":
            self.table = [t for t in self.table if t[0] != path.rsplit("/", 1)[1]]
            return 200, "{}"
        if method == "POST":
            self.table.append(("gid-1", body["guardrail"]["guardrail_name"]))
            return 200, '{"guardrail_id": "gid-1"}'
        return self.answer


def test_patch_and_put_bodies_move_api_base_to_the_new_scanner(tmp_path):
    a = FakeApi(tmp_path)
    new = cc.policy("B", editable=True)
    r = a.edit_policy(new, "PATCH")
    params = {"guardrail": "generic_guardrail_api", "mode": "pre_call", "default_on": True,
              "api_base": "http://127.0.0.1:2222/input"}
    assert a.calls[-1] == ("PATCH", "/guardrails/gid-1", {"litellm_params": params})
    assert r["acknowledged"] and r["detail"].startswith("HTTP 200")
    a.edit_policy(new, "PUT")
    assert a.calls[-1] == ("PUT", "/guardrails/gid-1",
                           {"guardrail": {"guardrail_name": "gcl-a", "litellm_params": params}})


def test_a_422_is_a_rejected_edit(tmp_path):
    r = FakeApi(tmp_path, answer=(422, '{"detail": "Invalid guardrail configuration"}')).edit_policy(
        cc.policy("B", editable=True), "PUT")
    assert r["acknowledged"] is False and "HTTP 422" in r["detail"]


def test_each_start_clears_the_table_and_proves_it_holds_only_the_check_guardrail(tmp_path):
    a = FakeApi(tmp_path, table=[("old-1", "left-over"), ("old-2", "gcl-b")])
    a._seed_guardrail(cc.policy("A")["guards"][0], SCANNERS)
    assert [c[:2] for c in a.calls if c[0] == "DELETE"] == [("DELETE", "/guardrails/old-1"),
                                                              ("DELETE", "/guardrails/old-2")]
    assert a.table == [("gid-1", "gcl-a")] and a._guard_id == "gid-1"


def test_a_table_that_cannot_be_proven_clean_makes_the_check_unavailable(tmp_path):
    class Stubborn(FakeApi):
        def _api(self, method, path, body=None, timeout_s=30.0):
            if method == "DELETE":
                return 500, "boom"
            return super()._api(method, path, body, timeout_s)

    with pytest.raises(CheckUnavailable, match="could not clear"):
        Stubborn(tmp_path, table=[("old-1", "x")])._seed_guardrail(cc.policy("A")["guards"][0], SCANNERS)


def test_only_the_scope_expectation_is_documented(tmp_path):
    a = adapter(tmp_path)
    assert cc.documented_for(a, "scope_in") == ["stopped"]
    assert all(cc.documented_for(a, k) is None
               for k in ("scope_out", "live_tighten:PATCH", "live_loosen:PUT", "load_failure:unknown_guard"))
    src = a.config_documented_sources["default"][0]
    assert src["read_for"].startswith("litellm 1.105.0") and "read 2026-10-12" in src["read_for"]


@pytest.mark.skipif(not INTEG, reason="set GCL_INTEG_PYTHON to run a real LiteLLM proxy")
def test_real_litellm_controls_and_scope(tmp_path):
    ids = {"k01", "k02", "k03", "k04", "k09", "k10"}
    run = run_contracts(LiteLLMProxy(INTEG, Path(tmp_path), "default"), 60, extra=("config",),
                        only={"none", *ids})
    res = {r["scenario"]["id"]: r for r in run["results"] if r["scenario"]["mode"] == "config"}
    assert res["k00c"]["policy"] == "held", res["k00c"]["notes"]
    assert res["k09"]["policy"] == "held" and res["k10"]["policy"] == "held"
    assert all(res[k]["policy"] in ("held", "violated") for k in ids)   # never "unverified": the setup works


@pytest.mark.skipif(not (INTEG and DB), reason="set GCL_INTEG_PYTHON and GCL_LITELLM_DATABASE_URL")
def test_real_litellm_live_edit_gets_a_verdict_for_both_routes(tmp_path):
    ids = {"k05", "k06", "k07", "k08"}
    run = run_contracts(LiteLLMProxy(INTEG, Path(tmp_path), "default"), 60, extra=("config",),
                        only={"none", *ids})
    res = {r["scenario"]["id"]: r for r in run["results"] if r["scenario"]["mode"] == "config"}
    assert res["k00c"]["policy"] == "held"
    assert {res[k]["policy"] for k in ids} <= {"held", "violated", "n/a"}   # a verdict, never unverified


def test_log_evidence_keeps_the_lines_a_hand_check_needs(tmp_path):
    log = tmp_path / "x.log"
    log.write_text("\n".join([
        "banner", "13:37:08 - LiteLLM:WARNING: register_model: model=x not in built-in cost map",
        '  File "frame.py", line 1, in apply_guardrail',
        "INFO:     127.0.0.1:1 - \"PUT /guardrails/ab HTTP/1.1\" 200 OK",
        "13:37:10 - LiteLLM Proxy:WARNING: Immediate sync: Failed to update 'gcl-a' in memory"]))
    got = cc._log_evidence(log).splitlines()
    assert got == ['INFO:     127.0.0.1:1 - "PUT /guardrails/ab HTTP/1.1" 200 OK',
                   "13:37:10 - LiteLLM Proxy:WARNING: Immediate sync: Failed to update 'gcl-a' in memory"]


def test_a_refusal_tail_shows_why_the_process_stopped_even_when_a_banner_follows(tmp_path):
    from gcl.enforce.adapters import _refusal_tail
    log = tmp_path / "x.log"
    log.write_text("ValueError: Unsupported guardrail: gcl-unknown-type\n" + "banner\n" * 30)
    assert "Unsupported guardrail" in _refusal_tail(log)
