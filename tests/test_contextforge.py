"""IBM ContextForge adapter: what needs no install (generated config, names, stage inference,
the guard plugin's protocol), plus one opt-in run against a real install.

Set GCL_INTEG_CONTEXTFORGE_PYTHON to the python of an environment with
`mcp-contextforge-gateway` installed (tested with 1.0.11) to run the real one.
"""

import importlib.util
import json
import os
import sys
import types
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from gcl.enforce.adapters import (
    ADAPTERS,
    CONTEXTFORGE_PROFILES,
    CONTEXTFORGE_SCAN,
    ContextForgeMCP,
    _driver_path,
    _slug,
)
from gcl.enforce.contracts import build_scenarios, run_contracts
from gcl.enforce.servers import MockModel, StandInScanner, null_expressible
from gcl.standards import MCP_INTEGRATIONS

PY = os.environ.get("GCL_INTEG_CONTEXTFORGE_PYTHON")


def _post(url, obj):
    r = urllib.request.urlopen(urllib.request.Request(url, data=json.dumps(obj).encode()), timeout=3)
    return json.loads(r.read())


def test_registered_and_listed_as_an_mcp_integration():
    assert ADAPTERS["contextforge"] is ContextForgeMCP
    assert "contextforge" in MCP_INTEGRATIONS
    assert ContextForgeMCP.mcp_transport == "http" and ContextForgeMCP.capabilities == {"input", "output", "retry"}
    assert ContextForgeMCP.harness_supplies_guard


def test_unknown_profile_is_refused(tmp_path):
    with pytest.raises(ValueError, match="unknown contextforge profile"):
        ContextForgeMCP(sys.executable, tmp_path, "banana")


@pytest.mark.parametrize("profile", sorted(CONTEXTFORGE_PROFILES))
def test_plugin_config_per_profile(tmp_path, profile):
    ad = ContextForgeMCP(sys.executable, tmp_path, profile)
    with StandInScanner(ad.protocol) as sc:
        cfg = ad._plugins_yaml(sc)
        (entry,) = cfg["plugins"]
        assert entry["kind"] == "contextforge_plugin.GclScanPlugin"
        assert {"tool_pre_invoke", "tool_post_invoke", "prompt_pre_fetch", "prompt_post_fetch",
                "resource_pre_fetch", "resource_post_fetch"} == set(entry["hooks"])
        # One listener per stage, so the stand-in tells input from output by where the plugin asks.
        assert entry["config"]["input_url"] == f"{sc.base_for('input')}/scan"
        assert entry["config"]["output_url"] == f"{sc.base_for('output')}/scan"
        assert entry["config"]["input_url"] != entry["config"]["output_url"]
    # Only the profile's own keys are set; everything else stays ContextForge's default.
    for key in ("mode", "on_error"):
        assert entry.get(key) == CONTEXTFORGE_PROFILES[profile]["plugin"].get(key)
    json.dumps(cfg)  # written as JSON, which YAML reads


def test_profiles_have_documented_expectations_with_sources():
    assert set(ContextForgeMCP.documented) == set(CONTEXTFORGE_PROFILES) == set(ContextForgeMCP.documented_sources)
    for p, src in ContextForgeMCP.documented_sources.items():
        assert src["read_for"].endswith("1.0.11") and src["passage"] and src["source"]
        assert ContextForgeMCP.documented[p]["allow"] == "passed"
    assert ContextForgeMCP.documented["default"]["error"] == "stopped"
    assert ContextForgeMCP.documented["ignore_error"]["error"] == "passed"
    assert ContextForgeMCP.documented["ignore_error"]["block"] == "stopped"
    assert ContextForgeMCP.documented["permissive"]["block"] == "passed"
    assert "conflicts" in ContextForgeMCP.documented_sources["default"]["passage"]


def test_names_clients_use_at_the_gateway(tmp_path):
    ad = ContextForgeMCP(sys.executable, tmp_path)
    assert ad.mcp_name("tool", "gcl_probe") == "gcl-gcl-probe"
    assert ad.mcp_name("tool", "gcl_hidden") == "gcl-gcl-hidden"
    assert ad.mcp_name("prompt", "gcl_prompt") == "gcl-gcl-prompt"
    assert ad.mcp_name("resource", "gcl://note") == "gcl://note"
    assert _slug("Gcl__Probe v2") == "gcl-probe-v2"


def test_stage_comes_from_the_hook_and_the_listener_must_agree():
    stage = CONTEXTFORGE_SCAN.stage_of
    for hook in ("tool_pre_invoke", "prompt_pre_fetch", "resource_pre_fetch"):
        assert stage({"hook": hook}) == "input"
    for hook in ("tool_post_invoke", "prompt_post_fetch", "resource_post_fetch"):
        assert stage({"hook": hook}) == "output"
    assert stage({"hook": "agent_pre_invoke_x"}) is None and stage({}) is None


def test_standin_answers_the_plugins_protocol_per_stage():
    path = CONTEXTFORGE_SCAN.path
    with StandInScanner(CONTEXTFORGE_SCAN) as sc:
        sc.configure({"input": "allow", "output": "block"})
        pre = {"hook": "tool_pre_invoke", "texts": ["note", "GCL-C-m14-x"]}
        post = {"hook": "resource_post_fetch", "texts": ["GCL-C-m09-x"]}
        assert _post(sc.base_for("input") + path, pre) == {"verdict": "ALLOW"}
        assert _post(sc.base_for("output") + path, post)["verdict"] == "BLOCK"
        # A post hook asking the input listener (or the reverse) is a wiring error, not a consultation.
        with pytest.raises(urllib.error.HTTPError):
            _post(sc.base_for("input") + path, post)
        assert sc.consulted("input") == 1 and sc.consulted("output") == 1
        # Surface traffic: blocks exactly the text that carries an attack marker.
        sc.configure({"input": "surface_block", "output": "surface_block"})
        assert _post(sc.base_for("input") + path, {"hook": "prompt_pre_fetch", "texts": ["GCL-C-m10-x"]}
                     )["verdict"] == "ALLOW"
        assert _post(sc.base_for("input") + path, {"hook": "prompt_pre_fetch", "texts": ["GCL-A-m10-x"]}
                     )["verdict"] == "BLOCK"
        assert sc.events[-1]["scanned"] == "GCL-A-m10-x"


def test_protocol_can_express_every_fault_including_type_and_null():
    assert null_expressible(CONTEXTFORGE_SCAN)
    sc = build_scenarios(ContextForgeMCP(sys.executable, Path("/tmp")))
    modes = {(s.stage, s.mode) for s in sc}
    assert {("input", "verdict_type"), ("output", "verdict_type"), ("input", "block_retry"),
            ("input", "null_verdict"), ("output", "timeout")} <= modes


def _load_plugin_with_stub_framework(monkeypatch):
    """The plugin module needs cpex, which gcl does not install: load it against stand-in classes."""
    fw = types.ModuleType("cpex.framework")

    class _Plain:
        def __init__(self, *a, **kw):
            self.__dict__.update(kw)

    for name in ("PluginConfig", "PluginContext", "PluginViolation", "PromptPosthookResult", "PromptPrehookResult",
                 "ResourcePostFetchResult", "ResourcePreFetchResult", "ToolPostInvokeResult", "ToolPreInvokeResult"):
        setattr(fw, name, type(name, (_Plain,), {}))
    fw.Plugin = type("Plugin", (), {"__init__": lambda self, config: setattr(self, "config", config)})
    monkeypatch.setitem(sys.modules, "cpex", types.ModuleType("cpex"))
    monkeypatch.setitem(sys.modules, "cpex.framework", fw)
    spec = importlib.util.spec_from_file_location("contextforge_plugin_under_test",
                                                  _driver_path("contextforge_plugin.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_plugin_sends_every_string_and_accepts_only_its_two_verdicts(monkeypatch):
    mod = _load_plugin_with_stub_framework(monkeypatch)

    class Model:
        def __init__(self, d):
            self.d = d

        def model_dump(self, mode="json"):
            return self.d

    payload = Model({"name": "t", "result": {"content": [{"type": "text", "text": "hello GCL-C-m01-x"}], "n": 3}})
    assert mod.strings(payload) == ["name", "t", "result", "content", "type", "text", "text", "hello GCL-C-m01-x", "n"]
    path = CONTEXTFORGE_SCAN.path
    with StandInScanner(CONTEXTFORGE_SCAN) as sc:
        url = sc.base_for("output") + path
        sc.configure({"output": "allow"})
        assert mod.ask(url, "tool_post_invoke", payload) is None
        sc.configure({"output": "block"})
        assert mod.ask(url, "tool_post_invoke", payload)["reason"].startswith("GCL-BLOCKED")
        for fault in ("unknown_verdict", "verdict_type", "null_verdict", "wrong_schema"):
            sc.configure({"output": fault})
            with pytest.raises(RuntimeError, match="unrecognised scanner verdict"):
                mod.ask(url, "tool_post_invoke", payload)
        sc.configure({"output": "error"})
        with pytest.raises(urllib.error.HTTPError):
            mod.ask(url, "tool_post_invoke", payload)
        sent = [e["body"]["hook"] for e in sc.events]
        assert set(sent) == {"tool_post_invoke"}


def test_mock_backend_is_what_gets_registered(tmp_path):
    """The registry is filled from the mock's /mcp; a surface or payload change is a new state."""
    ad = ContextForgeMCP(sys.executable, tmp_path)
    with MockModel("Noted.") as m:
        ad._model = m
        assert ad._mock_state() == (None, "")
        m.set_mcp_surface("m06", "GCL-C-m06-x")
        assert ad._mock_state() == ("m06", "GCL-C-m06-x")
        ad._synced = ("m06", "GCL-C-m06-x")
        m.set_mcp_surface("m06", "GCL-A-m06-x")
        assert ad._mock_state() != ad._synced


@pytest.mark.skipif(not PY, reason="set GCL_INTEG_CONTEXTFORGE_PYTHON to run ContextForge")
@pytest.mark.parametrize("profile", ["default", "ignore_error"])
def test_real_contextforge_controls_hold(tmp_path, profile):
    run = run_contracts(ADAPTERS["contextforge"](PY, tmp_path, profile), 60)
    for r in run["results"]:
        if r["scenario"]["control"] and r["scenario"]["mode"] in ("allow", "block"):
            assert r["policy"] == "held", (r["scenario"]["stage"], r["scenario"]["mode"], r["notes"])
    assert run["summary"]["scenarios"] > 4
