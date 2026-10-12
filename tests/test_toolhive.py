"""Stacklok ToolHive adapter: what needs no binary (generated webhook config, the webhook protocol the
stand-in speaks, the stages the plan covers, where ToolHive's state goes), plus one opt-in run
against a real `thv`.

Set GCL_INTEG_TOOLHIVE to the path of a `thv` binary (tested with v0.51.4) to run the real one. ToolHive
needs a container runtime to exist; it is found from TOOLHIVE_DOCKER_SOCKET, DOCKER_HOST or the current
docker context. No container is started and no image is pulled.
"""

import json
import os
import urllib.error
import urllib.request

import pytest

from gcl.enforce.adapters import ADAPTERS, TOOLHIVE_PROFILES, TOOLHIVE_WEBHOOK, ToolHiveMCP, _docker_socket, _thv_binary
from gcl.enforce.contracts import build_scenarios, run_contracts
from gcl.enforce.servers import StandInScanner, null_expressible
from gcl.standards import MCP_INTEGRATIONS

THV = os.environ.get("GCL_INTEG_TOOLHIVE")

CALL = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "gcl_probe", "arguments": {"note": "hello GCL-U-i01-ab12cd"}}}
HELLO = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}}


def review(mcp_request, uid="u-1"):
    """pkg/webhook/types.go `Request`, as ToolHive sends it."""
    return {"version": "v0.1.0", "uid": uid, "timestamp": "2026-10-11T20:00:00Z", "principal": None,
            "mcp_request": mcp_request, "context": {"server_name": "gcl", "source_ip": "127.0.0.1:1", "transport": ""}}


def _post(url, obj):
    r = urllib.request.urlopen(urllib.request.Request(url, data=json.dumps(obj).encode()), timeout=3)
    return json.loads(r.read())


def test_registered_and_listed_as_an_mcp_integration():
    assert ADAPTERS["toolhive"] is ToolHiveMCP
    assert "toolhive" in MCP_INTEGRATIONS
    assert ToolHiveMCP.mcp_transport == "http" and ToolHiveMCP.runtime == "node"
    # The webhooks see only what the client sends: no output side, so no output scenarios.
    assert "output" not in ToolHiveMCP.capabilities and "input" in ToolHiveMCP.capabilities


def test_unknown_profile_is_refused(tmp_path):
    with pytest.raises(ValueError, match="unknown toolhive profile"):
        ToolHiveMCP("thv", tmp_path, "banana")


def test_env_may_be_the_binary_or_its_folder(tmp_path):
    (tmp_path / "thv").write_text("")
    assert _thv_binary(str(tmp_path)) == tmp_path / "thv"
    assert _thv_binary(str(tmp_path / "thv")) == tmp_path / "thv"


@pytest.mark.parametrize("profile", sorted(TOOLHIVE_PROFILES))
def test_webhook_config_per_profile(tmp_path, profile):
    ad = ToolHiveMCP(str(tmp_path), tmp_path, profile)
    with StandInScanner(ad.protocol) as sc:
        cfg = json.loads(json.dumps(ad._webhooks(sc)))  # a JSON file: ToolHive reads .json as JSON
        assert set(cfg) == {"mutating", "validating"}
        (mut,), (val,) = cfg["mutating"], cfg["validating"]
        assert mut["name"] != val["name"]
        assert mut["url"] == f"{sc.base_for('input')}/mutate" and val["url"] == f"{sc.base_for('input')}/validate"
        for wh in (mut, val):
            # pkg/webhook/types.go ValidateDefinition: http only with insecure_skip_verify; 1 s <= timeout <= 30 s.
            assert wh["failure_policy"] == TOOLHIVE_PROFILES[profile] and wh["failure_policy"] in ("fail", "ignore")
            assert wh["tls_config"] == {"insecure_skip_verify": True}
            assert 1 <= float(wh["timeout"].rstrip("s")) <= 30
    # Both stages of the stand-in are not needed: the plan is input-only.
    assert ad.config_summary()["failure_policy"] == profile


def test_profiles_have_documented_expectations_with_sources():
    assert set(ToolHiveMCP.documented) == set(TOOLHIVE_PROFILES) == set(ToolHiveMCP.documented_sources)
    for p, src in ToolHiveMCP.documented_sources.items():
        assert src["read_for"] == "toolhive v0.51.4" and src["passage"] and "pkg/webhook/types.go" in src["source"]
        assert ToolHiveMCP.documented[p]["allow"] == "passed" and ToolHiveMCP.documented[p]["block"] == "stopped"
    fail, ignore = ToolHiveMCP.documented["fail"], ToolHiveMCP.documented["ignore"]
    for f in ("error", "timeout", "malformed", "empty", "unknown_verdict", "verdict_type", "refused"):
        assert fail[f] == "stopped" and ignore[f] == "passed"
    # Decided by the code, not the docs, and the same under both policies: left out of `documented`.
    for f in ("wrong_schema", "null_verdict"):
        assert f not in fail and f not in ignore


def test_names_pass_through(tmp_path):
    ad = ToolHiveMCP(str(tmp_path), tmp_path)
    assert ad.mcp_name("tool", "gcl_probe") == "gcl_probe" and ad.mcp_name("prompt", "gcl_prompt") == "gcl_prompt"


def test_plan_is_input_only(tmp_path):
    ad = ToolHiveMCP(str(tmp_path), tmp_path)
    plan = build_scenarios(ad)
    assert {s.stage for s in plan} == {"input"}
    modes = {s.mode for s in plan}
    assert {"allow", "block", "block_retry", "refused", "null_verdict"} <= modes and "modify" in modes
    assert ToolHiveMCP.documented["fail"]["modify"] == ToolHiveMCP.documented["ignore"]["modify"] == "modified"
    assert null_expressible(TOOLHIVE_WEBHOOK)


def test_standin_speaks_toolhives_webhook_api():
    with StandInScanner(TOOLHIVE_WEBHOOK) as sc:
        url = sc.base_for("input")
        sc.configure({"input": "allow"})
        a = _post(f"{url}/validate", review(CALL, "abc"))
        assert a == {"version": "v0.1.0", "uid": "abc", "allowed": True}   # uid echoed, as the RFC wants
        sc.configure({"input": "block"})
        b = _post(f"{url}/validate", review(CALL, "def"))
        assert b["allowed"] is False and b["uid"] == "def" and "GCL-BLOCKED" in b["message"]
        # The same body answers a mutating webhook (MutatingResponse embeds Response): no patch on a block.
        assert "patch" not in _post(f"{url}/mutate", review(CALL))
        assert sc.events[-1]["stage"] == "input" and sc.events[-1]["valid"]
        # Only the two webhook routes exist.
        with pytest.raises(urllib.error.HTTPError):
            _post(f"{url}/scan", review(CALL))


def test_handshake_is_never_the_scenarios_verdict():
    """ToolHive shows the webhook every POST, initialize included; a request with no gcl marker is not
    about the scenario, so a block or a fault there would end the session before the scenario's own call."""
    with StandInScanner(TOOLHIVE_WEBHOOK) as sc:
        url = sc.base_for("input")
        for mode in ("block", "error", "malformed", "wrong_schema"):
            sc.configure({"input": mode})
            assert _post(f"{url}/validate", review(HELLO))["allowed"] is True
            assert sc.events[-1]["mode"] == "allow"
        sc.configure({"input": "block"})
        assert _post(f"{url}/validate", review(CALL))["allowed"] is False


def test_modify_is_a_json_patch_under_mcp_request():
    with StandInScanner(TOOLHIVE_WEBHOOK) as sc:
        url = sc.base_for("input")
        sc.configure({"input": "modify"}, modify_text="[redacted] GCL-M-i01-ab12cd")
        got = _post(f"{url}/mutate", review(CALL))
        assert got["allowed"] is True and got["patch_type"] == "json_patch"
        (op,) = got["patch"]
        # pkg/webhook/mutating/patch.go: every path must sit under /mcp_request/ (the root is refused).
        assert op == {"op": "replace", "path": "/mcp_request/params/arguments/note",
                      "value": "[redacted] GCL-M-i01-ab12cd"}
        # Nothing to replace in a message without a note: allowed as it is.
        sc.configure({"input": "modify"}, modify_text="x GCL-M-i01-ab12cd")
        assert "patch" not in _post(f"{url}/mutate", review({**CALL, "method": "tools/list", "params": {}}))


def test_fault_answers_misread_by_toolhive_as_the_source_says():
    """What the verdict-field faults look like on the wire, and why each is decided as it is (Go decoding
    of pkg/webhook/types.go Response): a string where `allowed` is a bool does not decode (an error, so the
    failure policy applies); null leaves the zero value false (an explicit denial, policy-independent)."""
    with StandInScanner(TOOLHIVE_WEBHOOK) as sc:
        url = sc.base_for("input")
        for mode, expect in (("unknown_verdict", "unknown"), ("verdict_type", "false"), ("null_verdict", None)):
            sc.configure({"input": mode})
            ans = _post(f"{url}/validate", review({**CALL, "params": {**CALL["params"], "arguments": {
                "note": "GCL-U-i01-ab12cd"}}}))
            assert ans["allowed"] == expect, mode


def test_docker_socket_precedence(monkeypatch):
    monkeypatch.setenv("TOOLHIVE_DOCKER_SOCKET", "/a/docker.sock")
    monkeypatch.setenv("DOCKER_HOST", "unix:///b/docker.sock")
    assert _docker_socket() == "/a/docker.sock"
    monkeypatch.delenv("TOOLHIVE_DOCKER_SOCKET")
    assert _docker_socket() == "/b/docker.sock"


def test_all_state_stays_in_the_workdir(tmp_path, monkeypatch):
    monkeypatch.setenv("TOOLHIVE_DOCKER_SOCKET", "/a/docker.sock")
    env = ToolHiveMCP(str(tmp_path), tmp_path / "run")._env()
    for key in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME"):
        assert env[key].startswith(str(tmp_path / "run"))
    # No update check and no usage metrics phone home.
    assert env["TOOLHIVE_SKIP_UPDATE_CHECK"] == "true" and env["TOOLHIVE_USAGE_METRICS_ENABLED"] == "false"
    assert env["TOOLHIVE_DOCKER_SOCKET"] == "/a/docker.sock"


@pytest.mark.skipif(not THV, reason="set GCL_INTEG_TOOLHIVE to the path of a thv binary to run ToolHive")
@pytest.mark.parametrize("profile", ["fail", "ignore"])
def test_real_toolhive_controls_hold(tmp_path, profile):
    run = run_contracts(ADAPTERS["toolhive"](THV, tmp_path, profile), 40)
    for r in run["results"]:
        if r["scenario"]["control"] and r["scenario"]["mode"] in ("allow", "block"):
            assert r["policy"] == "held", (r["scenario"]["stage"], r["scenario"]["mode"], r["notes"])
    assert run["summary"]["scenarios"] > 4
