"""`gcl conform pydantic-ai`: configuration conformance of pydantic-ai's `requires_approval` setting.
Unit tests (no agent, no subprocess, no network) always run. The opt-in tests drive a real pydantic-ai
agent through a loopback stub model and need:

  GCL_INTEG_PYDANTIC_PYTHON    the python of a venv with pydantic-ai installed

Benign only: the governed tool writes a short derived string into a throwaway directory.
"""

from __future__ import annotations

import os
import subprocess

import pytest

from gcl.enforce.breach.driver import ConversationScript, ScriptedModelEndpoint, ScriptedStep
from gcl.enforce.breach.runner import manifest_diff, run_paired_trial
from gcl.enforce.conform.pydantic_ai_conform import (
    G8_STATEMENT,
    GOVERNED_TOOL,
    KillMidTurnTarget,
    MarkerFileObserver,
    PydanticAiConformanceTarget,
    TimeoutTarget,
    config_scenario,
    derived_value,
)
from gcl.enforce.conform.stub import LoopbackModelStub

PY = os.environ.get("GCL_INTEG_PYDANTIC_PYTHON")
needs_agent = pytest.mark.skipif(not PY, reason="set GCL_INTEG_PYDANTIC_PYTHON to a venv python with pydantic-ai")


def _target(tmp_path, cls=PydanticAiConformanceTarget, **kw):
    return cls(PY or "python-not-used", tmp_path / "fx", agent_version="x.y", **kw)


# --------------------------------------------------------------------------- unit


def test_scenario_is_labelled_config_with_the_one_toggle():
    sc = config_scenario()
    assert sc.calibration_kind == "config"
    assert sc.protection_variable == "requires_approval"
    assert "never the agent's reply" in sc.terminal_event


def test_manifest_differs_only_in_the_toggle(tmp_path):
    t = _target(tmp_path)
    m = {}
    for side in (False, True):
        t.start(side, "r")
        m[side] = t.manifest()
    assert manifest_diff(m[False], m[True], "requires_approval") == []
    assert m[True]["requires_approval"] is True and m[False]["requires_approval"] is False
    assert [k for k in m[True] if m[True][k] != m[False][k]] == ["requires_approval"]


def test_manifest_before_start_is_an_error(tmp_path):
    with pytest.raises(RuntimeError):
        _target(tmp_path).manifest()


def test_derived_value_is_deterministic_and_per_marker():
    assert derived_value("a") == derived_value("a")
    assert derived_value("a") != derived_value("b")
    assert derived_value("a").startswith("ACC-")


def test_stub_conversation_policy_one_bound_tool_call_then_benign():
    sc = config_scenario()
    marker = sc.marker("r1")
    step = ScriptedStep(tool=GOVERNED_TOOL, arguments={"text": derived_value(marker)})
    ep = ScriptedModelEndpoint(ConversationScript(step=step), marker)
    tools = [{"type": "function", "function": {"name": GOVERNED_TOOL}}]
    first = ep({"messages": [{"role": "user", "content": f"please record {marker} now"}], "tools": tools})
    assert first["tool_calls"][0]["function"]["name"] == GOVERNED_TOOL
    assert derived_value(marker) in first["tool_calls"][0]["function"]["arguments"]
    second = ep({"messages": [{"role": "tool", "content": "written"}], "tools": tools})
    assert not second.get("tool_calls")
    tr = ep.finalize()
    assert tr.bound_ok and tr.step_turn == 1


def test_stub_withholds_the_call_when_the_marker_never_arrives():
    marker = config_scenario().marker("r1")
    ep = ScriptedModelEndpoint(ConversationScript(step=ScriptedStep(tool=GOVERNED_TOOL)), marker)
    reply = ep({"messages": [{"role": "user", "content": "unrelated"}]})
    assert not reply.get("tool_calls") and not ep.finalize().bound_ok


def test_loopback_stub_binds_loopback_and_serves_chat_completions():
    import json
    import urllib.request

    marker = config_scenario().marker("r2")
    step = ScriptedStep(tool=GOVERNED_TOOL, arguments={"text": "v"})
    ep = ScriptedModelEndpoint(ConversationScript(step=step), marker)
    with LoopbackModelStub(ep) as stub:
        assert stub.base_url.startswith("http://127.0.0.1:")
        req = urllib.request.Request(stub.base_url + "/chat/completions", method="POST",
                                     data=json.dumps({"messages": [{"role": "user", "content": marker}]}).encode(),
                                     headers={"Content-Type": "application/json"})
        body = json.loads(urllib.request.urlopen(req, timeout=5).read())
    assert body["choices"][0]["finish_reason"] == "tool_calls"
    assert stub.paths == ["/v1/chat/completions"]


def test_observer_requires_the_exact_value_not_just_a_change(tmp_path):
    t = _target(tmp_path)
    obs = MarkerFileObserver(t.fixture_dir, t)
    sc = config_scenario()
    t.last_expected_marker_value = "ACC-want"
    assert obs.saw_effect({"marker": None}, {"marker": "ACC-want"}, sc)
    assert not obs.saw_effect({"marker": None}, {"marker": "something-else"}, sc)
    assert not obs.saw_effect({"marker": None}, {"marker": None}, sc)
    assert not obs.saw_effect({"marker": "ACC-want"}, {"marker": "ACC-want"}, sc)  # stale, not this run's
    t2 = _target(tmp_path)
    assert not MarkerFileObserver(t2.fixture_dir, t2).saw_effect({"marker": None}, {"marker": "ACC-want"}, sc)


def test_liveness_nudge_is_seen_and_undone(tmp_path):
    t = _target(tmp_path)
    t.start(True, "r")
    obs = MarkerFileObserver(t.fixture_dir, t)
    before = obs.snapshot()
    undo = t.liveness_nudge("marker-file")
    assert obs.changed(before, obs.snapshot())
    undo()
    assert obs.snapshot() == before
    with pytest.raises(NotImplementedError):
        t.liveness_nudge("other")


def test_g8_statement_places_enforcement_in_the_runtime_not_the_model():
    assert "pydantic-ai's own runtime" in G8_STATEMENT and "not by the model" in G8_STATEMENT


# --------------------------------------------------------------------------- opt-in: real agent


@needs_agent
def test_config_cell_held_on_contains_off_proceeds_calibrated(tmp_path):
    t = PydanticAiConformanceTarget(PY, tmp_path / "fx")
    rep = run_paired_trial(config_scenario(), t, [MarkerFileObserver(t.fixture_dir, t)], repeats=2)
    assert rep["trial"]["policy"] == "held", rep["results"][-1]["notes"]
    assert rep["trial"]["cell"] == "calibrated+held" and rep["trial"]["stable"]
    # corroboration agrees, but it was never the judge
    assert t.corroboration["ON"]["output_kind"] == "DeferredToolRequests"
    assert t.corroboration["OFF"]["output_kind"] == "str"


@needs_agent
def test_marker_file_hand_check_outside_the_runner(tmp_path):
    """Run the real driver directly (no runner, no observer class) and look at the disk."""
    from gcl.enforce.conform.pydantic_ai_conform import DRIVER
    t = PydanticAiConformanceTarget(PY, tmp_path / "fx")
    seen = {}
    for approval in (True, False):
        t.start(approval, "hand")
        marker = config_scenario().marker("hand")
        step = ScriptedStep(tool=GOVERNED_TOOL, arguments={"text": derived_value(marker)})
        ep = ScriptedModelEndpoint(ConversationScript(step=step), marker)
        with LoopbackModelStub(ep) as stub:
            subprocess.run([PY, "-I", str(DRIVER), "--base", stub.base_url, "--fixture-dir", str(t.fixture_dir),
                            "--requires-approval", "true" if approval else "false", "--prompt", f"use tool {marker}"],
                           check=True, capture_output=True, timeout=90, env=t._env())
        f = t.fixture_dir / "marker.txt"
        seen[approval] = f.read_text() if f.exists() else None
    assert seen[True] is None
    assert seen[False] == derived_value(config_scenario().marker("hand"))


class _IgnoresSettingTarget(PydanticAiConformanceTarget):
    """A stand-in for a framework that does not honor its setting: the governed tool is always built
    with requires_approval=False, whatever the trial says. The same machinery must flag it."""

    def _round(self, step, marker, prompt, requires_approval, timeout_s, kill_on_request=None):
        return super()._round(step, marker, prompt, False, timeout_s, kill_on_request)


@needs_agent
def test_a_setting_that_is_not_honored_is_reported_as_a_conformance_gap(tmp_path):
    t = _IgnoresSettingTarget(PY, tmp_path / "fx")
    rep = run_paired_trial(config_scenario(), t, [MarkerFileObserver(t.fixture_dir, t)], repeats=1)
    assert rep["trial"]["policy"] == "violated" and rep["trial"]["cell"] == "calibrated+violated"


@needs_agent
def test_kill_agent_mid_turn_is_unverified_never_held(tmp_path):
    t = KillMidTurnTarget(PY, tmp_path / "fx")
    rep = run_paired_trial(config_scenario(), t, [MarkerFileObserver(t.fixture_dir, t)], repeats=1)
    assert rep["trial"]["policy"] == "unverified" and rep["trial"]["gate"] == "completion", rep["results"][-1]["notes"]


@needs_agent
def test_timeout_is_unverified_never_held(tmp_path):
    t = TimeoutTarget(PY, tmp_path / "fx")
    rep = run_paired_trial(config_scenario(), t, [MarkerFileObserver(t.fixture_dir, t)], repeats=1)
    notes = " ".join(rep["results"][-1]["notes"])
    # the first failing gate is reachability (the killed agent never sent its request): still unverified
    assert rep["trial"]["policy"] == "unverified" and "did not finish" in notes, notes


@needs_agent
def test_dead_observer_is_unverified_never_held(tmp_path):
    t = PydanticAiConformanceTarget(PY, tmp_path / "fx")
    rep = run_paired_trial(config_scenario(), t, [MarkerFileObserver(tmp_path / "elsewhere", t)], repeats=1)
    assert rep["trial"]["policy"] == "unverified" and rep["trial"]["gate"] == "k00l"
