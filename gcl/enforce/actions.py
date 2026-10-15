"""Phase 1 run mode: agent-action controls (approval / read-only / allowlist).

`gcl enforce --extra ...` drives an `Adapter` through `contracts.build_scenarios`: one
integration, one guard protocol that answers allow/block/modify, exercised across
languages and protocol faults. An action target is a different shape, and `gcl actions`
is a dedicated command rather than another `--extra` for three reasons:

1. There is no guard verdict here. The control under test is a flag the target itself
   reads (a read-only mode, a command allowlist, an approval setting); gcl is not
   standing in for a scanner the target calls out to, it is the MCP *client* driving the
   real target's own tool, and the question is whether a specific action executes when
   the flag says it must not -- judged from gcl's own independent observation of the
   target's persisted state (`sinks.SqliteStateObserver`), never from the target's own
   "success": true.
2. `build_scenarios`' plan (allow/block/modify x faults x languages) has no slot for "the
   one action that bypasses this classifier" or for a ledger verdict
   ("executed without approval", "approved args != executed args", ...); bending it to fit
   would either lose those verdicts or misrepresent a config-level bypass as a language or
   protocol-fault scenario it is not.
3. Reusing `contracts.Scenario` / `contracts.Result` (mode "approval" for the opening gate,
   "exec" for the check that actually runs an action) keeps reports, `findings`, SARIF and
   `severity` working unchanged -- the same "ordinary Result dicts" contract `--extra
   config` and `--extra routes` already rely on -- without reusing the scenario *planner*,
   which is the part that does not fit.

Controls first, the same shape as `config_checks.py`'s k00c: a benign, clearly-approved
action must actually run (the harness reaches the target and can tell when something
happened at all) and a clearly-denied action must be stopped (the gate is live); if either
fails, the real check is unverified -- nothing here is evidence without both.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..standards import action_risks
from .contracts import Result, Scenario
from .ledger import ActionLedger, LedgerEvent, judge
from .mcp_client import Exchange, stdio_session
from .receipt import gcl_source, new_run_id

# The three checks every action target runs, in this fixed order. "approved" and "denied"
# are the opening controls (role "control", mode "approval"); "bypass" is the real check
# (mode "exec") and only runs if both controls held.
_CONTROL_KINDS = ("approved", "denied")
BYPASS_ID = "k01"


@dataclass
class ActionCheck:
    id: str
    name: str
    kind: str   # "approved" | "denied" | "bypass"


CHECKS = (
    ActionCheck("k00a", "control: a benign, approved action runs", "approved"),
    ActionCheck("k00d", "control: an obviously denied action is stopped", "denied"),
    ActionCheck(BYPASS_ID, "known-CVE replay: a denied action that bypasses the classifier", "bypass"),
)


class StdioMCPActionTarget:
    """Base shape for an action target reached as a real MCP server over stdio, with gcl
    playing the client (`mcp_client.stdio_session`): one subprocess per probe, started
    fresh and killed again (`stdio_session` already does this), so nothing here is a
    long-lived server gcl must remember to tear down. A later target of the same shape
    (another stdio MCP server with its own approval/read-only/allowlist flag) subclasses
    this and only writes `argv`, `env`, `probe` and `observe`."""

    name = "base"

    def describe(self) -> dict:
        """Enough about this target to stand in for `Adapter.describe()`: `findings add`,
        `--format sarif` and the terminal report all key off `run["integration"]`, and this
        keeps those working unchanged on an actions report (see the module docstring)."""
        return {"integration": self.name, "profile": "default", "versions": {}, "config": self.config_summary()}

    def config_summary(self) -> dict:
        return {}

    def argv(self) -> list[str]:
        raise NotImplementedError

    def env(self) -> dict:
        raise NotImplementedError

    def cwd(self) -> str | None:
        return None

    def probe(self, kind: str, marker: str) -> dict:
        """One JSON-RPC request (a `tools/call`) for check kind "approved" | "denied" |
        "bypass". `marker` is this check's own tag; a target that can usefully embed it in
        the call (so a reply can be tied back to this check) should."""
        raise NotImplementedError

    def observe(self) -> dict:
        """gcl's own independent snapshot of whatever persisted state the probes can
        affect (e.g. a throwaway file's contents), taken the same way before and after a
        probe. Must come from something gcl reads itself, never from the target's reply."""
        raise NotImplementedError

    def changed(self, before: dict, after: dict) -> bool:
        """Did the probe's action commit? The default (structural inequality) is enough
        for a target whose `observe()` is a complete snapshot; override for a partial one
        (e.g. only the field the probe's own action could plausibly touch)."""
        return before != after

    def reply_ok(self, ex: Exchange) -> bool:
        """For a read-type ("approved") probe only, where there is no persisted state to
        diff: did the protocol exchange itself complete with a successful tool result?
        This is the one place a target's own reply is read as evidence, because a
        read has no side effect for gcl to check independently -- see the module
        docstring. Never used for "denied" or "bypass": those are judged from `observe()`
        alone, regardless of what the reply claims."""
        raise NotImplementedError

    def call(self, step: dict, timeout_s: float) -> Exchange:
        return stdio_session(self.argv(), self.env(), [step], timeout_s, cwd=self.cwd())


def _judge_controls(approved_ran: bool, denied_ran: bool) -> tuple[bool, list[str]]:
    """Both controls hold or nothing past them is evidence (config_checks.judge_controls'
    shape): the approved/benign action must actually run (the harness works, and the
    control is not simply blocking everything) and the denied one must not (the gate is
    live, not disabled or unreachable)."""
    bad = []
    if not approved_ran:
        bad.append("the approved/benign action did not run: the harness cannot tell when something happened, "
                   "or the control over-blocks")
    if denied_ran:
        bad.append("the denied action ran: the gate is not live, so nothing past this is evidence")
    return not bad, bad


def _event_for(check: ActionCheck, run_id: str, ran: bool, before: dict, after: dict) -> LedgerEvent:
    marker = f"GCL-ACT-{check.id}-{run_id}"
    approval_decision = "approved" if check.kind == "approved" else "denied"
    receipt = {"marker": marker, "observed_before": before, "observed_after": after, "changed": ran} if ran else None
    action = {"check": check.kind, "id": check.id}
    return LedgerEvent(id=check.id, proposed_action=action, args_shown_to_approver=action,
                       approval_decision=approval_decision, args_executed=action if ran else None,
                       model_turn_occurred=True, receipt=receipt, marker=marker)


def _scenario(check: ActionCheck, run_id: str, mode: str) -> Scenario:
    role = "control" if check.kind in _CONTROL_KINDS else ""
    return Scenario(check.id, "input", mode, "en", check.name, "", run=run_id, role=role,
                    control=check.kind in _CONTROL_KINDS)


# What each check kind must observe for its control to hold / its replay to stay green.
_EXPECT = {"approved": "executed as approved", "denied": "blocked", "bypass": "blocked"}


def _result(check: ActionCheck, run_id: str, mode: str, observed: str, policy: str, notes: list[str],
           evidence: dict) -> Result:
    sc = _scenario(check, run_id, mode)
    evidence["owasp"] = action_risks(observed) if policy == "violated" else []
    doc = "unverified" if policy == "unverified" else "unspecified"
    return Result(sc, observed, _EXPECT[check.kind], None, policy, doc, evidence, list(notes))


def _unverified(check: ActionCheck, run_id: str, mode: str, why: str) -> Result:
    return _result(check, run_id, mode, "not run", "unverified", [why], {"ran": None})


def run_action_target(target: StdioMCPActionTarget, timeout_s: float = 30.0, say: Callable | None = None,
                      run_id: str | None = None) -> dict:
    """Run the fixed three checks (CHECKS) against `target`; ordinary Result dicts, the
    controls first. If the controls do not hold, the bypass check is reported unverified
    rather than run: a control that is not proven live cannot clear a target of anything."""
    say = say or (lambda *_: None)
    run_id = run_id or new_run_id()
    ledger = ActionLedger()
    results: list[Result] = []
    control_votes: dict[str, bool] = {}
    controls_ok: bool | None = None
    controls_why: list[str] = []
    for check in CHECKS:
        if check.kind == "bypass" and controls_ok is False:
            why = "; ".join(controls_why) or "the controls did not hold"
            results.append(_unverified(check, run_id, "exec", f"{why}: not evidence"))
            continue
        say(f"{check.id}: {check.name}")
        before = target.observe()
        marker = f"GCL-ACT-{check.id}-{run_id}"
        step = target.probe(check.kind, marker)
        ex = target.call(step, timeout_s)
        after = target.observe()
        ran = target.reply_ok(ex) if check.kind == "approved" else target.changed(before, after)
        event = ledger.record(_event_for(check, run_id, ran, before, after))
        evidence = {"ran": ran, "exchange_finished": ex.finished, "exchange_error": ex.error,
                   "exchange": list(ex.log)}
        if check.kind in _CONTROL_KINDS:
            control_votes[check.kind] = ran
            if len(control_votes) == len(_CONTROL_KINDS):
                controls_ok, controls_why = _judge_controls(control_votes["approved"], control_votes["denied"])
            # The individual control's own policy mirrors config_checks' CONTROL result:
            # "held" when it shows what a control must show, "unverified" otherwise --
            # never "violated": a failed control is not itself a finding, it is "nothing
            # past this is evidence".
            ok_this = ran if check.kind == "approved" else not ran
            observed = ("executed as approved" if (check.kind == "approved" and ran) else
                       "blocked" if (check.kind == "denied" and not ran) else
                       "not run" if check.kind == "approved" else "executed without approval")
            pol = "held" if ok_this else "unverified"
            notes = [] if ok_this else [f"check {check.id} ({check.name}) did not hold"]
            results.append(_result(check, run_id, "approval", observed, pol, notes, evidence))
        else:
            observed, pol, notes = judge(event)
            results.append(_result(check, run_id, "exec", observed, pol, notes, evidence))
    summary = _summarize(results)
    return {"target": target.name, "integration": target.describe(),
            "results": [r.to_dict() for r in results], "summary": summary,
            "ledger": ledger.to_list(),
            "receipt": {"run_id": run_id, "gcl": gcl_source(), "timeout_s": timeout_s, "problems": []}}


def _summarize(results: list[Result]) -> dict:
    """Both this phase's own shape (checks/held/violated/unverified) and the aliases
    `cli._enforce_exit` and `report.sarif.enforce_sarif` read (scenarios/policy_violated/
    documented_deviates), so an actions run is an ordinary enforce-shaped summary too."""
    held = sum(1 for r in results if r.policy == "held")
    violated = sum(1 for r in results if r.policy == "violated")
    unverified = sum(1 for r in results if r.policy == "unverified")
    return {"checks": len(results), "held": held, "violated": violated, "unverified": unverified,
            "scenarios": len(results), "policy_held": held, "policy_violated": violated,
            "documented_deviates": 0, "documented_unspecified_violations": violated}
