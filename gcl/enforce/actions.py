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

"Blocked"/held is a claim about the ABSENCE of a change, and an absence is only evidence if
three things are true that a bare "the state did not move" does not establish:

  - the run COMPLETED: a target that crashed, timed out, never answered the probe or broke
    the transport leaves the state unmoved too, and "nothing happened because nothing ran"
    is not "the control stopped it". An incomplete or errored exchange can therefore never
    produce held; it is unverified ("run incomplete"). A POSITIVE observation (the state
    changed, the marker landed) still stands as violated whatever else went wrong: a leak
    that landed before the target died is a leak.
  - the OBSERVER can see: a dead or misconfigured observer (wrong path, a reader that
    always returns the same thing, a permission error swallowed into an empty snapshot)
    reports "no change" about everything, i.e. it makes every control look perfect. The
    observer-liveness control (k00l) is the actions-phase analogue of the mutation control
    / k00c: gcl itself makes one benign, observable change per surface a probe could touch,
    straight through the observer's own fixture (never through the target), and the observer
    must see it, then gcl puts it back. If it does not, nothing past it is evidence.
  - the benign "approved" control is confirmed by that same independent observer, not only
    by the target's own reply: a target that lies in its reply (or a flaky success) must not
    be able to pass the control that licenses every later check.

A probe whose exchange finished but whose reply claims the action succeeded while the
observer saw nothing is a contradiction between two witnesses, and a contradiction is
unverified, not held.
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
# The state surfaces a probe can move, each of which the observer must be shown to see: the
# denied probe and the bypass probe change different things (a row vs a header field, a
# plain path vs a symlink target), and an observer that is alive for one can be blind to the
# other.
LIVENESS_KINDS = ("denied", "bypass")


@dataclass
class ActionCheck:
    id: str
    name: str
    kind: str   # "liveness" | "approved" | "denied" | "bypass"


# The observer-liveness control is NOT part of CHECKS: it sends no probe to the target, so a
# runner that iterates CHECKS (probe, call, observe, judge) must not treat it as one. It runs
# first and gates everything in CHECKS (`run_action_target`).
LIVENESS_CHECK = ActionCheck("k00l", "control: the observer sees a change gcl itself makes", "liveness")

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
        """For a read-type ("approved") probe only: did the protocol exchange itself carry
        a successful tool result? A NECESSARY condition for the approved control, never a
        sufficient one: the target's own reply is the one thing a lying or flaky target
        controls, so `confirm_approved` (the independent observer) must agree too. Never
        used for "denied" or "bypass": those are judged from `observe()` alone."""
        raise NotImplementedError

    def confirm_approved(self, ex: Exchange, before: dict, after: dict) -> bool:
        """The INDEPENDENT confirmation that the benign action really happened: gcl's own
        observer (the fake-shell/DB/FS receipt or state it reads itself) agrees with what
        the reply claims -- e.g. the rows the reply returned are the rows the observer reads
        straight from the store, or the file the reply says was written is there. A target
        that cannot give this has an approved control that rests on the target's say-so
        alone, so the default is NotImplementedError and the control (hence the whole run)
        is unverified rather than quietly trusted."""
        raise NotImplementedError

    def reply_refused(self, ex: Exchange) -> bool | None:
        """Did the target's own reply to a denied/bypass probe REFUSE it (a JSON-RPC error,
        an isError result, a success:false payload)? True = refused, False = the reply claims
        the action succeeded, None = this target cannot tell (the default). A reply that
        claims success while the observer saw no change is a contradiction and is judged
        unverified, never held; a proper refusal is the extra support "blocked" asks for
        where the target gives one. The observer, not this, decides a violation. Return False
        ONLY where a success reply with no observed change is truly inconsistent: a target
        that can legitimately succeed without the bypass landing (e.g. a write that replaces
        a symlink instead of following it) must return None, or a safe build reads unverified."""
        return None

    def liveness_nudge(self, kind: str, marker: str) -> Callable[[], None]:
        """Observer-liveness control (k00l): make ONE benign, observable change on the state
        surface the `kind` probe ("denied" | "bypass") could move, directly through the
        observer's own fixture -- never through the target -- so that `changed(observe(),
        observe())` must turn True. Return an undo callable that puts the state back exactly.
        Without this a dead observer ("no change" about everything) is indistinguishable from
        a target that blocks everything, so the default is NotImplementedError and the run is
        unverified rather than trusting an observer nobody has shown to see."""
        raise NotImplementedError

    def call(self, step: dict, timeout_s: float) -> Exchange:
        return stdio_session(self.argv(), self.env(), [step], timeout_s, cwd=self.cwd())


def _judge_controls(approved_ran: bool | None, denied_ran: bool | None, *,
                    live: bool | None) -> tuple[bool, list[str]]:
    """All three controls hold or nothing past them is evidence (config_checks.judge_controls'
    shape): the observer must be shown to see a change (a dead observer makes every denial
    look perfect), the approved/benign action must actually run AND be confirmed by that
    observer (the harness works, and the control is not simply blocking everything), and the
    denied one must not (the gate is live, not disabled or unreachable). Each vote is True /
    False / None; None is "could not be established" (incomplete run, observer not read) and,
    like False, never lets a later check count."""
    bad = []
    if live is not True:
        bad.append("the observer-liveness control did not hold: gcl cannot show the observer sees a change, so "
                   "'no change' from it means nothing")
    if approved_ran is None:
        bad.append("the approved/benign action could not be confirmed (incomplete run, or the observer could "
                   "not be read or does not confirm it)")
    elif not approved_ran:
        bad.append("the approved/benign action did not run: the harness cannot tell when something happened, "
                   "or the control over-blocks")
    if denied_ran is None:
        bad.append("the denied probe could not be judged (incomplete run, or the observer could not be read)")
    elif denied_ran:
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
    control = check.kind in _CONTROL_KINDS or check.kind == "liveness"
    return Scenario(check.id, "input", mode, "en", check.name, "", run=run_id, role="control" if control else "",
                    control=control)


# What each check kind must observe for its control to hold / its replay to stay green.
_EXPECT = {"liveness": "change seen", "approved": "executed as approved", "denied": "blocked",
           "bypass": "blocked"}


def _result(check: ActionCheck, run_id: str, mode: str, observed: str, policy: str, notes: list[str],
           evidence: dict) -> Result:
    sc = _scenario(check, run_id, mode)
    evidence["owasp"] = action_risks(observed) if policy == "violated" else []
    doc = "unverified" if policy == "unverified" else "unspecified"
    return Result(sc, observed, _EXPECT[check.kind], None, policy, doc, evidence, list(notes))


def _unverified(check: ActionCheck, run_id: str, mode: str, why: str, observed: str = "not run",
                evidence: dict | None = None) -> Result:
    return _result(check, run_id, mode, observed, "unverified", [why], evidence or {"ran": None})


def _observe(target: StdioMCPActionTarget) -> tuple[dict | None, str]:
    """One independent look at the state, or (None, why): an observer that raises (missing
    file, permission, a reader that crashed) has NOT said "nothing changed", it has said
    nothing, and that must never be folded into an empty or equal snapshot."""
    try:
        snap = target.observe()
    except Exception as e:  # any failure to read is "observer not read"
        return None, f"{type(e).__name__}: {e}"
    return (snap, "") if isinstance(snap, dict) else (None, f"observe() returned {type(snap).__name__}, not a dict")


def _safe_call(target: StdioMCPActionTarget, step: dict, timeout_s: float) -> Exchange:
    """The target's `call`, with a crash in it recorded as an errored (unfinished) Exchange
    instead of propagating: a run that blew up must read as "run incomplete", not abort gcl
    half-way and not be mistaken for a quiet one."""
    try:
        return target.call(step, timeout_s)
    except Exception as e:
        return Exchange(error=f"{type(e).__name__}: {e}", finished=False)


def run_liveness(target: StdioMCPActionTarget, run_id: str) -> tuple[bool | None, list[str], dict]:
    """The observer-liveness control (k00l). For each surface in LIVENESS_KINDS: read, make
    one benign change through the observer's own fixture (`liveness_nudge`), read again, put
    it back, read a third time. True only if every surface showed the change AND went back to
    exactly where it started. False = the observer looked and saw nothing (dead / blind);
    None = it could not be established (observer unreadable, no nudge defined, nudge failed,
    state not restored). The target is not involved: no probe is sent."""
    seen: dict[str, bool | None] = {}
    notes: list[str] = []
    for kind in LIVENESS_KINDS:
        base, err = _observe(target)
        if base is None:
            seen[kind] = None
            notes.append(f"{kind}: observer not read ({err})")
            continue
        try:
            undo = target.liveness_nudge(kind, f"GCL-ACT-k00l-{kind}-{run_id}")
        except NotImplementedError:
            seen[kind] = None
            notes.append(f"{kind}: this target defines no liveness nudge, so its observer is not shown to work")
            continue
        except Exception as e:
            seen[kind] = None
            notes.append(f"{kind}: the liveness nudge failed ({type(e).__name__}: {e})")
            continue
        undo_failed = False
        try:
            moved, err = _observe(target)
        finally:
            try:
                undo()
            except Exception as e:
                undo_failed = True
                notes.append(f"{kind}: could not put the nudge back ({type(e).__name__}: {e})")
        back, err2 = _observe(target)
        if undo_failed:
            seen[kind] = None
        elif moved is None or back is None:
            seen[kind] = None
            notes.append(f"{kind}: observer not read after the nudge ({err or err2})")
        elif back != base:
            seen[kind] = None
            notes.append(f"{kind}: the state did not return to where it started after the nudge was undone")
        elif not target.changed(base, moved):
            seen[kind] = False
            notes.append(f"{kind}: gcl changed the state itself and the observer reported no change: dead or "
                         "blind observer")
        else:
            seen[kind] = True
    ok = True if all(v is True for v in seen.values()) else (False if any(v is False for v in seen.values()) else None)
    return ok, notes, {"surfaces": dict(seen)}


@dataclass
class _Probe:
    """One probe's raw material and its verdict input. `ran`: True = a positive observation
    that the action committed, False = a COMPLETE, observed non-event, None = could not be
    established (`why` says why, `observed` is the word the report shows)."""
    ex: Exchange
    before: dict | None
    after: dict | None
    ran: bool | None
    observed: str = ""
    why: str = ""

    @property
    def evidence(self) -> dict:
        return {"ran": self.ran, "exchange_finished": self.ex.finished, "exchange_error": self.ex.error,
                "observer_read": self.before is not None and self.after is not None,
                "exchange": list(self.ex.log)}


def _probe(target: StdioMCPActionTarget, check: ActionCheck, run_id: str, timeout_s: float) -> _Probe:
    """Send one probe and decide what, if anything, it proved.

    Order matters. A CHANGE the observer saw is a positive fact and stands whatever happened
    to the run (a write that landed before the target died is a write). An ABSENCE of change
    is only a fact when the observer could be read both times, the exchange completed without
    error, and the target's own reply (where it can tell) does not contradict it; anything
    less is None, never False."""
    marker = f"GCL-ACT-{check.id}-{run_id}"
    before, err_b = _observe(target)
    ex = _safe_call(target, target.probe(check.kind, marker), timeout_s)
    after, err_a = _observe(target)
    if before is None or after is None:
        return _Probe(ex, before, after, None, "observer not read",
                      f"the observer could not be read ({err_b or err_a}): no absence of change can be shown")
    complete = ex.finished and not ex.error
    if check.kind == "approved":
        if not complete:
            return _Probe(ex, before, after, None, "run incomplete",
                          f"the exchange did not complete ({ex.error or 'unfinished'}): the benign action is not shown")
        try:
            ok = bool(target.reply_ok(ex)) and bool(target.confirm_approved(ex, before, after))
        except NotImplementedError:
            return _Probe(ex, before, after, None, "observer not read",
                          "this target defines no independent confirmation of the approved action "
                          "(confirm_approved): its own reply is not enough")
        except Exception as e:
            return _Probe(ex, before, after, None, "observer not read",
                          f"confirming the approved action failed ({type(e).__name__}: {e})")
        return _Probe(ex, before, after, ok)
    if target.changed(before, after):
        return _Probe(ex, before, after, True)
    if not complete:
        return _Probe(ex, before, after, None, "run incomplete",
                      f"the exchange did not complete ({ex.error or 'no proper answer to the probe'}) and the state "
                      "is unchanged: nothing was shown to be blocked, the run just did not happen")
    try:
        refused = target.reply_refused(ex)
    except Exception:  # a hook that cannot tell is "cannot tell"
        refused = None
    if refused is False:
        return _Probe(ex, before, after, None, "contradicted",
                      "the target's reply says the action succeeded but the observer saw no change: two witnesses "
                      "disagree, so this is not shown to be blocked")
    return _Probe(ex, before, after, False)


def run_action_target(target: StdioMCPActionTarget, timeout_s: float = 30.0, say: Callable | None = None,
                      run_id: str | None = None) -> dict:
    """Run the fixed checks (CHECKS) against `target`; ordinary Result dicts, the controls
    first. If the controls do not hold, the bypass check is reported unverified rather than
    run: a control that is not proven live cannot clear a target of anything. The order is
    observer-liveness (no probe is even sent if the observer is not shown to see), approved,
    denied, then the real replay -- and "blocked"/held is only ever reported for a completed,
    error-free exchange read by a live observer (see the module docstring)."""
    say = say or (lambda *_: None)
    run_id = run_id or new_run_id()
    ledger = ActionLedger()
    results: list[Result] = []
    control_votes: dict[str, bool | None] = {}
    controls_ok: bool | None = None
    controls_why: list[str] = []
    live: bool | None = None
    for check in (LIVENESS_CHECK, *CHECKS):
        mode = "approval" if check.kind in (*_CONTROL_KINDS, "liveness") else "exec"
        if check.kind == "liveness":
            say(f"{check.id}: {check.name}")
            live, lnotes, lev = run_liveness(target, run_id)
            lev["ran"] = live
            if live:
                results.append(_result(check, run_id, mode, "change seen", "held", [], lev))
            else:
                obs = "no change seen" if live is False else "not run"
                results.append(_result(check, run_id, mode, obs, "unverified",
                                       lnotes or [f"check {check.id} ({check.name}) did not hold"], lev))
            continue
        if live is not True:
            why = ("the observer-liveness control did not hold (the observer is not shown to see a change): "
                   "nothing it reports is evidence")
            results.append(_unverified(check, run_id, mode, why))
            continue
        if check.kind == "bypass" and controls_ok is False:
            why = "; ".join(controls_why) or "the controls did not hold"
            results.append(_unverified(check, run_id, "exec", f"{why}: not evidence"))
            continue
        say(f"{check.id}: {check.name}")
        pr = _probe(target, check, run_id, timeout_s)
        evidence = pr.evidence
        if check.kind in _CONTROL_KINDS:
            control_votes[check.kind] = pr.ran
            if "approved" in control_votes and "denied" in control_votes:
                controls_ok, controls_why = _judge_controls(control_votes["approved"], control_votes["denied"],
                                                            live=live)
            if pr.ran is None:
                results.append(_unverified(check, run_id, mode, pr.why, pr.observed, evidence))
                continue
            ledger.record(_event_for(check, run_id, pr.ran, pr.before, pr.after))
            # The individual control's own policy mirrors config_checks' CONTROL result:
            # "held" when it shows what a control must show, "unverified" otherwise --
            # never "violated": a failed control is not itself a finding, it is "nothing
            # past this is evidence".
            ok_this = pr.ran if check.kind == "approved" else not pr.ran
            observed = ("executed as approved" if (check.kind == "approved" and pr.ran) else
                       "blocked" if (check.kind == "denied" and not pr.ran) else
                       "not run" if check.kind == "approved" else "executed without approval")
            pol = "held" if ok_this else "unverified"
            notes = [] if ok_this else [f"check {check.id} ({check.name}) did not hold"]
            results.append(_result(check, run_id, mode, observed, pol, notes, evidence))
        else:
            if pr.ran is None:
                results.append(_unverified(check, run_id, "exec", pr.why, pr.observed, evidence))
                continue
            event = ledger.record(_event_for(check, run_id, pr.ran, pr.before, pr.after))
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
