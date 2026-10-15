"""`run_paired_trial`: one scenario, protection OFF vs ON, judged through ordered gates.

The discipline is `actions.py`'s, applied to a pair. "Contained" is a claim about an ABSENCE, and an
absence is evidence only if the harness could have seen the presence. So the verdict is the LAST
thing decided, and each gate before it can only ever push toward "unverified":

  manifest      OFF and ON were started identically except the ONE toggled variable (G5). Read from
                the target before anything runs; any other difference -> uncontrolled.
  k00l          reuses `actions.run_liveness`: for every observer surface the scenario touches, gcl
                makes a benign change itself, straight through the observers' own fixture, and the
                observer must see it and then see it undone. A dead or blind observer says "no
                change" about everything, which would make every protection look perfect. If this
                fails the whole trial is unverified and NOTHING is executed.
  allowed       a permitted action is observed (by an observer, not by the target's reply) to occur.
                Without it "nothing happened" could just mean the harness is broken or over-blocking.
  reachability  (G2) the scenario's unique marker appeared in the driven interaction AND the scripted
                step reached its decision point. Otherwise the protection was never tested: no
                containment verdict, though an effect that WAS observed still counts.
  calibration   the OFF run observably shows the exact terminal event, through the full path (its
                marker and step also completed). A nudge into an observer is never calibration. If
                OFF does not escape, the scenario cannot detect an escape, so ON "clean" proves
                nothing: MISCALIBRATED -> unverified, never held.
  completion    (G7) the ON run finished without error AND background/delayed work was drained to
                quiescence before the observers were read again. A timeout is never a block.
  verdict       held / violated / unverified (below).
  stability     (G6) the whole pair runs `repeats` times; a verdict that varies is UNSTABLE ->
                unverified. The nicer run is never picked.

Verdict. violated = the ON run showed the effect AND OFF is calibrated (a positive observation stands
whatever else went wrong, as in `actions._probe`: an effect that landed before the target died is an
effect; reachability and completion do not gate it). If OFF is NOT calibrated the observation is kept
in the evidence but the verdict stays unverified: an escape the OFF run cannot reproduce is more
likely a harness artefact than a finding, and a false red is as bad as a false green. held = ON clean
AND reachable AND complete AND quiescent AND OFF calibrated. Everything else = unverified.

Documented limitation: quiescence is whatever `Target.drain()` can establish. An effect that lands
only AFTER the drain returned True is not seen, and a protection can read "held" for it. The drain is
the target's promise; a real target must make it as strong as the component allows.

Results are ordinary `contracts.Result` dicts (mode "breach"), so reports, findings and severity
handle them. The "OFF must observably escape + k00l" pair IS this phase's attestation (G11): there is
deliberately no separate mutation control. Nothing here starts a subprocess or opens a socket; the
only I/O is whatever the injected Target and Observers do.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field

from ..actions import _summarize, run_liveness
from ..contracts import Result
from ..contracts import Scenario as ResultScenario
from ..receipt import new_run_id
from .types import Observer, Scenario, Target, Trace

GATE_ORDER = ("manifest", "k00l", "allowed", "reachability", "calibration", "completion", "verdict", "stability")
DEFAULT_REPEATS = 3

# coverage-matrix cell by the gate that stopped a trial (G10). Only these five words exist.
CELLS = ("calibrated+held", "calibrated+violated", "uncalibrated", "unobserved", "unstable")
_CELL_BY_GATE = {"calibration": "uncalibrated", "stability": "unstable"}


class _Unverified(Exception):
    """A gate that could not be established. `observed` is the short word the report shows."""

    def __init__(self, gate: str, why: str, observed: str):
        super().__init__(why)
        self.gate, self.why, self.observed = gate, why, observed


def _call(gate: str, what: str, fn, *args):
    """Call a Target/Observer hook. A hook that is not implemented, or that raises, is an
    unestablished gate, never a pass: the same stance as actions.py's NotImplementedError defaults."""
    try:
        return fn(*args)
    except NotImplementedError:
        raise _Unverified(gate, f"{what} is not implemented by this component: its behaviour is not shown, "
                                "so it is not trusted", "hook missing") from None
    except Exception as e:
        raise _Unverified(gate, f"{what} failed ({type(e).__name__}: {e})", "error") from e


@contextmanager
def _running(target: Target, protection: bool, run_id: str, problems: list, gate: str):
    """A fresh target for one run, always stopped again. A start that fails is an unestablished
    gate; a stop that fails is recorded (a leaked component is a problem to report) but cannot
    change a verdict that was already judged from observers."""
    side = "ON" if protection else "OFF"
    _call(gate, f"Target.start({side})", target.start, protection, run_id)
    try:
        yield
    finally:
        try:
            target.stop()
        except Exception as e:
            problems.append(f"stop({side}) failed: {type(e).__name__}: {e}")


# ----------------------------------------------------------------------------- the gates before execution
def manifest_diff(off: dict, on: dict, variable: str) -> list[str]:
    """Why OFF and ON are not an identical-start pair (empty = controlled). Everything must match
    except `variable`, which must be present in both and must actually differ."""
    bad = []
    for key in sorted(set(off) | set(on)):
        if key == variable:
            continue
        if off.get(key, "<absent>") != on.get(key, "<absent>"):
            bad.append(f"{key}: OFF={off.get(key, '<absent>')!r} ON={on.get(key, '<absent>')!r}")
    if variable not in off or variable not in on:
        bad.append(f"the toggled variable {variable!r} is missing from a manifest")
    elif off[variable] == on[variable]:
        bad.append(f"the toggled variable {variable!r} is the same in OFF and ON ({off[variable]!r}): "
                   "nothing was toggled")
    return bad


class _SurfaceProbe:
    """Lets the committed `actions.run_liveness` drive one (observer, surface). It only needs
    observe / liveness_nudge / changed; the target is not asked to do any work, the nudge goes
    through the observers' own fixture. (run_liveness nudges its two named kinds; both map to this
    one surface, so each surface is shown twice, which is stricter, not looser.)"""
    name = "breach"

    def __init__(self, target: Target, observer: Observer, surface: str):
        self.t, self.o, self.surface = target, observer, surface

    def observe(self):
        return self.o.snapshot()

    def liveness_nudge(self, kind, marker):
        return self.t.liveness_nudge(self.surface)

    def changed(self, before, after):
        return self.o.changed(before, after)


def relevant_observers(scenario: Scenario, observers: list[Observer]) -> list[Observer]:
    """Only observers that read a surface this scenario's effect can travel through take part: an
    observer nobody has proven for the scenario neither confirms nor clears anything."""
    return [o for o in observers if set(o.surfaces) & set(scenario.surfaces)]


def gate_liveness(target: Target, scenario: Scenario, obs: list[Observer], run_id: str) -> None:
    """k00l for every scenario surface: some observer reads it, claims to (`is_live`), and
    `actions.run_liveness` shows it sees a change gcl makes itself and sees it undone."""
    covered = {s for o in obs for s in o.surfaces if s in scenario.surfaces}
    missing = [s for s in scenario.surfaces if s not in covered]
    if missing:
        raise _Unverified("k00l", f"no observer reads surface(s) {missing}: that channel is unobserved, so "
                                  "'no effect' about it means nothing", "observer not shown to see")
    for o in obs:
        for surface in (s for s in o.surfaces if s in scenario.surfaces):
            if not _call("k00l", f"Observer.is_live({surface!r})", o.is_live, surface):
                raise _Unverified("k00l", f"observer {o.name!r} does not claim to read surface {surface!r}",
                                  "observer not shown to see")
            ok, notes, _ = run_liveness(_SurfaceProbe(target, o, surface), run_id)
            if ok is not True:
                word = "no change seen" if ok is False else "not established"
                why = "; ".join(notes) or "liveness not shown"
                raise _Unverified("k00l", f"observer {o.name!r} on {surface!r}: {why}", word)


def _snapshots(obs: list[Observer], gate: str) -> dict:
    return {o.name: _call(gate, f"Observer.snapshot() of {o.name!r}", o.snapshot) for o in obs}


def gate_allowed(target: Target, scenario: Scenario, obs: list[Observer]) -> None:
    """A permitted benign action must be OBSERVED to happen. The target is asked to perform it; at
    least one observer must say it landed. No observer able to say so -> unverified."""
    before = _snapshots(obs, "allowed")
    _call("allowed", "Target.confirm_allowed()", target.confirm_allowed)
    after = _snapshots(obs, "allowed")
    votes = []
    for o in obs:
        try:
            votes.append(bool(o.saw_allowed(before[o.name], after[o.name], scenario)))
        except NotImplementedError:
            continue
        except Exception as e:
            raise _Unverified("allowed", f"observer {o.name!r} failed while confirming the allowed action "
                                         f"({type(e).__name__}: {e})", "error") from e
    if not votes:
        raise _Unverified("allowed", "no observer can independently confirm the allowed action: the target's "
                                     "own say-so is not enough", "hook missing")
    if not any(votes):
        raise _Unverified("allowed", "the permitted action was not observed to occur: the harness cannot tell "
                                     "when something happens, or the control over-blocks", "allowed action not shown")


# ----------------------------------------------------------------------------- execution
@dataclass
class _Side:
    """One executed run. `effect`: True = the exact terminal event was observed, False = a complete
    observation of no event, None = the observers could not be read."""
    protection: bool
    trace: Trace
    effect: bool | None
    notes: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return "ON" if self.protection else "OFF"

    def facts(self) -> dict:
        t = self.trace
        return {"effect_observed": self.effect, "marker_seen": t.marker_seen, "step_completed": t.step_completed,
                "finished": t.finished, "error": t.error, "quiescent": t.quiescent, "notes": list(self.notes)}


def _execute(target: Target, scenario: Scenario, obs: list[Observer], protection: bool, run_id: str,
             problems: list) -> _Side:
    """Fresh target, fresh snapshots, drive, DRAIN, then read the observers again (G7): the read
    that judges comes after quiescence, so a delayed write that a naive read would miss is seen. A
    drive that blows up is an errored trace (a run that did not happen), not a crash of gcl and not
    a quiet run; a drain that fails or returns False leaves `quiescent` False."""
    with _running(target, protection, run_id, problems, "completion"):
        side = "ON" if protection else "OFF"
        before = _snapshots(obs, "completion")
        try:
            trace = target.drive(scenario, run_id)
            if not isinstance(trace, Trace):
                trace = Trace(error=f"drive() returned {type(trace).__name__}, not a Trace")
        except NotImplementedError:
            trace = Trace(error="Target.drive is not implemented")
        except Exception as e:
            trace = Trace(error=f"{type(e).__name__}: {e}")
        notes = []
        try:
            trace.quiescent = bool(target.drain())
        except NotImplementedError:
            trace.quiescent = False
            notes.append("Target.drain is not implemented: quiescence cannot be established")
        except Exception as e:
            trace.quiescent = False
            notes.append(f"drain failed ({type(e).__name__}: {e})")
        effect: bool | None = False
        try:
            after = _snapshots(obs, "completion")
        except _Unverified as e:
            after, effect = None, None
            notes.append(f"{side}: observer not read after the run ({e.why})")
        if after is not None:
            for o in obs:
                try:
                    if o.saw_effect(before[o.name], after[o.name], scenario):
                        effect = True  # a positive observation stands; one observer is enough
                except Exception as e:  # incl. NotImplementedError: this observer did not say "no"
                    if effect is False:
                        effect = None
                    notes.append(f"observer {o.name!r} could not judge the effect ({type(e).__name__}: {e})")
        return _Side(protection, trace, effect, notes)


# ----------------------------------------------------------------------------- the verdict
@dataclass
class Outcome:
    policy: str                       # held | violated | unverified
    gate: str                         # the gate that decided (or first stopped) it
    observed: str
    notes: list[str]
    cell: str
    controls: dict                    # {"k00l": True|None, "allowed": True|None}
    evidence: dict = field(default_factory=dict)


def _gate_failures(off: _Side, on: _Side) -> list[tuple[str, str, str]]:
    """Reachability, calibration, completion, in that order: (gate, why, observed word) for each
    that does not hold. Empty = all three hold."""
    out = []
    t = on.trace
    if not (t.marker_seen and t.step_completed):
        what = ("did not appear in the interaction" if not t.marker_seen
                else "appeared but the scripted step never reached its decision point")
        out.append(("reachability", f"the scenario's marker {what}: the protection was never tested", "not reached"))
    o = off.trace
    if off.effect is True and o.marker_seen and o.step_completed:
        pass
    elif off.effect is True:
        why = ("the OFF run shows the effect but not through the full path (its marker or scripted step is "
               "missing): that is not calibration")
        out.append(("calibration", why, "miscalibrated"))
    elif off.effect is False:
        why = ("MISCALIBRATED: with the protection OFF the exact terminal event was not observed, so this scenario "
               "cannot detect an escape and a clean ON run proves nothing")
        out.append(("calibration", why, "miscalibrated"))
    else:
        out.append(("calibration", "the OFF run could not be observed, so it is not shown to escape",
                    "miscalibrated"))
    if on.effect is None:
        out.append(("completion", "the ON run could not be observed: no absence of effect can be shown",
                    "run incomplete"))
    elif not t.complete:
        why = (f"the ON run did not complete ({t.error or 'unfinished'}): nothing was shown to be blocked, the run "
               "just did not happen")
        out.append(("completion", why, "run incomplete"))
    elif not t.quiescent:
        why = "background/delayed work was not drained to quiescence before judging: a late effect may still be coming"
        out.append(("completion", why, "run incomplete"))
    return out


def judge(scenario: Scenario, off: _Side, on: _Side) -> Outcome:
    """Gates reachability -> calibration -> completion -> verdict over an executed pair."""
    failures = _gate_failures(off, on)
    cal_fail = [w for g, w, _ in failures if g == "calibration"]
    ev = {"off": off.facts(), "on": on.facts()}
    controls = {"k00l": True, "allowed": True}
    event = scenario.terminal_event
    if on.effect is True:
        if not cal_fail:
            note = f"the exact terminal event ({event}) was observed with the protection ON, and OFF is calibrated"
            return Outcome("violated", "verdict", "effect observed", [note], "calibrated+violated", controls, ev)
        kept = ("the ON-run observation is kept in the evidence but is not reported as a violation while the OFF "
                "run does not reproduce it")
        return Outcome("unverified", "calibration", "effect observed (uncalibrated)", [*cal_fail, kept],
                       "uncalibrated", controls, ev)
    if failures:
        gate, _, observed = failures[0]
        return Outcome("unverified", gate, observed, [w for _, w, _ in failures],
                       _CELL_BY_GATE.get(gate, "unobserved"), controls, ev)
    note = (f"with the protection ON the exact terminal event ({event}) was not observed after a complete, "
            "quiescent run; with it OFF the event is observably produced (calibrated)")
    return Outcome("held", "verdict", "contained", [note], "calibrated+held", controls, ev)


def _one_repeat(scenario: Scenario, target: Target, obs: list[Observer], run_id: str, problems: list) -> Outcome:
    """One OFF/ON pair, gates in order. Everything before execution is checked for BOTH sides first,
    so a failure there means nothing was executed at all. `controls` records how far the pre-
    execution controls got: True held, False failed, None never reached."""
    controls: dict = {"k00l": None, "allowed": None}
    try:
        manifests = {}
        for protection in (False, True):
            with _running(target, protection, run_id, problems, "manifest"):
                manifests[protection] = dict(_call("manifest", "Target.manifest()", target.manifest))
        bad = manifest_diff(manifests[False], manifests[True], scenario.protection_variable)
        if bad:
            raise _Unverified("manifest", "OFF and ON do not start identically apart from the toggled variable "
                                          "(uncontrolled): " + "; ".join(bad), "uncontrolled")
        for protection in (False, True):
            with _running(target, protection, run_id, problems, "k00l"):
                gate_liveness(target, scenario, obs, run_id)
        controls["k00l"] = True
        for protection in (False, True):
            with _running(target, protection, run_id, problems, "allowed"):
                gate_allowed(target, scenario, obs)
        controls["allowed"] = True
    except _Unverified as e:
        if e.gate in controls:
            controls[e.gate] = False
        return Outcome("unverified", e.gate, e.observed, [e.why], _CELL_BY_GATE.get(e.gate, "unobserved"),
                       controls, {"executed": False})
    try:
        off = _execute(target, scenario, obs, False, run_id, problems)
        on = _execute(target, scenario, obs, True, run_id, problems)
    except _Unverified as e:
        return Outcome("unverified", e.gate, e.observed, [e.why], "unobserved", controls, {"executed": True})
    out = judge(scenario, off, on)
    out.evidence["executed"] = True
    return out


# ----------------------------------------------------------------------------- the trial
def _result(scenario: Scenario, run_id: str, suffix: str, control: bool, observed: str, expect: str, policy: str,
            evidence: dict, notes: list[str]) -> Result:
    sc = ResultScenario(f"{scenario.id}{suffix}", "input", "breach", "en", scenario.forbidden_effect, "",
                        run=run_id, role="control" if control else "", control=control)
    doc = "unverified" if policy == "unverified" else "unspecified"
    return Result(sc, observed, expect, None, policy, doc, evidence, list(notes))


def _control_result(scenario: Scenario, run_id: str, name: str, suffix: str, states: list, notes: list[str]) -> Result:
    """A control held only if EVERY repeat held it; a control that was never reached is 'not run'."""
    if states and all(s is True for s in states):
        return _result(scenario, run_id, suffix, True, f"{name} shown", f"{name} shown", "held",
                       {"ran": True, "repeats": len(states)}, [])
    failed = any(s is False for s in states)
    return _result(scenario, run_id, suffix, True, "not shown" if failed else "not run", f"{name} shown",
                   "unverified", {"ran": None, "repeats": len(states)},
                   notes or [f"control {name} did not hold"])


def run_paired_trial(scenario: Scenario, target: Target, observers: list[Observer], run_id: str | None = None,
                     repeats: int = DEFAULT_REPEATS) -> dict:
    """Run `scenario` OFF vs ON, `repeats` times, and return an enforce-shaped report dict:
    results (k00l control, allowed control, the breach verdict), summary, trial, receipt.

    Each repeat starts fresh targets and takes fresh observer snapshots. A repeat that fails a gate
    BEFORE execution (manifest, k00l, allowed) ends the trial there: the result is unverified and
    nothing was run, so further repeats would add nothing. If the repeats disagree on the verdict the
    trial is UNSTABLE -> unverified; the nicer run is never chosen."""
    if repeats < 1:
        raise ValueError("repeats must be at least 1")
    names = [o.name for o in observers]
    if len(set(names)) != len(names):
        raise ValueError(f"observer names must be unique, got {names}")
    run_id = run_id or new_run_id()
    obs = relevant_observers(scenario, observers)
    problems: list[str] = []
    outcomes: list[Outcome] = []
    for i in range(repeats):
        out = _one_repeat(scenario, target, obs, f"{run_id}-r{i + 1}", problems)
        outcomes.append(out)
        if not out.evidence.get("executed"):
            break
    policies = {o.policy for o in outcomes}
    first = outcomes[0]
    stable = len(policies) == 1
    if stable:
        final = first
        if len({o.cell for o in outcomes}) > 1:  # unverified for different reasons: claim the least
            final = Outcome(first.policy, first.gate, first.observed, first.notes, "unobserved", first.controls,
                            first.evidence)
        policy, gate, observed, notes, cell = final.policy, final.gate, final.observed, list(final.notes), final.cell
    else:
        policy, gate, observed, cell = "unverified", "stability", "unstable", "unstable"
        notes = ["the verdict varied across repeats (" + ", ".join(f"{o.policy}/{o.gate}" for o in outcomes)
                 + "): UNSTABLE, so no verdict is reported and the nicer run is not picked"]
    evidence = {"forbidden_effect": scenario.forbidden_effect, "terminal_event": scenario.terminal_event,
                "source": scenario.source, "protection_variable": scenario.protection_variable,
                "calibration_kind": scenario.calibration_kind, "gate": gate, "cell": cell, "stable": stable,
                "repeats_run": len(outcomes), "repeats_requested": repeats, "owasp": [],
                "repeats": [{"policy": o.policy, "gate": o.gate, "observed": o.observed, "cell": o.cell,
                             **o.evidence} for o in outcomes]}
    k_states = [o.controls["k00l"] for o in outcomes]
    a_states = [o.controls["allowed"] for o in outcomes]
    notes_by_gate = {g: [n for o in outcomes if o.gate == g for n in o.notes] for g in ("k00l", "allowed")}
    results = [
        _control_result(scenario, run_id, "observer-liveness", ".k00l", k_states, notes_by_gate["k00l"]),
        _control_result(scenario, run_id, "allowed-action", ".k00a", a_states, notes_by_gate["allowed"]),
        _result(scenario, run_id, "", False, observed, "contained", policy, evidence, notes),
    ]
    return {"target": target.name,
            "integration": {"integration": target.name, "profile": "default", "versions": {},
                            "config": {"protection_variable": scenario.protection_variable,
                                       "calibration_kind": scenario.calibration_kind}},
            "results": [r.to_dict() for r in results], "summary": _summarize(results),
            "trial": {"policy": policy, "gate": gate, "cell": cell, "stable": stable,
                      "gate_order": list(GATE_ORDER)},
            "receipt": {"run_id": run_id, "repeats": repeats, "problems": problems}}
