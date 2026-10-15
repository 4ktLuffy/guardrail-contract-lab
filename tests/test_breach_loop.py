"""`gcl breach` step 1: the paired-trial loop and its gate order, with negative controls.

Each test below is a negative control: it breaks exactly ONE thing in an in-process fake and asserts
that the gate guarding that thing turns the trial into "unverified" (or, for a real escape, into
"violated") and never into a false "held". The point of the whole package is that "held" is hard to
get: if any test here could pass while the matching gate were deleted, the gate would not be proven.

Everything is an in-process fake over a real mutable in-memory store (a list of rows): no network,
no subprocess, benign markers only. "Observed" means a fact about that store, not a scripted boolean.
"""

from __future__ import annotations

import pytest

from gcl.enforce import actions
from gcl.enforce.breach import (
    CALIBRATION_KINDS,
    GATE_ORDER,
    Observer,
    Scenario,
    Target,
    Trace,
    coverage_matrix,
    run_paired_trial,
)
from gcl.enforce.breach import runner as breach_runner
from gcl.enforce.breach.runner import CELLS, manifest_diff

SC = Scenario("s1", "a value is recorded in the fixture store", "the marker value is durably recorded in the store",
              "readonly", "config")


class World:
    """The real mutable state every fake shares: durable `rows`, delayed `pending` writes, a `flag`
    on a second surface, and counters so a test can prove that nothing was executed."""

    def __init__(self):
        self.rows: list[str] = []
        self.pending: list[str] = []
        self.flag = 0
        self.drives = 0
        self.starts = 0
        self.stops = 0
        self.on_drives = 0


class FakeTarget(Target):
    """A fake component. Knobs, all default to the healthy 'protection works, OFF escapes' case:
    on_leaks (bool | callable(n) -> bool: the effect lands with protection ON), off_escapes,
    on_marker/on_step/off_marker (reachability facts), on_finished/on_error/crash (completion),
    delay (effect goes to a delayed queue, flushed by drain), late (effect lands only AFTER the drain,
    at stop), drain_ok, allowed_works, nudge_undo, missing (hooks that raise NotImplementedError),
    manifest_extra / same_toggle (identical-start violations)."""

    name = "fake"

    def __init__(self, world, on_leaks=False, off_escapes=True, on_marker=True, on_step=True, off_marker=True,
                 on_finished=True, on_error="", crash=False, delay=False, late=False, drain_ok=True,
                 allowed_works=True, nudge_undo=True, missing=(), manifest_extra=None, same_toggle=False,
                 off_step=True):
        self.w = world
        self.on_leaks, self.off_escapes = on_leaks, off_escapes
        self.on_marker, self.on_step, self.off_marker, self.off_step = on_marker, on_step, off_marker, off_step
        self.on_finished, self.on_error, self.crash = on_finished, on_error, crash
        self.delay, self.late, self.drain_ok = delay, late, drain_ok
        self.allowed_works, self.nudge_undo = allowed_works, nudge_undo
        self.missing, self.manifest_extra, self.same_toggle = set(missing), manifest_extra or {}, same_toggle
        self.protection = None
        self.starts = 0

    def _need(self, hook):
        if hook in self.missing:
            raise NotImplementedError(hook)

    def start(self, protection, run_id):
        self.protection = protection
        self.starts += 1
        self.w.starts += 1
        # fresh fixtures every run: nothing carries over between runs (G5)
        self.w.rows.clear()
        self.w.pending.clear()
        self.w.flag = 0

    def stop(self):
        self.w.stops += 1
        self.w.rows.extend(self.w.pending)  # a LATE write lands here, after the run was already judged
        self.w.pending.clear()

    def manifest(self):
        self._need("manifest")
        m = {"version": "1.0", "env": "x", "isolation": "net-off", "readonly": self.protection and not self.same_toggle}
        m.update(self.manifest_extra if self.protection else {})
        return m

    def liveness_nudge(self, surface):
        self._need("liveness_nudge")
        if surface == "flag":
            self.w.flag = 7
            return lambda: setattr(self.w, "flag", 0)
        self.w.rows.append("nudge:k00l")
        return (lambda: self.w.rows.remove("nudge:k00l")) if self.nudge_undo else (lambda: None)

    def confirm_allowed(self):
        self._need("confirm_allowed")
        if self.allowed_works:
            self.w.rows.append("allowed:benign")

    def _leaks(self):
        if not self.protection:
            return self.off_escapes
        if callable(self.on_leaks):
            return self.on_leaks(self.w.on_drives)
        return self.on_leaks

    def drive(self, scenario, run_id):
        self._need("drive")
        self.w.drives += 1
        if self.protection:
            self.w.on_drives += 1
        if self.protection and self.crash:
            raise RuntimeError("target process died")
        row = f"effect:{scenario.marker(run_id)}"
        if self._leaks():
            if self.protection and (self.late or self.delay):  # only the ON run's write is delayed
                self.w.pending.append(row)
            else:
                self.w.rows.append(row)
        if self.protection:
            return Trace(self.on_marker, self.on_step, self.on_finished, self.on_error)
        return Trace(self.off_marker, self.off_step, True, "")

    def drain(self):
        self._need("drain")
        if not self.protection:
            return True
        if self.late:
            return True  # claims quiescence; the write still lands afterwards (documented limitation)
        if self.drain_ok:
            self.w.rows.extend(self.w.pending)
            self.w.pending.clear()
        return self.drain_ok


class StoreObserver(Observer):
    """Independent reader of the store. mode: live | dead (frozen snapshot, sees nothing) | raises."""

    def __init__(self, world, name="store", surface="store", mode="live", missing=()):
        self.w, self.name, self.surfaces, self.mode = world, name, (surface,), mode
        self.missing = set(missing)

    def _rows(self):
        return self.w.rows if self.surface_is_store else [self.w.flag]

    @property
    def surface_is_store(self):
        return self.surfaces[0] == "store"

    def snapshot(self):
        if self.mode == "raises":
            raise OSError("database is locked")
        if self.mode == "dead":
            return {"rows": []}
        return {"rows": list(self._rows())}

    def saw_effect(self, before, after, scenario):
        new = [r for r in after["rows"] if r not in before["rows"]]
        return any(str(r).startswith(f"effect:GCL-BRE-{scenario.id}-") for r in new)

    def saw_allowed(self, before, after, scenario):
        if "saw_allowed" in self.missing:
            raise NotImplementedError
        return any(str(r).startswith("allowed:") for r in after["rows"] if r not in before["rows"])

    def is_live(self, surface):
        return surface in self.surfaces


def trial(world=None, scenario=SC, observers=None, repeats=3, **kw):
    world = world or World()
    target = FakeTarget(world, **kw)
    observers = observers if observers is not None else [StoreObserver(world)]
    report = run_paired_trial(scenario, target, observers, run_id="t0", repeats=repeats)
    return report, world, target


def verdict(report):
    return report["results"][-1]


def controls(report):
    return report["results"][0], report["results"][1]


def never_held(report):
    assert verdict(report)["policy"] != "held", verdict(report)["notes"]
    assert report["summary"]["held"] == sum(1 for r in report["results"] if r["scenario"]["control"] and
                                            r["policy"] == "held")


# ------------------------------------------------------------------------------------------ the happy paths
def test_happy_path_off_escapes_on_contained_is_held():
    report, world, _ = trial()
    v = verdict(report)
    assert v["policy"] == "held" and v["observed"] == "contained"
    assert v["scenario"]["mode"] == "breach"  # an ordinary Result dict: reports/findings/severity handle it
    assert v["evidence"]["cell"] == "calibrated+held" and v["evidence"]["stable"] is True
    assert v["evidence"]["repeats_run"] == 3 and v["evidence"]["calibration_kind"] == "config"
    k, a = controls(report)
    assert (k["policy"], a["policy"]) == ("held", "held") and k["scenario"]["role"] == "control"
    assert report["summary"]["held"] == 3 and report["summary"]["violated"] == 0
    assert report["trial"]["gate_order"] == list(GATE_ORDER)
    assert world.starts == world.stops and world.starts > 0  # every start was stopped: no leaked component


def test_on_shows_the_effect_is_violated():
    report, *_ = trial(on_leaks=True)
    v = verdict(report)
    assert v["policy"] == "violated" and v["observed"] == "effect observed"
    assert v["evidence"]["cell"] == "calibrated+violated"
    assert report["summary"]["violated"] == 1


# --------------------------------------------------------------------------------- gate: calibration (OFF)
def test_off_does_not_show_the_effect_is_miscalibrated_never_held():
    """THE never-cry-wolf test. ON is clean, the run is complete and reachable, but OFF never escapes:
    the scenario could not have detected an escape, so 'contained' proves nothing."""
    report, *_ = trial(off_escapes=False)
    v = verdict(report)
    assert v["policy"] == "unverified" and v["policy"] != "held"
    assert v["evidence"]["gate"] == "calibration" and v["observed"] == "miscalibrated"
    assert v["evidence"]["cell"] == "uncalibrated"
    assert any("MISCALIBRATED" in n for n in v["notes"])


def test_on_effect_without_a_calibrated_off_is_kept_but_not_reported_as_violation():
    report, *_ = trial(on_leaks=True, off_escapes=False)
    v = verdict(report)
    assert v["policy"] == "unverified" and v["evidence"]["gate"] == "calibration"
    assert v["observed"] == "effect observed (uncalibrated)"
    assert v["evidence"]["repeats"][0]["on"]["effect_observed"] is True  # the observation is kept


@pytest.mark.parametrize("flag", ["off_marker", "off_step"])
def test_off_effect_that_did_not_come_through_the_full_path_is_not_calibration(flag):
    """An effect that appears without the marker/step having traversed the path (as a nudge into the
    sink would) must never be accepted as calibration."""
    report, *_ = trial(**{flag: False})
    v = verdict(report)
    assert v["policy"] == "unverified" and v["evidence"]["gate"] == "calibration"
    assert any("full path" in n for n in v["notes"])


# ---------------------------------------------------------------------------------- hooks missing -> unverified
@pytest.mark.parametrize("hook", ["manifest", "liveness_nudge", "confirm_allowed", "drive", "drain"])
def test_target_hook_missing_reads_unverified_never_held(hook):
    report, *_ = trial(missing=[hook])
    never_held(report)
    assert verdict(report)["policy"] == "unverified"


def test_observer_that_cannot_confirm_the_allowed_action_is_unverified():
    world = World()
    report, *_ = trial(world=world, observers=[StoreObserver(world, missing=["saw_allowed"])])
    v = verdict(report)
    assert v["policy"] == "unverified" and v["evidence"]["gate"] == "allowed" and world.drives == 0


def test_base_classes_default_to_not_implemented():
    for call in (lambda: Target().start(True, "r"), lambda: Target().liveness_nudge("s"),
                 lambda: Target().confirm_allowed(), lambda: Target().drive(SC, "r"),
                 lambda: Observer().snapshot(), lambda: Observer().is_live("s"),
                 lambda: Observer().saw_allowed({}, {}, SC)):
        with pytest.raises(NotImplementedError):
            call()


# ------------------------------------------------------------------------------------------ gate: k00l
def test_dead_observer_makes_the_whole_trial_unverified_and_nothing_runs():
    """A frozen observer says 'no change' about everything, which makes any protection look perfect."""
    world = World()
    report, world, _ = trial(world=world, observers=[StoreObserver(world, mode="dead")])
    v = verdict(report)
    assert v["policy"] == "unverified" and v["evidence"]["gate"] == "k00l"
    assert world.drives == 0, "nothing may be executed once the observer is not shown to see"
    k, a = controls(report)
    assert k["policy"] == "unverified" and a["policy"] == "unverified"
    assert any("dead or blind" in n for n in v["notes"])
    never_held(report)


def test_observer_that_raises_is_not_an_observer_that_saw_nothing():
    world = World()
    report, world, _ = trial(world=world, observers=[StoreObserver(world, mode="raises")])
    assert verdict(report)["policy"] == "unverified" and verdict(report)["evidence"]["gate"] == "k00l"
    assert world.drives == 0


def test_blind_observer_on_one_of_two_surfaces_fails_k00l():
    world = World()
    sc = Scenario("s2", "x", "y", "readonly", "config", surfaces=("store", "flag"))
    blind = StoreObserver(world, name="flag", surface="flag", mode="dead")
    report, world, _ = trial(world=world, scenario=sc, observers=[StoreObserver(world), blind])
    assert verdict(report)["policy"] == "unverified" and verdict(report)["evidence"]["gate"] == "k00l"
    assert world.drives == 0


def test_surface_nobody_observes_is_unobserved_not_held():
    world = World()
    sc = Scenario("s2", "x", "y", "readonly", "config", surfaces=("store", "egress"))
    report, world, _ = trial(world=world, scenario=sc)
    v = verdict(report)
    assert v["policy"] == "unverified" and v["evidence"]["gate"] == "k00l" and v["evidence"]["cell"] == "unobserved"
    assert world.drives == 0


def test_nudge_that_is_not_undone_fails_k00l():
    report, world, _ = trial(nudge_undo=False)
    assert verdict(report)["evidence"]["gate"] == "k00l" and verdict(report)["policy"] == "unverified"
    assert world.drives == 0


def test_k00l_is_the_committed_actions_gate():
    assert breach_runner.run_liveness is actions.run_liveness


# ------------------------------------------------------------------------------------- gate: allowed action
def test_over_blocking_harness_fails_the_allowed_control():
    report, world, _ = trial(allowed_works=False)
    v = verdict(report)
    assert v["policy"] == "unverified" and v["evidence"]["gate"] == "allowed" and world.drives == 0
    k, a = controls(report)
    assert k["policy"] == "held" and a["policy"] == "unverified"


# ------------------------------------------------------------------------------------ gate: reachability
@pytest.mark.parametrize("flag", ["on_marker", "on_step"])
def test_reachability_missing_gives_no_containment_verdict(flag):
    report, *_ = trial(**{flag: False})
    v = verdict(report)
    assert v["policy"] == "unverified" and v["evidence"]["gate"] == "reachability" and v["observed"] == "not reached"
    assert v["evidence"]["cell"] == "unobserved"


def test_reachability_missing_but_effect_observed_is_still_reported():
    report, *_ = trial(on_marker=False, on_leaks=True)
    v = verdict(report)
    assert v["policy"] == "violated", "an observed effect counts even when reachability is not shown"
    assert v["evidence"]["repeats"][0]["on"]["marker_seen"] is False


# ----------------------------------------------------------------------------- gate: completion / quiescence
@pytest.mark.parametrize("kw", [
    {"on_finished": False},
    {"on_error": "BrokenPipeError: transport closed"},
    {"on_finished": False, "on_error": "timed out after 30s"},
])
def test_incomplete_or_errored_on_run_is_never_held(kw):
    """Pre-fix analogue: a crashed/timed-out target leaves the store unchanged, which 'looks' contained."""
    report, *_ = trial(**kw)
    v = verdict(report)
    assert v["policy"] == "unverified" and v["evidence"]["gate"] == "completion" and v["observed"] == "run incomplete"


def test_crashed_drive_is_an_errored_run_not_a_quiet_one():
    report, *_ = trial(crash=True)
    v = verdict(report)
    assert v["policy"] == "unverified" and any("did not complete" in n and "died" in n for n in v["notes"])
    never_held(report)


def test_effect_that_landed_before_the_crash_is_still_a_violation():
    report, *_ = trial(crash=False, on_leaks=True, on_finished=False, on_error="died after the write")
    assert verdict(report)["policy"] == "violated"


def test_delayed_effect_is_caught_by_the_drain_not_a_false_held():
    """The effect lands only after a naive read. Showing the precondition on the fake, then the runner."""
    world = World()
    t = FakeTarget(world, on_leaks=True, delay=True)
    obs = StoreObserver(world)
    t.start(True, "pre")
    before = obs.snapshot()
    t.drive(SC, "pre-r1")
    naive_after = obs.snapshot()  # a naive judge reads here ...
    assert not obs.saw_effect(before, naive_after, SC), "precondition: the effect has not landed yet"
    t.drain()
    assert obs.saw_effect(before, obs.snapshot(), SC)  # ... and would have called it contained

    report, *_ = trial(on_leaks=True, delay=True)
    assert verdict(report)["policy"] == "violated"


def test_drain_that_cannot_establish_quiescence_is_unverified():
    report, *_ = trial(on_leaks=True, delay=True, drain_ok=False)
    # the effect is still pending (unseen) and quiescence was not shown: never held
    v = verdict(report)
    assert v["policy"] == "unverified" and v["evidence"]["gate"] == "completion"
    never_held(report)


def test_documented_limitation_effect_after_the_drain_is_not_seen():
    """LIMITATION, pinned on purpose: if the target claims quiescence and the effect lands only after
    the drain returned, no observer reading before that point can see it, and the run reads held. The
    guarantee is as strong as `Target.drain()`; a real target must make it as strong as it can."""
    report, *_ = trial(on_leaks=True, late=True)
    assert verdict(report)["policy"] == "held"


# --------------------------------------------------------------------------------------- gate: stability
def test_outcome_that_flips_across_repeats_is_unstable_and_unverified():
    report, *_ = trial(on_leaks=lambda n: n % 2 == 0)  # contained, escapes, contained
    v = verdict(report)
    assert v["policy"] == "unverified" and v["evidence"]["gate"] == "stability" and v["observed"] == "unstable"
    assert v["evidence"]["cell"] == "unstable" and v["evidence"]["stable"] is False
    assert [r["policy"] for r in v["evidence"]["repeats"]] == ["held", "violated", "held"]


def test_stable_violation_stays_violated_across_repeats():
    report, *_ = trial(on_leaks=True, repeats=3)
    assert verdict(report)["policy"] == "violated" and verdict(report)["evidence"]["repeats_run"] == 3


# ------------------------------------------------------------------------------------- gate: manifest (G5)
def test_difference_beyond_the_toggle_is_uncontrolled():
    report, world, _ = trial(manifest_extra={"env": "DIFFERENT", "mounts": "/extra"})
    v = verdict(report)
    assert v["policy"] == "unverified" and v["evidence"]["gate"] == "manifest" and v["observed"] == "uncontrolled"
    assert world.drives == 0
    assert any("env" in n and "mounts" in n for n in v["notes"])


def test_toggle_that_did_not_change_is_not_a_pair():
    report, world, _ = trial(same_toggle=True)
    assert verdict(report)["evidence"]["gate"] == "manifest" and world.drives == 0


def test_manifest_diff_ignores_only_the_toggle():
    assert manifest_diff({"a": 1, "v": 0}, {"a": 1, "v": 1}, "v") == []
    assert manifest_diff({"a": 1, "v": 0}, {"a": 2, "v": 1}, "v")
    assert manifest_diff({"a": 1}, {"a": 1, "v": 1}, "v")


# ---------------------------------------------------------------------------------- scenario and plumbing
def test_scenario_validates_and_labels_the_calibration_kind():
    assert CALIBRATION_KINDS == ("config", "version")
    with pytest.raises(ValueError):
        Scenario("s", "e", "t", "v", "both")
    with pytest.raises(ValueError):
        Scenario("s", "", "t", "v", "config")
    version = Scenario("s3", "e", "t", "version", "version")
    report, *_ = trial(scenario=version)
    assert verdict(report)["evidence"]["calibration_kind"] == "version"
    assert report["integration"]["config"]["calibration_kind"] == "version"


def test_every_start_gets_fresh_state():
    report, world, target = trial(repeats=2)
    assert verdict(report)["policy"] == "held"
    assert world.starts == world.stops and target.starts == world.starts


def test_duplicate_observer_names_are_refused():
    world = World()
    with pytest.raises(ValueError):
        run_paired_trial(SC, FakeTarget(world), [StoreObserver(world), StoreObserver(world)], "t0")


# ------------------------------------------------------------------------------------------ coverage matrix
def test_coverage_matrix_shape_and_no_percentages():
    results = []
    for sid, effect, source, kw in [
        ("a", "write recorded", "tool_result", {}),
        ("b", "write recorded", "web_page", {"on_leaks": True}),
        ("c", "file read", "tool_result", {"off_escapes": False}),
        ("d", "file read", "web_page", {"on_leaks": lambda n: n % 2 == 0}),
    ]:
        sc = Scenario(sid, effect, "t", "readonly", "config", source=source)
        report, *_ = trial(scenario=sc, **kw)
        results += report["results"]
    m = coverage_matrix(results)
    assert m["rows"] == ["write recorded", "file read"] and m["cols"] == ["tool_result", "web_page"]
    assert m["cells"]["write recorded"] == {"tool_result": "calibrated+held", "web_page": "calibrated+violated"}
    assert m["cells"]["file read"] == {"tool_result": "uncalibrated", "web_page": "unstable"}
    assert all(c in CELLS for row in m["cells"].values() for c in row.values())
    assert not any(isinstance(v, float) for v in m.values())  # never a score


def test_coverage_matrix_untried_cells_are_unobserved_and_conflicts_are_unstable():
    a = Scenario("a", "eff1", "t", "readonly", "config", source="s1")
    b = Scenario("b", "eff2", "t", "readonly", "config", source="s2")
    held, *_ = trial(scenario=a)
    viol, *_ = trial(scenario=b, on_leaks=True)
    m = coverage_matrix(held["results"] + viol["results"])
    assert m["cells"]["eff1"]["s2"] == "unobserved" and m["cells"]["eff2"]["s1"] == "unobserved"
    held2, *_ = trial(scenario=a)
    viol2, *_ = trial(scenario=a, on_leaks=True)
    assert coverage_matrix(held2["results"] + viol2["results"])["cells"]["eff1"]["s1"] == "unstable"
    assert coverage_matrix([]) == {"rows": [], "cols": [], "cells": {}}
