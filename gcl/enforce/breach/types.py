"""The vocabulary of a breach trial: Scenario, Trace, and the Target / Observer interfaces.

Two roles are kept strictly apart, as in `actions.py`: the `Target` is the thing under test and may
be wrong, flaky or lying; the `Observer`s are gcl's own independent readers of state and are the
only ones allowed to say whether an effect happened. Every hook a fake or a real component must
provide defaults to NotImplementedError, so a component that forgot one reads UNVERIFIED instead of
being quietly trusted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

CALIBRATION_KINDS = ("config", "version")


@dataclass(frozen=True)
class Scenario:
    """One test, with its claim kept narrow.

    forbidden_effect  what must not happen, narrowly enough that the observer set is complete for
                      THAT effect (G4). Breadth comes from more scenarios, never from one broad one.
    terminal_event    the EXACT event that counts as "the effect occurred" (G7), e.g. "the marker
                      value is durably recorded in the fixture store". A write that started and was
                      rolled back, or a request that never arrived, is NOT this event.
    protection_variable  the one name that is toggled between the OFF and ON run.
    calibration_kind  "config" (same build, protection setting on/off) or "version" (two builds):
                      different claims, labelled on every result and never mixed (G3).
    source            the channel the trigger arrives through; the columns of the coverage matrix.
    surfaces          the state surfaces the observers must be shown to see (k00l runs per surface).
    """
    id: str
    forbidden_effect: str
    terminal_event: str
    protection_variable: str
    calibration_kind: str
    source: str = "default"
    surfaces: tuple[str, ...] = ("store",)

    def __post_init__(self):
        if self.calibration_kind not in CALIBRATION_KINDS:
            raise ValueError(f"calibration_kind must be one of {CALIBRATION_KINDS}, got {self.calibration_kind!r}")
        for name in ("id", "forbidden_effect", "terminal_event", "protection_variable"):
            if not getattr(self, name).strip():
                raise ValueError(f"Scenario.{name} must not be empty: a vague scenario cannot be judged")
        if not self.surfaces:
            raise ValueError("Scenario.surfaces must name at least one surface to observe")

    def marker(self, run_id: str) -> str:
        """The unique benign marker for this run: it rides the injected content (reachability) and
        is the value the forbidden effect would record. Carries the run id so a stale or cached
        value from another run is not evidence."""
        return f"GCL-BRE-{self.id}-{run_id}"


@dataclass
class Trace:
    """What the driven interaction reports about ITSELF, for the gates that are about whether the
    run happened -- never about whether the effect did (only an Observer says that).

    marker_seen      the scenario's marker appeared in the driven interaction (G2)
    step_completed   the scripted step reached its decision point (the attempt was really made)
    finished/error   the completed-run flags of `actions.py`: a run that crashed, timed out or broke
                     its transport leaves state unmoved too, and that is not a block
    quiescent        set by the runner from `Target.drain()`, not by `drive`: background and delayed
                     work finished and observers were drained before judging (G7)
    """
    marker_seen: bool = False
    step_completed: bool = False
    finished: bool = False
    error: str = ""
    quiescent: bool = False
    log: list = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return self.finished and not self.error


class Target:
    """The component under test, started with its protection ON or OFF. Subclassed by fakes here
    and by a real component later."""

    name = "target"

    def start(self, protection: bool, run_id: str) -> None:
        """Start a FRESH instance (fresh home/config/fixtures: no state carries between runs, G5)
        with the protection ON (True) or OFF (False)."""
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError

    def manifest(self) -> dict:
        """Everything that defines the start: env, config, version, mounts, isolation. The runner
        diffs OFF against ON and demands that ONLY `scenario.protection_variable` differs (G5)."""
        raise NotImplementedError

    def liveness_nudge(self, surface: str) -> Callable[[], None]:
        """k00l: make ONE benign, observable change on `surface` straight through the observers'
        own fixture (never through the component) and return an undo that puts it back exactly. A
        nudge is only for proving an observer can see; it is NEVER calibration."""
        raise NotImplementedError

    def confirm_allowed(self) -> None:
        """Perform one benign, PERMITTED action through the real path. Whether it happened is judged
        by `Observer.saw_allowed`, not by anything returned here: a component's own say-so is what
        this control exists to distrust."""
        raise NotImplementedError

    def drive(self, scenario: Scenario, run_id: str) -> Trace:
        """Run the scripted interaction (the compromised-model attempt) and report what it saw."""
        raise NotImplementedError

    def drain(self) -> bool:
        """Wait until background/delayed work is quiescent and flushed; True only if that was
        established. False (or an exception) means the run cannot support an absence claim."""
        raise NotImplementedError


class Observer:
    """gcl's own independent reader of state. Decides; the Target's output never does."""

    name = "observer"
    surfaces: tuple[str, ...] = ("store",)

    def snapshot(self) -> dict:
        """The current state, read the same way before and after. Must come from something gcl
        reads itself, never from the component's reply."""
        raise NotImplementedError

    def saw_effect(self, before: dict, after: dict, scenario: Scenario) -> bool:
        """Did the scenario's EXACT terminal event occur between the two snapshots?"""
        raise NotImplementedError

    def saw_allowed(self, before: dict, after: dict, scenario: Scenario) -> bool:
        """Did the permitted benign action (`Target.confirm_allowed`) occur? NotImplementedError
        means this observer cannot confirm it, which leaves the control unverified."""
        raise NotImplementedError

    def is_live(self, surface: str) -> bool:
        """Does this observer claim to read `surface` at all? A necessary condition for k00l; the
        behavioural proof (a change gcl makes must be seen) is `actions.run_liveness`."""
        raise NotImplementedError

    def changed(self, before: dict, after: dict) -> bool:
        """For k00l: did a gcl-made nudge show up? Structural inequality by default."""
        return before != after

