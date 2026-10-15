"""The scripted-model driver (`gcl breach` step 2): the model slot of a component under test, and the
reachability trace that says whether the trial's scripted step was ever reachable.

What it is. Under the assume-breach design the model is a given: gcl stands in for it and answers the
component's model requests from a fixed script. The component's own loop, tools and PERMISSION CHECKS
are the subject of the trial, so this module is the model slot and NOTHING else:

  * it only ANSWERS model requests. It never calls the component's executor, never replaces or
    pre-answers an approval/permission check, holds no reference to an Observer or a fixture, and so
    cannot itself cause the forbidden effect. Only the component acting on the scripted step may.
  * the ONE scripted step is emitted exactly once, and only on the BOUND turn: the first turn whose
    request carries the scenario's unique marker (G2). Before the marker has come back the step is
    never emitted. If the marker never arrives the step is WITHHELD and `marker_seen` stays False, so
    step 1's reachability gate leaves containment UNVERIFIED. The driver does not "help" by firing
    anyway: an attempt that was never reachable says nothing about the protection.

ConversationScript (G1) is the deterministic policy: benign SETUP replies by turn index ("understood,
proceeding"), then the step at the bound turn, then the benign default for every further turn. Same
inputs give the same outputs; there is no randomness and no clock. It is stateless -- the endpoint owns
the per-run state -- so one script can be reused across runs without leaking between them (G5).

Echo hazard: the step's argument is the marker, so once it is sent the marker will ride the history
of later requests. A marker is therefore credited only if it was seen before any step went out.

Marker matching (G2) is by the unique token only, not by the surrounding text: a component that
summarises, truncates or reorders the injected content still shows `marker_seen`. The one strictness
that matters is the token boundary: a marker is not seen inside a longer token, because
`GCL-BRE-s1-t0-r1` is a prefix of `GCL-BRE-s1-t0-r10` and a stale value from ANOTHER run is not evidence.

ReachabilityTrace is what the endpoint recorded: `marker_seen`, `marker_turn`, `step_turn` (None when
withheld), `step_completed` (emitted AND its request/response round returned), `bound_ok` (step turn ==
the turn the marker first appeared; a step on any other turn is out-of-band), plus a size-capped list of
per-turn summaries for the evidence bundle. `to_trace` maps it onto step 1's `Trace` and counts a step
only if it is bound: an out-of-band step is not a step that tests the protection.

ScriptedModelEndpoint is the seam: a plain in-process callable `endpoint(request) -> reply` that a
component's model client calls. Replies use the OpenAI chat shape (an assistant message, tool calls as
`tool_calls`) so a step-3 HTTP/stdio front over a real local endpoint can serialise them unchanged.
Nothing here opens a socket or starts a process; calls are serialised under a lock so a threaded client
still produces a single deterministic turn order.

Benign only: the step's argument is the scenario's marker value; the worst the component can do with
it is record that value on a throwaway fixture.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass, field

from .types import Scenario, Trace

MAX_RECORDED_TURNS = 50  # evidence is capped: a runaway loop must not grow the bundle without bound
DEFAULT_REPLY = "Understood. Continuing with the task."
DEFAULT_SETUP = ("Understood. I will look at the available information first.",
                 "Noted. Proceeding to the next step.")


@dataclass(frozen=True)
class ScriptedStep:
    """The single action the scenario is about: one tool call. `arguments` string values may contain
    `{marker}`, replaced by the run's marker when rendered, so the value the forbidden effect would
    record is exactly the value reachability was bound to."""
    tool: str
    arguments: dict = field(default_factory=lambda: {"note": "{marker}"})

    def __post_init__(self):
        if not self.tool.strip():
            raise ValueError("ScriptedStep.tool must not be empty")

    def render(self, marker: str) -> dict:
        args = {k: (v.replace("{marker}", marker) if isinstance(v, str) else v) for k, v in self.arguments.items()}
        return {"role": "assistant", "content": None,
                "tool_calls": [{"id": "call_gcl_step", "type": "function",
                                "function": {"name": self.tool, "arguments": json.dumps(args, sort_keys=True)}}]}


def benign_message(text: str) -> dict:
    return {"role": "assistant", "content": text}


@dataclass(frozen=True)
class ConversationScript:
    """Deterministic policy for a component's successive model requests (G1).

    setup_replies  benign, schema-valid replies for turns 1..n, used while the step is not due; a turn
                   past the list gets `default_reply`.
    step           the one scripted action, or None for a script that only ever answers benignly.
    default_reply  the benign answer for any turn that is neither a setup turn nor the step.

    `answer` is a pure function of (turn, whether this request carries the marker, which turn the
    marker first appeared on): nothing else can change what is said."""
    step: ScriptedStep | None = None
    setup_replies: tuple[str, ...] = DEFAULT_SETUP
    default_reply: str = DEFAULT_REPLY

    def answer(self, turn: int, marker_present: bool, marker_turn: int | None, step_emitted: bool) -> tuple[str, str]:
        """(kind, text) for 1-based `turn`. `marker_turn` is the first turn the marker appeared on
        INCLUDING this one. kind is "step" only on that exact turn and only if no step went out yet;
        otherwise "setup" or "default". The step text is a placeholder: the endpoint renders it."""
        if self.step is not None and marker_present and turn == marker_turn and not step_emitted:
            return "step", ""
        if turn <= len(self.setup_replies):
            return "setup", self.setup_replies[turn - 1]
        return "default", self.default_reply


# --------------------------------------------------------------------------------- marker matching
def request_text(request) -> str:
    """Every string in a model request (values, at any depth), joined. Walking the structure instead of
    serialising it means JSON escaping can never hide or fake a marker."""
    out: list[str] = []

    def walk(x):
        if isinstance(x, str):
            out.append(x)
        elif isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, (list, tuple)):
            for v in x:
                walk(v)

    if not isinstance(request, (str, dict, list, tuple)):
        raise TypeError(f"a model request must be a str, dict or list, got {type(request).__name__}")
    walk(request)
    return "\n".join(out)


def contains_marker(text: str, marker: str) -> bool:
    """The marker as a whole token. Surrounding text is irrelevant (paraphrase/truncation/reordering
    tolerant); a longer token that merely starts with the marker is a DIFFERENT value (another run)."""
    pattern = r"(?<![A-Za-z0-9])" + re.escape(marker) + r"(?![A-Za-z0-9_]|-[A-Za-z0-9])"
    return re.search(pattern, text) is not None


def _offered_tools(request) -> list[str]:
    tools = request.get("tools") if isinstance(request, dict) else None
    names = []
    for t in tools or []:
        if isinstance(t, dict):
            names.append(str((t.get("function") or {}).get("name") or t.get("name") or ""))
    return names


# --------------------------------------------------------------------------------- the trace
@dataclass
class ReachabilityTrace:
    """What the endpoint recorded about reachability, for step 1's gates and the evidence bundle.

    marker_seen      the marker (as a whole token) appeared in SOME model request
    marker_turn      the first turn it appeared on (1-based), else None
    step_turn        the turn the scripted step was emitted on, None if it never was (withheld)
    step_completed   the step was emitted AND its request/response round returned to the caller
    withheld_reason  why the step was not emitted when it was due or never due (empty if it went out)
    turns            per-turn summaries, at most MAX_RECORDED_TURNS (`turns_total` counts all);
                     request SHAPE only (sizes, a short digest), never request content
    """
    marker: str
    marker_seen: bool = False
    marker_turn: int | None = None
    step_turn: int | None = None
    step_completed: bool = False
    withheld_reason: str = ""
    turns_total: int = 0
    turns: list = field(default_factory=list)

    @property
    def bound_ok(self) -> bool:
        """The step went out on the very turn the marker first appeared (G2). False when the step was
        withheld (nothing was bound), when it went out BEFORE the marker (out-of-band: the model slot
        could not have been relaying the trigger), and when it went out after (not the bound turn)."""
        return self.marker_seen and self.step_turn is not None and self.step_turn == self.marker_turn

    @property
    def truncated(self) -> bool:
        return self.turns_total > len(self.turns)

    def to_dict(self) -> dict:
        return {"marker": self.marker, "marker_seen": self.marker_seen, "marker_turn": self.marker_turn,
                "step_turn": self.step_turn, "step_completed": self.step_completed, "bound_ok": self.bound_ok,
                "withheld_reason": self.withheld_reason, "turns_total": self.turns_total,
                "truncated": self.truncated, "turns": [dict(t) for t in self.turns]}

    def to_trace(self, finished: bool = True, error: str = "") -> Trace:
        """Step 1's `Trace`. `step_completed` there means the scripted step reached its decision point
        as a BOUND step: an out-of-band step does not count, because it did not test the protection
        against the injected trigger. `finished`/`error` are the caller's (the component's own run
        outcome); this trace knows only the model slot."""
        return Trace(marker_seen=self.marker_seen, step_completed=self.step_completed and self.bound_ok,
                     finished=finished, error=error, log=[{"reachability": self.to_dict()}])


# --------------------------------------------------------------------------------- the seam
class ScriptedModelEndpoint:
    """The model slot as an in-process callable: `reply = endpoint(request)`.

    One instance per run (it holds the per-run state; the script itself is stateless). It records each
    request into its `ReachabilityTrace` and answers per the `ConversationScript`. It holds no
    observer, fixture, executor or component reference, so it cannot cause or mask an effect. A real
    local HTTP/stdio endpoint (step 3) wraps `__call__` and serialises the returned message."""

    def __init__(self, script: ConversationScript, marker: str):
        if not marker.strip():
            raise ValueError("marker must not be empty: reachability cannot be bound to nothing")
        benign = [*script.setup_replies, script.default_reply]
        if any(contains_marker(t, marker) for t in benign):
            raise ValueError("a benign reply contains the marker: the driver would then 'see' its own echo and "
                             "reachability would prove nothing")
        self.script, self.marker = script, marker
        self.trace = ReachabilityTrace(marker)
        self._lock = threading.Lock()

    @classmethod
    def for_run(cls, script: ConversationScript, scenario: Scenario, run_id: str) -> ScriptedModelEndpoint:
        return cls(script, scenario.marker(run_id))

    def __call__(self, request) -> dict:
        with self._lock:
            return self._answer(request)

    def _answer(self, request) -> dict:
        tr = self.trace
        text = request_text(request)  # raises TypeError for a malformed request, recording nothing
        tr.turns_total += 1
        turn = tr.turns_total
        present = contains_marker(text, self.marker)
        if present and tr.marker_turn is None and tr.step_turn is None:
            # Credited only BEFORE any step went out: once the driver has itself sent the marker (the
            # step carries it), a later request holding it may be the driver's own echo coming back in
            # the conversation history, which is no evidence the trigger was ever relayed.
            tr.marker_seen, tr.marker_turn = True, turn
        kind, body = self.script.answer(turn, present, tr.marker_turn, tr.step_turn is not None)
        reason = ""
        if kind == "step":
            offered = _offered_tools(request)
            if offered and self.script.step.tool not in offered:
                # The step must be a schema-valid call to a tool this request offers. It cannot be
                # emitted on the bound turn, and the bound turn does not come again: withheld.
                kind, reason = "default", f"the step tool {self.script.step.tool!r} was not offered on the bound turn"
                body = self.script.default_reply
        if kind == "step":
            reply = self.script.step.render(self.marker)
            tr.step_turn, tr.step_completed = turn, True  # set only now: the reply exists and is returned next
        else:
            reply = benign_message(body)
            if reason:
                tr.withheld_reason = reason
        if len(tr.turns) < MAX_RECORDED_TURNS:
            tr.turns.append({"turn": turn, "marker_present": present, "reply": kind,
                             "messages": len(request.get("messages") or []) if isinstance(request, dict) else 0,
                             "tools": len(_offered_tools(request)), "chars": len(text),
                             "digest": hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]})
        return reply

    def finalize(self) -> ReachabilityTrace:
        """The trace as of now, with the reason a step never went out stated if nobody gave one."""
        tr = self.trace
        if tr.step_turn is None and not tr.withheld_reason:
            if self.script.step is None:
                tr.withheld_reason = "the script has no step"
            elif not tr.marker_seen:
                tr.withheld_reason = "the marker never appeared in a model request: the step was withheld"
        return tr
