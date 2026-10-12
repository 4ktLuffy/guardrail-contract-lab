"""Config applied (`gcl enforce --extra config`): the configured guardrail policy is the one that runs.

Every other check in `gcl enforce` assumes the guard is configured and loaded. Three properties
decide whether it is:

  load failure  a policy that fails to load must not allow everything (one check per way the
                adapter declares a policy can fail to load: missing, malformed, an unknown guard type, ...)
  live edit     a policy edited while the integration runs takes effect (tighten: allow, then block;
                loosen: block, then allow; once per edit mechanism the adapter declares)
  scope         a scoped policy applies to its scope (scope X) and only to it (the other scope)

Proof, not log reading. The phase starts two stand-in scanners of the adapter's protocol, its own:
scanner A always answers allow, scanner B always answers block. The policy gcl hands the adapter
(neutral, see below) points a guard at A or at B. A request carries a sentinel `GCL-K-<id>-<run>`
in the user message, and which scanner received that sentinel is the proof of which policy was
running. The mock model's record says whether the request reached the provider. The client's
status is recorded; "stopped" needs the model to have never received the sentinel AND a complete
response (a timeout or transport failure is "no answer": unverified). A verdict that rests on a
scanner being consulted is never held without that receipt. "Refused to start" means the process
EXITED while starting; one that stays up and never becomes healthy is an error (unverified), since
a slow or hung start proves nothing.

  stopped   model never got the sentinel, a complete response arrived
  passed    the model got the sentinel
  no answer neither: unverified

The adapter translates the neutral policy into the integration's own configuration:

    {"guards": [{"name": "gcl-a", "scanner": "A" | "B", "scope": "*" | <adapter.config_scopes[i]>}],
     "broken": None | one of adapter.load_failures, "editable": bool}

`editable` is True only for the live-edit checks (and both of their policies): the adapter may then
need a different setup for them (LiteLLM: a database, because only guardrails created through its
management API can be edited). The framework does not say which check it is running, so the adapter
raises CheckUnavailable from start_policy when the setup cannot do it.

Controls first (k00c): with guard -> B on "*" a request must be stopped with B consulted, and with
guard -> A on "*" requests to both scopes must pass with A consulted. If they do not, every check is
unverified ("the controls did not hold: not evidence"). Each check also starts the integration fresh
and stops it afterwards; one that raises is unverified with the error and the others still run. The
phase runs after the ordinary snapshot (its traffic is not charged to an ordinary scenario) and the
results are ordinary result dicts (mode "config"), so reports, compare, findings and SARIF handle
them like any scenario.

A stricter-than-configured outcome (a loosening that did not apply, a stop outside the scope) is a
violation of the contract but not a leak: no OWASP tags. A stop outside the scope is only a violation
when scanner B was consulted; stopped without B consulted, something else may have stopped it:
unverified. A request that was stopped never proves the policy applied unless its scanner says so.
Each result also carries the documented verdict (conforms / deviates) where the adapter's
`config_documented` has an expectation for its kind, else unspecified.

Check ids (k01...) are assigned by `plan` in a fixed
order; every result also carries its kind ("load_failure:missing", "live_tighten:PATCH", ...).

Out of scope: the integration's own management APIs beyond what `edit_policy` reports, policies that
combine several guards, hot reload of anything but the policy.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass

from ..standards import config_risks
from .adapters import CheckUnavailable, StartRefused
from .servers import StandInScanner

PROBE_TEXT = "Please summarise this note."
SETTLE_S = 0.3        # quiet time after a probe before the evidence is read
EDIT_MARGIN_S = 0.5   # waited on top of the adapter's documented propagation time


@dataclass(frozen=True)
class Check:
    id: str
    name: str
    prop: str            # load_failure | live_edit | scope (an adapter's config_checks entry)
    description: str
    expect: str          # what the contract wants the probe to see: stopped | passed
    # kind: load_failure:<variant> | live_tighten:<mechanism> | live_loosen:<mechanism> | scope_in | scope_out
    kind: str = ""
    arg: str = ""        # the variant (broken) or the edit mechanism

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "property": self.prop, "check": self.kind,
                "description": self.description}


CONTROL = Check("k00c", "controls", "", "guard -> B must stop, guard -> A must pass, on both scopes", "")


def plan(adapter) -> list[Check]:
    """The checks this adapter can run, with ids assigned in a fixed order: one load-failure check
    per variant the adapter declares (k01, k02, ...), then tighten and loosen for each edit mechanism
    it declares, then the scope pair. Reports key on `kind`, never on an id number."""
    out: list[Check] = []

    def add(name, prop, description, expect, kind, arg=""):
        out.append(Check(f"k{len(out) + 1:02d}", name, prop, description, expect, kind, arg))

    caps = adapter.config_checks
    if "load_failure" in caps:
        for variant, what in adapter.load_failures.items():
            add(f"policy fails to load: {what}", "load_failure",
                f"start with the intended policy (guard -> B on every request) broken as: {what}", "stopped",
                f"load_failure:{variant}", variant)
    if "live_edit" in caps:
        many = len(adapter.edit_mechanisms) > 1
        for mech in adapter.edit_mechanisms:
            at = f" ({mech})" if many else ""
            add(f"live edit, tighten{at}", "live_edit", f"running with guard -> A (allow); edit to guard -> B "
                f"(block) by {mech}; the next request must be stopped", "stopped", f"live_tighten:{mech}", mech)
            add(f"live edit, loosen{at}", "live_edit", f"running with guard -> B (block); edit to guard -> A "
                f"(allow) by {mech}; the next request must pass", "passed", f"live_loosen:{mech}", mech)
    if "scope" in caps:
        add("scoped policy, in scope", "scope", "guard -> B scoped to scope X: a request to X must be stopped",
            "stopped", "scope_in")
        add("scoped policy, out of scope", "scope", "guard -> B scoped to scope X: a request to the other scope "
            "Y must pass, B not consulted", "passed", "scope_out")
    return out


def policy(scanner: str, scope: str = "*", broken: str | None = None, editable: bool = False) -> dict:
    """The neutral policy: one guard, pointed at scanner "A" or "B"."""
    return {"guards": [{"name": f"gcl-{scanner.lower()}", "scanner": scanner, "scope": scope}], "broken": broken,
            "editable": editable}


# --------------------------------------------------------------------------- probes
def _settle(model, scanners: dict, max_s: float = 3.0) -> None:
    """Wait until the model and both scanners are quiet: a late call is part of the evidence."""
    end = time.monotonic() + max_s
    while time.monotonic() < end:
        last = max([model.last_activity(), *(s.last_activity() for s in scanners.values())])
        busy = model.inflight or any(s.inflight for s in scanners.values())
        if not busy and time.monotonic() - last >= SETTLE_S:
            return
        time.sleep(0.05)


_LOG_KEEP = re.compile(r"[Gg]uardrail|PUT|PATCH|POST|DELETE|ERROR|WARNING|Immediate|Skipping|Exception|refus|fail")


def _log_evidence(log, keep: int = 40) -> str:
    """The lines of the integration's log that matter for a hand check (management calls, requests,
    guardrail messages, errors); traceback frames and cost-map warnings are left out."""
    try:
        lines = log.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    hits = [ln[:300] for ln in lines if _LOG_KEEP.search(ln) and not ln.startswith(" ") and "register_model" not in ln]
    return "\n".join(hits[-keep:])


def outcome_of(complete: bool, model_received: bool) -> str:
    return "passed" if model_received else ("stopped" if complete else "no answer")


def probe(adapter, model, scanners: dict, sentinel: str, scope: str, timeout_s: float) -> dict:
    """One request through `scope`, with what each observer recorded for its sentinel."""
    t0 = time.monotonic()
    obs = adapter.call_scope(scope, [{"role": "user", "content": f"{PROBE_TEXT} {sentinel}"}], timeout_s)
    _settle(model, scanners)
    received = any(sentinel in json.dumps(e["body"], ensure_ascii=False) for e in list(model.events)
                   if e["t"] >= t0)
    complete = bool(obs.finished and obs.status is not None and not obs.transport)
    return {"sentinel": sentinel, "scope": scope, "client_status": obs.status, "client_error": obs.error,
            "client_complete": complete, "model_received": received,
            "consulted": {k: s.consulted("input", sentinel) for k, s in scanners.items()},
            "outcome": outcome_of(complete, received)}


# --------------------------------------------------------------------------- verdicts
# Each returns (observed, policy, notes). Pure: unit-tested on synthetic probes.
def _asked(p: dict, who: str) -> str:
    n = p["consulted"][who]
    return f"scanner {who} was consulted {n} time(s)" if n else f"scanner {who} was never consulted"


def judge_controls(block: dict | None, allow: list[dict]) -> tuple[bool, list[str]]:
    """Both controls hold or the checks are not evidence. `block`: guard -> B on every request;
    `allow`: guard -> A, one probe per scope."""
    bad = []
    if block is None or block["outcome"] != "stopped" or not block["consulted"]["B"]:
        bad.append("with guard -> B a request was not stopped with B consulted"
                   + (f" ({block['outcome']}; {_asked(block, 'B')})" if block else ""))
    for p in allow:
        if p["outcome"] != "passed" or not p["consulted"]["A"]:
            bad.append(f"with guard -> A the request to {p['scope']} did not pass with A consulted "
                       f"({p['outcome']}; {_asked(p, 'A')})")
    if len(allow) != 2:
        bad.append("the guard -> A control did not probe both scopes")
    return not bad, bad


def judge_load(refused: bool, probe_: dict | None) -> tuple[str, str, list[str]]:
    if refused:
        return "refused to start", "held", ["refused to start with a policy it could not load"]
    if probe_ is None or probe_["outcome"] == "no answer":
        return "no answer", "unverified", ["it started, but the probe got no complete answer: unproven either way"]
    if probe_["outcome"] == "stopped":
        return "stopped", "held", [("started with a policy it could not load, and stopped the probe "
                                   f"({_asked(probe_, 'B')})")]
    note = "ran without its policy: everything allowed"
    if probe_["consulted"]["B"]:
        note += "; scanner B was consulted and answered block, and the request still reached the model"
    return "passed", "violated", [note]


def judge_edit(kind: str, pre: dict, edit: dict | None, post: dict | None) -> tuple[str, str, list[str]]:
    """kind "tighten" (A then B) or "loosen" (B then A). `pre` is the check's own control: the
    old policy must visibly run first. `edit` None: the edit was not made (pre-edit control failed)."""
    old = "A" if kind == "tighten" else "B"
    want_pre = "passed" if kind == "tighten" else "stopped"
    if pre["outcome"] != want_pre or not pre["consulted"][old]:
        return "control failed", "unverified", [
            (f"before the edit the request did not {'pass' if kind == 'tighten' else 'stop'} with {old} consulted "
            f"({pre['outcome']}; {_asked(pre, old)}): not evidence")]
    if edit is None:
        return "not run", "unverified", ["the edit was not made"]
    if not edit.get("acknowledged"):
        return "edit rejected", "n/a", [(f"the integration rejected the edit ({edit.get('detail', '')}): it told the "
                                        "truth, nothing to judge")]
    if post is None or post["outcome"] == "no answer":
        return "no answer", "unverified", ["after the edit the probe got no complete answer"]
    ack = (f" The integration acknowledged the edit ({edit.get('mechanism')}: {edit.get('detail', '')}) and it had "
           "no effect" + (": a success answer for an edit that changed nothing is the worst case." if kind == "tighten"
                          else "."))
    if kind == "tighten":
        if post["outcome"] == "stopped":
            if post["consulted"]["B"]:
                return "stopped", "held", ["after the edit the request was stopped with B consulted"]
            return "stopped", "unverified", [(f"stopped after the edit, but {_asked(post, 'B')}: not proof the new "
                                             "policy ran")]
        if post["consulted"]["A"] and not post["consulted"]["B"]:
            note = "the old policy kept running (A was consulted, B was not)"
        elif post["consulted"]["B"]:
            note = "B was consulted and answered block, yet the request reached the model"
        else:
            note = "neither scanner was consulted after the edit, and the request reached the model"
        return "passed", "violated", [note + "." + ack]
    if post["outcome"] == "passed":
        if post["consulted"]["A"]:
            return "passed", "held", ["after the edit the request passed with A consulted"]
        return "passed", "unverified", [(f"passed after the edit, but {_asked(post, 'A')}: not proof the new "
                                        "policy ran")]
    if post["consulted"]["B"]:
        return "stopped", "violated", ["the old policy kept running (B consulted): stricter than configured, "
                                       "not a leak." + ack]
    return "stopped", "unverified", [f"stopped after the edit, but {_asked(post, 'B')}: not proof the old policy ran"]


def judge_scope(kind: str, p: dict) -> tuple[str, str, list[str]]:
    """kind "in" (k06: the scope the policy names) or "out" (k07: the other scope)."""
    if p["outcome"] == "no answer":
        return "no answer", "unverified", ["the probe got no complete answer"]
    b = p["consulted"]["B"]
    if kind == "in":
        if p["outcome"] == "stopped":
            if b:
                return "stopped", "held", ["the request to the scope was stopped with B consulted"]
            return "stopped", "unverified", [f"stopped, but {_asked(p, 'B')}: not proof the scoped policy ran"]
        return "passed", "violated", ["the scoped policy did not apply to its scope"
                                      + ("; B was consulted and the request still reached the model" if b else "")]
    if p["outcome"] == "passed" and not b:
        return "passed", "held", ["the request to the other scope passed and B was never consulted"]
    if b:
        return p["outcome"], "violated", [("the policy applied outside its scope (B was consulted"
                                           + ("; the request still reached the model" if p["outcome"] == "passed"
                                              else "") + "): not a leak")]
    return p["outcome"], "unverified", [("the request to the other scope was stopped without B being consulted: "
                                         "something else stopped it, so this is not proof the policy applied "
                                         "outside its scope")]


# --------------------------------------------------------------------------- results
def documented_for(adapter, kind: str) -> list[str] | None:
    """The outcome(s) the adapter's docs promise for this check kind, or None (the docs say nothing).
    The full kind ("live_tighten:PATCH") wins over its prefix ("live_tighten")."""
    table = adapter.config_documented.get(adapter.profile, {})
    want = table.get(kind, table.get(kind.split(":")[0]))
    return None if want is None else ([want] if isinstance(want, str) else list(want))


def _result(chk: Check, run_id: str, sentinel: str, observed: str, pol: str, evidence: dict, notes: list[str],
            expect: list[str] | None = None) -> dict:
    """`expect`: what the adapter's docs promise for this kind (documented_for), or None."""
    from .contracts import Result, Scenario

    role = "control" if chk is CONTROL else ""
    sc = Scenario(chk.id, "input", "config", "en", "", "", run=run_id, role=role)
    # A documented verdict needs a real observation: unverified stays unverified, n/a stays n/a, and a
    # kind the docs do not cover (or the controls) stays unspecified.
    if pol in ("unverified", "n/a"):
        doc = pol
    elif expect and not role:
        doc = "conforms" if observed in expect else "deviates"
    else:
        doc = "unspecified"
    notes = list(notes)
    if pol == "violated" and doc == "conforms":
        notes.append("documented behaviour for this configuration (not a bug; a policy choice)")
    elif pol == "violated" and doc == "unspecified":
        notes.append("not covered by the integration's documentation")
    r = Result(sc, observed, chk.expect or "as configured", expect if not role else None, pol, doc, evidence,
               notes)
    d = r.to_dict()
    d["scenario"]["user_sentinel"] = d["scenario"]["reply_sentinel"] = sentinel
    d["scenario"]["config"] = chk.to_dict()
    d["evidence"]["check"] = chk.kind
    d["evidence"]["owasp"] = config_risks(chk.kind) if pol == "violated" else []
    return d


def _evidence(given: dict | list, probes: list[dict], **more) -> dict:
    last = probes[-1] if probes else {}
    return {"policy_given": given, "probes": probes, "edit": None, "start": "started",
            "scanner_a_consulted": (last.get("consulted") or {}).get("A", 0),
            "scanner_b_consulted": (last.get("consulted") or {}).get("B", 0),
            "model_received": last.get("model_received", False), "client_status": last.get("client_status"),
            "client_error": last.get("client_error", ""), "log_tail": "", **more}


def _unverified(chk: Check, run_id: str, note: str, observed: str = "not run", pol: str = "unverified",
                **ev) -> dict:
    return _result(chk, run_id, f"GCL-K-{chk.id}-{run_id}", observed, pol, _evidence({}, [], **ev), [note])


def selected(adapter, only: set[str] | None) -> list[Check]:
    """The planned checks `only` names (`k04`), or all; a filter that names none selects nothing."""
    checks = plan(adapter)
    if only is None:
        return checks
    ids = {i.removesuffix("c") for i in only}
    return [c for c in checks if c.id in ids]


def unverified_checks(adapter, run_id: str, only: set[str] | None, note: str) -> list[dict]:
    chosen = selected(adapter, only)
    return ([_unverified(CONTROL, run_id, note, "error")] if chosen else []) + [
        _unverified(c, run_id, note, "error") for c in chosen]


# --------------------------------------------------------------------------- the phase
class _Phase:
    def __init__(self, adapter, model, scanners: dict, run_id: str, timeout_s: float):
        self.adapter, self.model, self.scanners = adapter, model, scanners
        self.run_id, self.timeout_s = run_id, timeout_s
        self.x, self.y = adapter.config_scopes

    def expect(self, chk: Check) -> list[str] | None:
        return documented_for(self.adapter, chk.kind)

    def start(self, pol: dict) -> None:
        self.adapter.stop()
        self.adapter.start_policy(self.model, self.scanners, pol)

    def probe(self, tag: str, scope: str) -> dict:
        return probe(self.adapter, self.model, self.scanners, f"GCL-K-{tag}-{self.run_id}", scope, self.timeout_s)

    def controls(self) -> dict:
        given = [policy("B"), policy("A")]
        self.start(given[0])
        block = self.probe("k00b", self.x)
        self.adapter.stop()
        self.start(given[1])
        allow = [self.probe("k00ax", self.x), self.probe("k00ay", self.y)]
        ok, why = judge_controls(block, allow)
        return {"ok": ok, "why": why, "given": given, "probes": [block, *allow]}

    def check(self, chk: Check) -> dict:
        run = {"load_failure": self._load, "live_tighten": self._edit, "live_loosen": self._edit,
               "scope_in": self._scope, "scope_out": self._scope}[chk.kind.split(":")[0]]
        try:
            d = run(chk)
            if not d["evidence"]["log_tail"]:   # the integration's own log of this start, for the hand check
                d["evidence"]["log_tail"] = _log_evidence(self.adapter.log)
            return d
        except CheckUnavailable as e:  # the adapter knows this setup cannot run the check: say why
            return _unverified(chk, self.run_id, f"cannot be run here: {e}", "unavailable")
        except Exception as e:  # one check must not cost the others, or the ordinary run
            return _unverified(chk, self.run_id, f"error: {type(e).__name__}: {e}", "error")
        finally:
            self.adapter.stop()

    def _load(self, chk: Check) -> dict:
        given = policy("B", broken=chk.arg)
        try:
            self.start(given)
        except StartRefused as e:
            obs, pol, notes = judge_load(True, None)
            return _result(chk, self.run_id, f"GCL-K-{chk.id}-{self.run_id}", obs, pol,
                           _evidence(given, [], start="refused", log_tail=e.log_tail), notes, self.expect(chk))
        p = self.probe(chk.id, self.x)
        obs, pol, notes = judge_load(False, p)
        return _result(chk, self.run_id, p["sentinel"], obs, pol, _evidence(given, [p]), notes, self.expect(chk))

    def _edit(self, chk: Check) -> dict:
        kind = "tighten" if chk.kind.startswith("live_tighten") else "loosen"
        old, new = ("A", "B") if kind == "tighten" else ("B", "A")
        given = [policy(old, editable=True), policy(new, editable=True)]
        self.start(given[0])
        pre = self.probe(f"{chk.id}pre", self.x)
        edit = post = None
        if pre["outcome"] == ("passed" if kind == "tighten" else "stopped") and pre["consulted"][old]:
            edit = self.adapter.edit_policy(given[1], chk.arg)   # only once the old policy visibly runs
            edit = {**edit, "requested_mechanism": chk.arg}
            if edit.get("acknowledged"):
                time.sleep(self.adapter.propagation_s + EDIT_MARGIN_S)
                post = self.probe(chk.id, self.x)
        obs, pol, notes = judge_edit(kind, pre, edit, post)
        notes = [f"[edit by {chk.arg}] {n}" for n in notes]
        probes = [pre] + ([post] if post else [])
        return _result(chk, self.run_id, (post or pre)["sentinel"], obs, pol,
                       _evidence(given, probes, edit=edit), notes, self.expect(chk))

    def _scope(self, chk: Check) -> dict:
        given = policy("B", scope=self.x)
        self.start(given)
        inside = chk.kind == "scope_in"
        p = self.probe(chk.id, self.x if inside else self.y)
        obs, pol, notes = judge_scope("in" if inside else "out", p)
        return _result(chk, self.run_id, p["sentinel"], obs, pol, _evidence(given, [p]), notes, self.expect(chk))


def run_config(adapter, model, run_id: str, timeout_s: float, say=None, only: set[str] | None = None) -> list[dict]:
    """The controls, then each selected check; result dicts, the controls first (id k00c)."""
    say = say or (lambda *_: None)
    chosen = selected(adapter, only)
    if not chosen:
        return []
    out: list[dict] = []
    with StandInScanner(adapter.protocol) as a, StandInScanner(adapter.protocol) as b:
        a.configure({"input": "allow", "output": "allow"})
        b.configure({"input": "block", "output": "allow"})
        phase = _Phase(adapter, model, {"A": a, "B": b}, run_id, timeout_s)
        try:
            say("k00c: controls")
            try:
                ctl = phase.controls()
            except Exception as e:  # incl. CheckUnavailable: without controls nothing is evidence
                ctl = {"ok": False, "why": [f"error: {type(e).__name__}: {e}"], "given": [], "probes": []}
            finally:
                adapter.stop()
            out.append(_result(CONTROL, run_id, f"GCL-K-k00c-{run_id}",
                               "as configured" if ctl["ok"] else "not as configured",
                               "held" if ctl["ok"] else "unverified", _evidence(ctl["given"], ctl["probes"]),
                               [("guard -> B stopped the request with B consulted; guard -> A passed both scopes "
                                "with A consulted")] if ctl["ok"] else ctl["why"]))
            for chk in chosen:
                say(f"{chk.id}: {chk.name}")
                if not ctl["ok"]:
                    out.append(_unverified(chk, run_id, "the controls did not hold: not evidence"))
                else:
                    out.append(phase.check(chk))
        finally:
            adapter.stop()
    return out


def summarize(results: list[dict]) -> dict:
    """Counts by policy over the checks (not the controls); `controls` is the controls' own policy."""
    checks = [r for r in results if not r["scenario"]["role"]]
    ctl = next((r["policy"] for r in results if r["scenario"]["role"]), "")
    return {"checks": len(checks), **{p: sum(1 for r in checks if r["policy"] == p)
                                      for p in ("held", "violated", "unverified", "n/a")}, "controls": ctl}
