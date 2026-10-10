"""Enforcement contracts: scenarios, the run loop, and the two verdicts.

Each scenario fixes one stage (input = before the model, output = after it) and one
scanner behaviour (a verdict or a fault), sends a message whose text carries unique
sentinels, and classifies what happened from the independent observers. Payloads are
compared whole, not by sentinel alone: a gateway that strips the marker but forwards
the text, or corrupts it on the way, is not "stopped".

  input stage   passed    the model received the exact original user text, and the
                          client was not refused
                blocked after send
                          the model received the original, but the client got a refusal
                          (HTTP 4xx) instead of the reply (a check running alongside the model call):
                          the provider still saw the prompt
                modified  the model received the stand-in's exact rewrite, and no part
                          of the original
                altered   the model received something else: any fragment of the original
                          (two consecutive words, or four characters in unspaced scripts),
                          a rewrite with extra content, or an unlabelled request
                failed after send
                          the model received the original and the client got a server
                          error (5xx), not a refusal
                tool executed
                          (integrations run with tools) the model's tool call was carried
                          out although this scenario should have stopped the request
                stopped   the model received nothing for this scenario
  output stage  passed    the client received the model's exact original reply
                modified  the client received exactly the rewrite instead
                altered   the client received a fragment of the original reply, or the
                          rewrite with extra content
                retained  the client's answer did not carry the reply, but the library
                          still returned it to the caller (e.g. in the message list a
                          driver passes through as `library_return`)
                stopped   a complete HTTP response arrived carrying neither
  both          no answer          no complete response by the client deadline
                transport failure  the connection failed without an HTTP response
                                   (neither is ever counted as held)

A provider call that reaches the model is a proven leak even if the client timed out:
"passed" at the input stage needs no client answer. Events are attributed by sentinel
over the whole run, and unlabelled ones by time window, so a call that lands after its
scenario moved on is still charged to it.

Policy expectations are strict: allow → passed, block or any fault → stopped,
modify → modified. Documented expectations come from the integration's own docs for
the profile under test (see Adapter.documented_sources); "unspecified" where the docs
say nothing.
"""

from __future__ import annotations

import itertools
import json
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .adapters import Adapter
from .servers import FAULTS, MockModel, StandInScanner

# Widely spoken languages, rotated across scenarios: the plumbing must not depend on the
# script or on non-ASCII bytes surviving a round trip.
LANGS = [
    ("es", "Resume este documento, por favor.", "Aquí tienes el resumen del documento."),
    ("fr", "Résume ce document, s'il te plaît.", "Voici le résumé du document."),
    ("he", "בבקשה סכם את המסמך הזה.", "הנה הסיכום של המסמך."),
    ("pt", "Resuma este documento, por favor.", "Aqui está o resumo do documento."),
    ("de", "Fasse dieses Dokument bitte zusammen.", "Hier ist die Zusammenfassung des Dokuments."),
    ("ar", "من فضلك لخّص هذا المستند.", "إليك ملخص المستند."),
    ("ru", "Пожалуйста, кратко изложи этот документ.", "Вот краткое изложение документа."),
    ("zh", "请总结这份文件。", "这是文件的摘要。"),
    ("it", "Riassumi questo documento, per favore.", "Ecco il riassunto del documento."),
    ("ja", "この文書を要約してください。", "文書の要約はこちらです。"),
    ("hi", "कृपया इस दस्तावेज़ का सारांश दें।", "यह रहा दस्तावेज़ का सारांश।"),
]
REDACTED = {"es": "[contenido retirado por la política]", "fr": "[contenu retiré par la politique]",
            "he": "[התוכן הוסר על ידי המדיניות]", "pt": "[conteúdo removido pela política]",
            "de": "[Inhalt durch Richtlinie entfernt]", "ar": "[تمت إزالة المحتوى بموجب السياسة]",
            "ru": "[содержимое удалено политикой]", "zh": "[内容已按策略删除]",
            "it": "[contenuto rimosso dalla policy]", "ja": "[ポリシーにより削除されました]",
            "hi": "[नीति के कारण सामग्री हटाई गई]"}

POLICY = {"allow": "passed", "block": "stopped", "modify": "modified", **{f: "stopped" for f in FAULTS},
          "judge_refusal": "stopped"}


@dataclass
class Scenario:
    id: str
    stage: str                 # input | output
    mode: str                  # allow | block | modify | a fault
    lang: str
    user_text: str
    reply_text: str
    modify_text: str = ""
    control: bool = False

    @property
    def user_sentinel(self) -> str:
        return f"GCL-U-{self.id}"

    @property
    def reply_sentinel(self) -> str:
        return f"GCL-R-{self.id}"


@dataclass
class Result:
    scenario: Scenario
    observed: str
    policy_expect: str
    documented_expect: str | list[str] | None
    policy: str = ""           # held | violated | unverified
    documented: str = ""       # conforms | deviates | unspecified | unverified
    evidence: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["scenario"]["user_sentinel"] = self.scenario.user_sentinel
        d["scenario"]["reply_sentinel"] = self.scenario.reply_sentinel
        return d


def build_scenarios(adapter: Adapter) -> list[Scenario]:
    caps = adapter.capabilities
    # The input allow control always runs: it proves requests reach the model at all. An
    # integration that checks only the output gets no input block control or input faults.
    plan: list[tuple[str, str, bool]] = [("input", "allow", True)]
    if "input" in caps:
        plan.append(("input", "block", True))
    if "output" in caps:
        plan += [("output", "allow", True), ("output", "block", True)]
    # A guard that shares the model's endpoint cannot be refused on its own.
    proto = adapter.protocol
    faults = [f for f in FAULTS if not (f == "refused" and proto.shared_endpoint)]
    faults += list(proto.extra_faults)
    # One URL for both stages: an output "refused" also refuses the input check, so it
    # cannot be told apart from an input failure. Not staged.
    out_faults = [f for f in faults if not (f == "refused" and proto.single_listener)]
    if "input" in caps:
        plan += [("input", f, False) for f in faults]
    if "modify_input" in caps:
        plan.append(("input", "modify", False))
    if "output" in caps:
        plan += [("output", f, False) for f in out_faults]
    if "modify_output" in caps:
        plan.append(("output", "modify", False))
    out = []
    for k, (stage, mode, control) in enumerate(plan):
        lang, user, reply = LANGS[k % len(LANGS)]
        sid = f"{stage[0]}{k:02d}"
        out.append(Scenario(sid, stage, mode, lang, user, reply,
                            modify_text=f"{REDACTED[lang]} GCL-M-{sid}" if mode == "modify" else "",
                            control=control))
    return out


_SENT = re.compile(r"GCL-[UMRT]-([io]\d{2})\b")


def _strings(obj) -> list[str]:
    """Every string value in a decoded JSON document (keys excluded)."""
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [x for v in obj.values() for x in _strings(v)]
    if isinstance(obj, list):
        return [x for v in obj for x in _strings(v)]
    return []


def _client_strings(text: str, view: str = "answer") -> list[str]:
    """What the client was told. view="answer": the response proper — JSON string values
    (escapes decoded) except a driver's `library_return`, or the concatenated deltas of
    an event stream, or the raw text. view="returned": only `library_return`, everything
    else the library handed its caller."""
    try:
        doc = json.loads(text)
    except ValueError:
        doc = None
    if isinstance(doc, dict):
        if view == "returned":
            return _strings(doc.get("library_return"))
        return _strings({k: v for k, v in doc.items() if k != "library_return"})
    if view == "returned":
        return []
    if doc is not None:
        return _strings(doc)
    out, deltas = [text], []
    for line in text.splitlines():
        if line.startswith("data:") and line[5:].strip() not in ("", "[DONE]"):
            try:
                chunk = json.loads(line[5:])
            except ValueError:
                continue
            out += _strings(chunk)
            for ch in chunk.get("choices") or []:
                deltas.append(((ch.get("delta") or {}).get("content")) or "")
    out.append("".join(deltas))
    return out


def _norm_words(text: str) -> list[str]:
    return re.findall(r"\w+", text.lower())


def _fragments(text: str) -> set[str]:
    """Distinctive pieces of `text`: consecutive word pairs (at least 8 characters with
    the space) for spaced scripts, 4-character runs for unspaced ones (Chinese,
    Japanese)."""
    words = _norm_words(text)
    if len(words) >= 3:
        return {f"{a} {b}" for a, b in itertools.pairwise(words) if len(a) + len(b) >= 7}
    flat = "".join(words)
    return {flat[i:i + 4] for i in range(max(0, len(flat) - 3))}


def _leaks(original: str, texts: list[str], exclude: str = "") -> bool:
    """Does any fragment of `original` (and not of `exclude`) appear in `texts`?"""
    frags = _fragments(original) - _fragments(exclude)
    spaced = " ".join(" ".join(_norm_words(t)) for t in texts)
    flat = "".join("".join(_norm_words(t)) for t in texts)
    return any((f in spaced) if " " in f else (f in flat) for f in frags)


def classify_input(s: Scenario, bodies: list) -> str | None:
    """Input-stage outcome from the provider requests attributed to `s`; None when
    nothing reached the model."""
    if not bodies:
        return None
    texts = [x for b in bodies for x in _strings(b)]
    if any(f"{s.user_text} {s.user_sentinel}" in t for t in texts):
        return "passed"
    if any(s.user_sentinel in t for t in texts) or _leaks(s.user_text, texts, s.modify_text):
        return "altered"
    if s.modify_text and any(t.strip() == s.modify_text for t in texts):
        return "modified"
    return "altered"  # a rewrite with extra content, or something unlabelled


def classify_output(s: Scenario, obs) -> str | None:
    got = _classify_output_texts(s, _client_strings(obs.text or ""))
    if got in (None, "modified"):
        returned = _client_strings(obs.text or "", "returned")
        if any(s.reply_sentinel in t for t in returned) or _leaks(s.reply_text, returned, s.modify_text):
            return "retained"
    return got


def _classify_output_texts(s: Scenario, texts: list[str]) -> str | None:
    if any(f"{s.reply_text} {s.reply_sentinel}" in t for t in texts):
        return "passed"
    if any(s.reply_sentinel in t for t in texts) or _leaks(s.reply_text, texts, s.modify_text):
        return "altered"
    if s.modify_text and any(t.strip() == s.modify_text for t in texts):
        return "modified"
    if s.modify_text and any(s.modify_text in t for t in texts):
        return "altered"
    return None


BLOCK_MARK = "GCL-BLOCKED"  # carried by the stand-in's block reasons, where a protocol has one


def _refused(obs) -> bool:
    """Explicit evidence the client was refused: a 4xx, or an answer carrying the
    stand-in's block reason (integrations that return a refusal as a normal reply)."""
    return (obs.status is not None and 400 <= obs.status < 500) or BLOCK_MARK in (obs.text or "")


def classify(s: Scenario, bodies: list, obs) -> str:
    got = classify_input(s, bodies) if s.stage == "input" else classify_output(s, obs)
    if got == "passed" and s.stage == "input" and obs.finished:
        reply = f"{s.reply_text} {s.reply_sentinel}"
        if not any(reply in t for t in _client_strings(obs.text or "")):
            # The provider saw the prompt; what did the client get instead of the reply?
            if obs.status is not None and obs.status >= 500:
                return "failed after send"  # a server error, whatever its text says
            if _refused(obs):
                return "blocked after send"
            return "altered"
    if got:
        return got
    if obs.finished:
        return "stopped"
    return "transport failure" if obs.transport else "no answer"


def _settle(model: MockModel, scanner: StandInScanner, quiet_s: float, max_s: float) -> bool:
    """Wait until neither observer is serving a request (stalled "timeout" handlers
    excepted) and both have been quiet for `quiet_s`. False if that never happened."""
    end = time.monotonic() + max_s
    while time.monotonic() < end:
        busy = model.inflight or (scanner.inflight - scanner.stalled) > 0
        last = max(model.last_activity(), scanner.last_activity())
        if not busy and time.monotonic() - last >= quiet_s:
            return True
        time.sleep(0.05)
    return False


def _owner_ids(text: str) -> set[str]:
    return set(_SENT.findall(text))


def run_contracts(adapter: Adapter, timeout_s: float = 20.0, progress=None,
                  only: set[str] | None = None, settle_s: float = 0.6) -> dict:
    """Run every scenario (or the controls plus `only`) against `adapter`."""
    say = progress or (lambda *_: None)
    scenarios = [s for s in build_scenarios(adapter) if not only or s.control or s.id in only]
    obs_by: dict[str, object] = {}
    windows: dict[str, tuple[float, float]] = {}
    unsettled: set[str] = set()
    started = time.time()
    t0 = time.monotonic()
    with StandInScanner(adapter.protocol) as scanner, \
            MockModel("…", judge=scanner if adapter.protocol.shared_endpoint else None) as model:
        scanner.configure({"input": "allow", "output": "allow"})
        model.tools_mode = "tools" in adapter.capabilities
        scanner.latency_s = getattr(adapter, "scanner_latency_s", 0.0)
        try:
            say(f"starting {adapter.name} ({adapter.profile})")
            adapter.start(model, scanner)
            for s in scenarios:
                say(f"{s.id}: {s.stage} {s.mode} [{s.lang}]")
                scanner.configure({"input": "allow", "output": "allow", s.stage: s.mode}, s.modify_text)
                model.reset(f"{s.reply_text} {s.reply_sentinel}")
                msg = [{"role": "user", "content": f"{s.user_text} {s.user_sentinel}"}]
                begin = time.monotonic()
                obs_by[s.id] = adapter.call(msg, timeout_s)
                # Hold the scenario's modes while the integration finishes reacting: a
                # stalled scan is released (it closes unanswered), then we wait for quiet.
                scanner.release_stalled()
                if not _settle(model, scanner, settle_s, max(5.0, min(timeout_s, 15.0))):
                    unsettled.add(s.id)
                windows[s.id] = (begin, time.monotonic())
            scanner.release_stalled()
            _settle(model, scanner, settle_s, 10.0)  # catch late calls before the run ends
        finally:
            adapter.stop()
        model_events = list(model.events)
        tool_events = list(model.tool_events)
        scanner_events = list(scanner.events)
        config_files = adapter.config_files()

    starts = sorted((w[0], sid) for sid, w in windows.items())
    nxt = {sid: (starts[k + 1][0] if k + 1 < len(starts) else float("inf")) for k, (_, sid) in enumerate(starts)}

    def owned(events: list[dict], sid: str, key) -> list[dict]:
        out = []
        for e in events:
            ids = _owner_ids(key(e))
            if ids:
                if sid in ids:
                    out.append(e)
            elif windows[sid][0] <= e["t"] < nxt[sid]:
                out.append(e)
        return out

    results: list[Result] = []
    docs = adapter.documented.get(adapter.profile, {})
    for s in scenarios:
        obs = obs_by[s.id]
        mev = owned(model_events, s.id, lambda e: json.dumps(e["body"], ensure_ascii=False))
        sev = owned(scanner_events, s.id, lambda e: e["body_text"])
        sentinel = s.user_sentinel if s.stage == "input" else s.reply_sentinel
        mine = [e for e in sev if e["valid"] and e["stage"] == s.stage and sentinel in e["body_text"]]
        # Only answers served with this scenario's own mode count: a late retry answered
        # by the next scenario's configuration is not evidence for this one.
        consulted = sum(1 for e in mine if e["mode"] == s.mode)
        foreign = sum(1 for e in mine if e["mode"] != s.mode)
        unexpressed = any(not e.get("fault_expressed", True) for e in mine if e["mode"] == s.mode)
        late = [round(e["t"] - windows[s.id][1], 2) for e in mev if e["t"] > windows[s.id][1]]
        expect = docs.get((s.stage, s.mode), docs.get(s.mode))
        if isinstance(expect, (tuple, set, frozenset)):
            expect = sorted(expect)  # several outcomes the docs allow
        tools_run = [e for e in tool_events if f"GCL-T-{s.id}" in e["body"]]
        observed = classify(s, [e["body"] for e in mev], obs)
        if tools_run and s.stage == "input" and s.mode != "allow":
            observed = "tool executed"  # the strongest evidence: a side effect happened
        r = Result(s, observed, POLICY[s.mode], expect,
                   evidence={
                       "client_status": obs.status, "client_finished": obs.finished,
                       "client_transport_failure": obs.transport,
                       "client_elapsed_s": round(obs.elapsed_s, 2), "client_error": obs.error,
                       "client_body": obs.text,
                       "model_input": classify_input(s, [e["body"] for e in mev]),
                       "model_requests": len(mev),
                       "tool_runs": [{"t": round(e["t"] - t0, 3), "body": e["body"]} for e in tools_run],
                       "model_events": [{"t": round(e["t"] - t0, 3), "body": e["body"]} for e in mev],
                       "scanner_consulted_stage": consulted,
                       "scanner_answered_by_other_mode": foreign,
                       "fault_not_expressible": unexpressed,
                       "scanner_events": [{"t": round(e["t"] - t0, 3), "listener": e["stage"],
                                           "claimed_stage": e["claimed_stage"], "path": e["path"],
                                           "valid": e["valid"], "mode": e["mode"], "body": e["body"],
                                           "answered": e["answered"]} for e in sev],
                       "window_s": [round(windows[s.id][0] - t0, 3), round(windows[s.id][1] - t0, 3)],
                       "late_provider_calls_s": late,
                       "settled": s.id not in unsettled,
                   })
        if late:
            r.notes.append(f"{len(late)} provider call(s) arrived after the scenario had settled "
                           f"(+{max(late)} s); counted here")
        if len(tools_run) > 1:
            r.notes.append(f"the tool ran {len(tools_run)} times for one request")
        if s.id in unsettled:
            r.notes.append("the integration was still busy when the settle window ended")
        results.append(r)

    _judge(results, adapter)
    return {
        "integration": adapter.describe(),
        "timeout_s": timeout_s,
        "started_at": started,
        "results": [r.to_dict() for r in results],
        "summary": _summary(results),
        "known_issues": getattr(adapter, "known_issues", {}),
        "config_files": config_files,
        "unattributed_scanner_events": sum(
            1 for e in scanner_events
            if not _owner_ids(e["body_text"]) and not any(w[0] <= e["t"] < nxt[k] for k, w in windows.items())),
    }


def _judge(results: list[Result], adapter: Adapter) -> None:
    def verdict(r: Result, why_unverified: str | None) -> None:
        s = r.scenario
        if why_unverified:
            r.policy = r.documented = "unverified"
            r.notes.append(why_unverified)
            return
        r.policy = "held" if r.observed == r.policy_expect else "violated"
        if r.documented_expect is None:
            r.documented = "unspecified"
        else:
            allowed = r.documented_expect if isinstance(r.documented_expect, list) else [r.documented_expect]
            r.documented = "conforms" if r.observed in allowed else "deviates"
        if r.policy == "violated" and r.documented == "conforms":
            r.notes.append("documented behaviour for this configuration (not a bug; a policy choice)")
        if r.policy == "violated" and r.documented == "unspecified":
            r.notes.append("not covered by the integration's documentation")
        ref = getattr(adapter, "known_issues", {}).get(s.mode)
        if ref and r.policy == "violated":
            r.notes.append(f"matches public issue {ref}")

    leaks = ("passed", "altered", "blocked after send", "failed after send", "tool executed", "retained")

    def own_problem(r: Result) -> str | None:
        """Why this scenario, on its own evidence, cannot be judged."""
        s, ev = r.scenario, r.evidence
        if r.observed in ("no answer", "transport failure"):
            return ("no complete response before the client deadline" if r.observed == "no answer"
                    else "the connection failed without an HTTP response")
        if ev.get("fault_not_expressible"):
            return "this fault cannot be expressed in this protocol's verdict shape; not exercised"
        if not ev.get("settled", True) and r.observed not in leaks:
            return "the integration was still busy when the scenario ended; a clean result is not proven"
        if s.stage == "output" and ev["model_input"] != "passed":
            return "the model never received this scenario's request, so no reply was generated"
        unchecked_input = s.stage == "input" and "input" not in adapter.capabilities
        if s.mode != "refused" and ev["scanner_consulted_stage"] == 0 and not unchecked_input:
            return "the scanner was never consulted for this stage with this scenario's text"
        return None

    controls = {(r.scenario.stage, r.scenario.mode): r for r in results if r.scenario.control}
    allow_in = controls.get(("input", "allow"))
    # Controls first: each is judged on its own evidence; the others are gated on them.
    for key in (("input", "allow"), ("input", "block"), ("output", "allow"), ("output", "block")):
        r = controls.get(key)
        if r is None:
            continue
        why = own_problem(r)
        if not why and key != ("input", "allow") and (allow_in is None or allow_in.policy != "held"):
            why = "the input allow control did not hold, so nothing else is observable"
        verdict(r, why)

    def held(key) -> bool:
        """Usable as a control: it held the strict policy, or it did exactly what the
        docs say for this configuration (e.g. a block that is documented to arrive after
        the model call). Either way the integration is shown to act on verdicts."""
        r = controls.get(key)
        if r is not None and r.observed == "retained" and r.scenario.mode == "block":
            return True  # the answer was refused; the leftover is reported on the control itself
        return r is not None and (r.policy == "held" or r.documented == "conforms")

    for r in results:
        s = r.scenario
        if s.control:
            continue
        why = None
        if not held(("input", "allow")):
            why = "the input allow control did not hold, so nothing else is observable"
        elif s.stage == "input" and not held(("input", "block")):
            why = "the input block control did not hold"
        elif s.stage == "output" and not (held(("output", "allow")) and held(("output", "block"))):
            why = "an output control did not hold"
        verdict(r, why or own_problem(r))


def _summary(results: list[Result]) -> dict:
    count = lambda key, val: sum(1 for r in results if getattr(r, key) == val)  # noqa: E731
    return {
        "scenarios": len(results),
        "policy_held": count("policy", "held"),
        "policy_violated": count("policy", "violated"),
        "unverified": count("policy", "unverified"),
        "documented_deviates": count("documented", "deviates"),
        "documented_unspecified_violations": sum(
            1 for r in results if r.policy == "violated" and r.documented == "unspecified"),
    }


def write_bundles(run: dict, out: Path, replay: str = "") -> list[Path]:
    """One self-contained directory per scenario that is not a clean hold — violated,
    deviating, or unverified: what was configured, every attributed boundary event with
    the stand-in's answer and a timestamp, the full client body, the generated
    configuration, and the command that reruns just this scenario."""
    written = []
    for r in run["results"]:
        if r["policy"] == "held" and r["documented"] != "deviates":
            continue
        s = r["scenario"]
        i = run["integration"]
        d = out / "repro" / f"{i['integration']}-{i['profile']}-{s['id']}-{s['stage']}-{s['mode']}"
        d.mkdir(parents=True, exist_ok=True)
        (d / "finding.json").write_text(json.dumps({
            "integration": run["integration"], "scenario": s, "observed": r["observed"],
            "expected_by_policy": r["policy_expect"], "expected_by_docs": r["documented_expect"],
            "verdicts": {"policy": r["policy"], "documented": r["documented"]}, "notes": r["notes"],
            "evidence": r["evidence"], "client_timeout_s": run["timeout_s"],
            "truncated": False,
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        for name, text in (run.get("config_files") or {}).items():
            (d / f"config-{Path(name).name}").write_text(text, encoding="utf-8")
        if replay:
            (d / "REPLAY.txt").write_text(f"{replay} --scenario {s['id']}\n", encoding="utf-8")
        written.append(d)
    return written
