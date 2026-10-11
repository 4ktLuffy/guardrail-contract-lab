"""SARIF 2.1.0 for rule-located defects, so a CI code-scanning view can annotate the
exact line of the rule file. Only findings tied to a rule with a known line are
emitted; run-level problems (a missing engine) go in the run's notifications."""

from __future__ import annotations

from .. import __version__
from ..lint import CODES

_KINDS = {
    "compile_split": ("GCL201", "Rule does not compile in every engine"),
    "match_split": ("GCL202", "Engines disagree on a match"),
    "line_split": ("GCL206", "Engines disagree on line terminators"),
    "benign_hit": ("GCL203", "Rule fires on ordinary text"),
    "timeout": ("GCL204", "Rule hangs (catastrophic backtracking)"),
    "slow": ("GCL205", "Rule is slow on long input"),
}
_LEVEL = {"error": "error", "warning": "warning", "note": "note"}


def to_sarif(sec: dict) -> dict:
    path = sec["ruleset"]["path"]
    rules = sec["rules"]
    descriptors = [{"id": code, "name": title, "shortDescription": {"text": title},
                    "fullDescription": {"text": detail},
                    "defaultConfiguration": {"level": _LEVEL[level]}}
                   for code, (level, title, detail) in CODES.items()]
    descriptors += [{"id": code, "name": title, "shortDescription": {"text": title}}
                    for code, title in _KINDS.values()]
    results = []

    def loc(rule_id):
        line = rules.get(rule_id, {}).get("line")
        region = {"startLine": line} if line else {"startLine": 1}
        return [{"physicalLocation": {"artifactLocation": {"uri": path}, "region": region}}]

    for h in sec["hazards"]:
        results.append({"ruleId": h["code"], "level": _LEVEL[h["level"]],
                        "message": {"text": f"{h['title']} in rule {h['rule_id']}."},
                        "locations": loc(h["rule_id"])})
    notes = []
    for f in sec["findings"]:
        if f["kind"] not in _KINDS:
            notes.append({"level": "error", "message": {"text": f["detail"]}})
            continue
        msg = f"{f['title']} (rule {f['rule_id']}): {f['detail']}"
        if f.get("witness") is not None:
            msg += f" Minimal witness: {f['witness']!r}."
        results.append({"ruleId": _KINDS[f["kind"]][0], "level": _LEVEL[f["level"]],
                        "message": {"text": msg}, "locations": loc(f["rule_id"])})
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "guardrail-contract-lab", "version": __version__,
                                "informationUri": "https://github.com/4ktLuffy/guardrail-contract-lab",
                                "rules": descriptors}},
            "invocations": [{"executionSuccessful": sec["complete"],
                             "toolExecutionNotifications": notes}],
            "results": results,
        }],
    }


def enforce_sarif(runs, anchor: str) -> dict:
    """One SARIF result per scenario that is not a clean hold: violated (error), deviating
    from the integration's own docs (warning), or unverified (note) — guessed results say
    so. `runs` is one run or every run of a latency sweep (each result names its latency).
    Enforcement has no source line, so every result points at `anchor`, a file in the
    repository that names the integration under test; GitHub tells results apart by
    `primaryLocationLineHash`, which is set from the scenario's identity."""
    import hashlib

    runs = runs if isinstance(runs, list) else [runs]
    rules, results = {}, []
    for run in runs:
        i, lat = run["integration"], run.get("judge_latency_s")
        for r in run["results"]:
            s, ev = r["scenario"], r["evidence"]
            if r["policy"] == "held" and r["documented"] != "deviates":
                continue
            rid = f"GCL-E-{s['stage']}-{s['mode']}"
            rules.setdefault(rid, {"id": rid, "name": f"{s['stage']} {s['mode']}",
                                   "shortDescription": {"text": f"{s['stage']} stage, guard behaviour: {s['mode']}"}})
            level = "error" if r["policy"] == "violated" else ("warning" if r["documented"] == "deviates" else "note")
            ident = "/".join(str(x) for x in (i["integration"], i["profile"], s["stage"], s["mode"],
                                              s.get("role") or "", s["lang"], s.get("attack") or "",
                                              "" if lat is None else f"{lat:g}s"))
            guessed = " Rests on a guessed stand-in answer: confirm before reporting." \
                if ev.get("confidence") == "guessed" else ""
            what = f"attack {s['attack']} " if s.get("attack") else ""
            at = f" at guard latency {lat:g}s" if lat is not None else ""
            msg = (f"{i['integration']} ({i['profile']}): {what}{s['stage']} {s['mode']} [{s['lang']}]{at} "
                   f"observed {r['observed']}, policy {r['policy']}, docs {r['documented']}.{guessed} "
                   + " ".join(r["notes"][:3]))
            results.append({"ruleId": rid, "level": level, "message": {"text": msg.strip()},
                            "partialFingerprints": {
                                "primaryLocationLineHash": hashlib.sha256(ident.encode()).hexdigest()[:32],
                                "gclScenario": ident},
                            "properties": {"tags": ev.get("owasp") or [],
                                           "observed": r["observed"], "policy": r["policy"],
                                           "documented": r["documented"], "confidence": ev.get("confidence"),
                                           "attack": s.get("attack") or None, "judge_latency_s": lat,
                                           "run_id": (run.get("receipt") or {}).get("run_id")},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": anchor},
                                                                "region": {"startLine": 1}}}]})
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "guardrail-contract-lab", "version": __version__,
                                "informationUri": "https://github.com/4ktLuffy/guardrail-contract-lab",
                                "rules": list(rules.values())}},
            "invocations": [{"executionSuccessful": all(r["summary"]["unverified"] < r["summary"]["scenarios"]
                                                        for r in runs),
                             "properties": {"receipts": [r.get("receipt") for r in runs],
                                            "summaries": [r["summary"] for r in runs]}}],
            "results": results,
        }],
    }
