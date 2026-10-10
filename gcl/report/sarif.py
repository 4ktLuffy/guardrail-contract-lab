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
