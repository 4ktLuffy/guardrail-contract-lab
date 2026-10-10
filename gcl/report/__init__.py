"""One canonical result document; terminal, HTML and SARIF are views of it.

The JSON is the record: inputs with hashes, runtime versions, every finding with its
witness, and denominators for every number. Nothing in a view is computed that is
not in the JSON, so a reviewer can check a claim from the file alone.
"""

from __future__ import annotations

import datetime as _dt
import json
import platform
from pathlib import Path

from .. import __version__


def envelope(command: str, inputs: dict) -> dict:
    return {
        "tool": "guardrail-contract-lab",
        "version": __version__,
        "command": command,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "host": {"python": platform.python_version(), "platform": platform.platform()},
        "inputs": inputs,
    }


def check_section(res) -> dict:
    rules = {r.id: r.to_dict() for r in res.ruleset.rules}
    by_level: dict[str, int] = {}
    for f in res.findings:
        by_level[f.level] = by_level.get(f.level, 0) + 1
    affected = {f.rule_id for f in res.findings if f.rule_id != "*"}
    return {
        "ruleset": {"path": res.ruleset.path, "sha256": res.ruleset.sha256,
                    "rules": len(res.ruleset.rules), "skipped": res.ruleset.skipped},
        "engines": res.engines,
        "complete": res.complete,
        "stats": res.stats,
        "summary": {
            "rules": len(res.ruleset.rules),
            "rules_with_findings": len(affected),
            "compile_split": len(res.rules_with("compile_split")),
            "match_split": len(res.rules_with("match_split")),
            "line_split": len(res.rules_with("line_split") - res.rules_with("match_split")),
            "benign_hit": len(res.rules_with("benign_hit")),
            "timeout": len(res.rules_with("timeout")),
            "slow": len(res.rules_with("slow")),
            "hazards": len(res.hazards),
            "findings_by_level": by_level,
        },
        "hazards": [h.to_dict() for h in res.hazards],
        "findings": [f.to_dict() for f in res.findings],
        "rules": rules,
    }


def write_json(doc: dict, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    return p
