"""Load a guardrail rule set into one flat, located list of rules.

Two shapes are accepted, YAML or JSON:

  * category map  {"categoryName": [{pattern, reason?, severity?, lang?, id?}, ...]}
  * flat list     [{pattern, category?, reason?, severity?, lang?, id?}, ...]

A plain string is accepted wherever a rule object is. Every rule keeps the line it
came from, so a finding can point at the exact place in the user's file (SARIF needs
it, and so does a reviewer).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Rule:
    id: str
    pattern: str
    category: str = ""
    reason: str = ""
    severity: str = ""
    lang: str | None = None
    flags: str | None = None  # the rule's own flags, JavaScript notation ("i", "gi"…)
    line: int | None = None  # 1-based line of the pattern in the source file

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v not in (None, "")}


@dataclass
class RuleSet:
    path: str
    sha256: str
    rules: list[Rule] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)  # entries we could not read


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _line_index(text: str) -> dict[tuple, int]:
    """Map (category, index) -> 1-based line of each rule, from the YAML node tree.

    JSON is valid YAML, so this works for both. Lines are best-effort: if the
    document does not compose (unusual), rules simply have no line.
    """
    try:
        root = yaml.compose(text)
    except yaml.YAMLError:
        return {}
    out: dict[tuple, int] = {}

    def item_line(node) -> int:
        if isinstance(node, yaml.MappingNode):
            for k, v in node.value:
                if isinstance(k, yaml.ScalarNode) and k.value == "pattern":
                    return v.start_mark.line + 1
        return node.start_mark.line + 1

    if isinstance(root, yaml.MappingNode):
        for k, v in root.value:
            if isinstance(v, yaml.SequenceNode):
                for i, item in enumerate(v.value):
                    out[(k.value, i)] = item_line(item)
    elif isinstance(root, yaml.SequenceNode):
        for i, item in enumerate(root.value):
            out[("", i)] = item_line(item)
    return out


def _coerce(entry, category: str, index: int, lines: dict, skipped: list) -> Rule | None:
    if isinstance(entry, str):
        entry = {"pattern": entry}
    if not isinstance(entry, dict) or not isinstance(entry.get("pattern"), str):
        skipped.append(f"{category or 'rules'}[{index}]: no string 'pattern'")
        return None
    cat = entry.get("category", category) or ""
    rid = str(entry.get("id") or f"{cat or 'rule'}[{index}]")
    return Rule(
        id=rid,
        pattern=entry["pattern"],
        category=cat,
        reason=str(entry.get("reason", "")),
        severity=str(entry.get("severity", "")),
        lang=entry.get("lang"),
        flags=str(entry["flags"]) if entry.get("flags") is not None else None,
        line=lines.get((category, index)),
    )


def load_rules(path: str | Path) -> RuleSet:
    p = Path(path)
    raw = p.read_bytes()
    text = raw.decode("utf-8")
    data = json.loads(text) if p.suffix == ".json" else yaml.safe_load(text)
    lines = _line_index(text)
    rs = RuleSet(path=str(p), sha256=_sha256(raw))
    if isinstance(data, dict):
        for category, entries in data.items():
            if not isinstance(entries, list):
                continue  # settings blocks and the like
            for i, e in enumerate(entries):
                r = _coerce(e, str(category), i, lines, rs.skipped)
                if r:
                    rs.rules.append(r)
    elif isinstance(data, list):
        for i, e in enumerate(data):
            r = _coerce(e, "", i, lines, rs.skipped)
            if r:
                rs.rules.append(r)
    else:
        raise ValueError(f"{p}: expected a mapping of categories or a list of rules")
    # Ids must be unique: reports, fixes and replays are keyed by them. A repeated id
    # gets the first free "#n" suffix, checked against every id in the file (so ids
    # "x, x, x#1" become "x, x#2, x#1", never two "x#1").
    taken = {r.id for r in rs.rules}
    used: set[str] = set()
    for r in rs.rules:
        if r.id in used:
            n = 1
            while f"{r.id}#{n}" in taken or f"{r.id}#{n}" in used:
                n += 1
            r.id = f"{r.id}#{n}"
        used.add(r.id)
    return rs


def load_cases(path: str | Path) -> list[dict]:
    """JSONL cases: {id, text, lang?, intent?, label?, kind?}. Blank lines ignored."""
    out = []
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        c = json.loads(line)
        if not isinstance(c, dict) or not isinstance(c.get("text"), str):
            raise ValueError(f"{path}:{n}: a case must be an object with a string 'text'")
        c.setdefault("id", f"case-{n}")
        if not isinstance(c["id"], (str, int)) or isinstance(c["id"], bool):
            raise ValueError(f"{path}:{n}: case 'id' must be a string or integer")
        out.append(c)
    seen: set = set()
    dup: list = []
    for c in out:  # encounter order; ids may mix strings and integers
        if c["id"] in seen and c["id"] not in dup:
            dup.append(c["id"])
        seen.add(c["id"])
    if dup:
        raise ValueError(f"{path}: duplicate case ids {dup[:5]} (answers are matched by id)")
    return out
