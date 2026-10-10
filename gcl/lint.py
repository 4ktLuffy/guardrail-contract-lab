"""Static hazards: regex syntax whose meaning depends on the engine that compiles it.

A lint hit is a *hazard*, not a verdict; `gcl check` then runs the rule in every
engine to confirm whether the hazard changes a real result. Each code says which
way it breaks, because "invalid in JS" (loud, if anyone logs it) and "means
something else in JS" (silent) are different risks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .rules import Rule


@dataclass
class Hazard:
    code: str
    level: str      # error: breaks in a common engine; warning: may diverge; note: FYI
    title: str
    detail: str
    rule_id: str
    offset: int = 0

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def _d(*parts: str) -> str:
    return " ".join(parts)


CODES = {
    "GCL101": ("error", "Global inline flag group", _d(
        "`(?i)`-style flag groups are Python syntax. JavaScript rejects them ('Invalid group');",
        "a loader that skips uncompilable rules drops this rule silently.",
        "If the loader already passes the flag, strip the group.")),
    "GCL102": ("warning", "Scoped inline modifiers", _d(
        "`(?i:…)` / `(?-i:…)` need ES2025 RegExp modifiers; older JavaScript engines reject",
        "the rule.")),
    "GCL103": ("warning", "Unicode-dependent \\w \\b \\d", _d(
        "Python's \\w, \\b and \\d are Unicode-aware; JavaScript's are ASCII-only (with or",
        "without the u flag). Next to non-Latin text the rule matches in Python and not in",
        "JavaScript.")),
    "GCL104": ("error", "Python-only named group", _d(
        "`(?P<name>…)` / `(?P=name)` are Python syntax; JavaScript uses (?<name>…).")),
    "GCL105": ("error", "\\A or \\Z anchor", _d(
        "Python anchors. In JavaScript without the u flag, \\A and \\Z are the literal",
        "letters 'A' and 'Z' — no error, different meaning.")),
    "GCL106": ("error", "Atomic group or possessive quantifier", _d(
        "Python 3.11+ only; JavaScript rejects it.")),
    "GCL107": ("note", "Lookbehind", _d(
        "Supported by current JavaScript engines, not by RE2/Go or old engines.")),
    "GCL108": ("warning", "Nested quantifier", _d(
        "A quantified group that itself contains + or * can backtrack catastrophically on",
        "long tool output (ReDoS). Confirmed by the timing check.")),
    "GCL109": ("note", "Case-folding hazard", _d(
        "Characters such as ß, İ, ı, ſ and the Kelvin sign fold differently across engines",
        "under case-insensitive matching.")),
    "GCL111": ("warning", "Dot and line terminators", _d(
        "`.` excludes only \\n in Python but also \\r, U+2028 and U+2029 in JavaScript: text",
        "with Windows line endings or Unicode separators matches differently.")),
    "GCL112": ("warning", "Multiline anchors and line terminators", _d(
        "With the m flag, JavaScript's ^ and $ also break at \\r, U+2028 and U+2029;",
        "Python's only at \\n.")),
    "GCL113": ("error", "Quantifier with no minimum", _d(
        "`{,n}` means 0 to n times in Python but is the literal text \"{,n}\" in",
        "JavaScript. Write `{0,n}`.")),
    "GCL110": ("warning", "Mixed-script letter class", _d(
        "A character class of Cyrillic/Greek letters that look Latin fires on ordinary text",
        "in that script. Homoglyph attacks are mixed script *within a token*; match",
        "adjacency instead.")),
}


# Hazards that only matter when a JavaScript engine loads the rules.
JS_ONLY = {"GCL101", "GCL102", "GCL103", "GCL104", "GCL105", "GCL106", "GCL107", "GCL111",
           "GCL112", "GCL113"}


def _range(a: int, b: int) -> str:
    return f"{chr(a)}-{chr(b)}"


# Characters whose case folding differs between engines (incl. KELVIN SIGN, ANGSTROM SIGN).
_FOLD = {"ß", "ẞ", "İ", "ı", "ſ", chr(0x212A), chr(0x212B)}
_GLOBAL_FLAGS = re.compile(r"\(\?[aiLmsux]+\)")
_SCOPED = re.compile(r"\(\?[imsx]*(?:-[imsx]+)?:")
_LATIN = re.compile(r"[A-Za-z]")
_CYR_GREEK = re.compile("[" + _range(0x0370, 0x03FF) + _range(0x0400, 0x04FF) + "]")
# Cyrillic and Greek letters that are visually identical to Latin ones.
_LOOKALIKE = set("аеорсухі") | set("αεορντ")


def _tokens(p: str):
    """Yield (offset, token, in_class) with escapes kept whole."""
    i, in_cls = 0, False
    while i < len(p):
        c = p[i]
        if c == "\\" and i + 1 < len(p):
            yield i, p[i:i + 2], in_cls
            i += 2
            continue
        if c == "[" and not in_cls:
            in_cls = True
            yield i, c, False
            j = i + 1
            if p[j:j + 1] == "^":
                j += 1
            if p[j:j + 1] == "]":
                j += 1  # literal ] first in a class
            for k in range(i + 1, j):
                yield k, p[k], True
            i = j
            continue
        if c == "]" and in_cls:
            in_cls = False
            yield i, c, False
            i += 1
            continue
        yield i, c, in_cls
        i += 1


def _classes(p: str):
    """Yield the raw text of each [...] character class."""
    start, buf = None, []
    for off, tok, in_cls in _tokens(p):
        if tok == "[" and not in_cls:
            start, buf = off, []
        elif tok == "]" and start is not None and not in_cls:
            yield start, "".join(buf)
            start = None
        elif start is not None:
            buf.append(tok)


def lint_rule(rule: Rule) -> list[Hazard]:
    p = rule.pattern
    found: dict[str, int] = {}

    def hit(code, off=0):
        found.setdefault(code, off)

    m = _GLOBAL_FLAGS.search(p)
    if m:
        hit("GCL101", m.start())
    for m in _SCOPED.finditer(p):
        if m.group(0) not in ("(?:",):
            hit("GCL102", m.start())
    if "(?P<" in p or "(?P=" in p:
        hit("GCL104", p.find("(?P"))
    if "(?>" in p:
        hit("GCL106", p.find("(?>"))
    if "(?<=" in p or "(?<!" in p:
        hit("GCL107", max(p.find("(?<="), p.find("(?<!")))

    non_ascii = any(ord(c) > 127 for c in p)
    non_english = rule.lang not in (None, "", "en")
    prev = ""
    for off, tok, in_cls in _tokens(p):
        if tok in ("\\w", "\\W", "\\b", "\\B", "\\d", "\\D") and (non_ascii or non_english):
            hit("GCL103", off)
        if tok in ("\\A", "\\Z") and not in_cls:
            hit("GCL105", off)
        if tok == "+" and not in_cls and prev in ("*", "+", "?", "}"):
            hit("GCL106", off)
        if not in_cls and len(tok) == 1 and tok in _FOLD:
            hit("GCL109", off)
        if not in_cls and tok == ".":
            hit("GCL111", off)
        if not in_cls and tok in ("^", "$") and prev != "[":
            hit("GCL112", off)
        if not in_cls and tok == "{" and re.match(r"\{,\d+\}", p[off:]):
            hit("GCL113", off)
        prev = tok if not in_cls else ""

    # Nested quantifier: a group whose body has + or * and which is itself quantified.
    for m in re.finditer(r"\((?:\?:)?([^()]*[+*][^()]*)\)[+*]", p):
        hit("GCL108", m.start())

    for off, body in _classes(p):
        if _LATIN.search(body) is None and _CYR_GREEK.search(body) and len(body) <= 40:
            # A class made only of Cyrillic/Greek letters that look Latin.
            n = sum(ch in _LOOKALIKE for ch in body)
            if n >= 4 and n >= len(body) * 0.6:
                hit("GCL110", off)

    out = []
    for code, off in found.items():
        level, title, detail = CODES[code]
        out.append(Hazard(code, level, title, detail, rule.id, off))
    return sorted(out, key=lambda h: h.code)


def lint(rules: list[Rule]) -> list[Hazard]:
    return [h for r in rules for h in lint_rule(r)]
