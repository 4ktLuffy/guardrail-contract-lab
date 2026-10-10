"""`gcl fix`: rewrite rules so every engine reads them the way Python does.

Python is the reference: on every input we test, the fixed rule must agree with the
original rule under Python `re`, and now agree in JavaScript too. Agreement on tested
inputs is evidence, not a proof; the rewrite is exact by construction only for text in
the scripts it names (see letter_class). Rewrites, each one
exact under the stated condition:

  * leading global flag group `(?i)` / `(?im)` — dropped when every engine's loader
    already applies those flags;
  * `\\A` → `(?<![\\s\\S])`, `\\Z` → `(?![\\s\\S])` — start/end of input in both engines;
  * `(?P<name>…)` → `(…)` when the name is never back-referenced;
  * `\\w`, `\\W`, `\\b` → explicit letter classes for the scripts the rule uses, and
    `\\b` → a single lookbehind/lookahead where the neighbouring token is provably a
    letter (much cheaper in Python than the full two-sided boundary).

Anything else (scoped modifiers, catastrophic nesting, script-blind classes) is not
auto-fixable and is reported, not touched. The YAML is edited in place at the
pattern scalars only, so comments and layout survive.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .rules import Rule

BS = "\\"


def _u(cp: int) -> str:
    """A \\uXXXX escape as regex source text (kept as an escape so files stay readable)."""
    return f"{BS}u{cp:04X}"


def _rng(a: int, b: int) -> str:
    return f"{_u(a)}-{_u(b)}"


# Letter ranges per script. A rule gets ASCII word characters plus the ranges of the
# scripts its literals (or its declared lang) use.
# Scripts a rewritten rule can be made exact for. A script is defined by Unicode
# character names: every Basic-Multilingual-Plane character that Python's \\w matches
# and whose name starts with the script's word ("LATIN SMALL LETTER H WITH HOOK",
# "CYRILLIC CAPITAL LETTER ZHE", …). That covers whole scripts, extensions included,
# rather than hand-picked blocks. COMMON word characters (digits, super/subscripts,
# fractions, fullwidth forms, Roman numerals, ordinal indicators, micro sign) are always
# included. Characters outside the BMP cannot appear in a JavaScript class without the
# u flag, so astral-plane letters are always out of scope.
SCRIPTS = {
    "latin": ("LATIN",), "greek": ("GREEK",), "cyrillic": ("CYRILLIC",),
    "armenian": ("ARMENIAN",), "hebrew": ("HEBREW",), "arabic": ("ARABIC",),
    "devanagari": ("DEVANAGARI",), "thai": ("THAI",), "ethiopic": ("ETHIOPIC",),
    "cjk": ("CJK", "HIRAGANA", "KATAKANA"), "hangul": ("HANGUL",),
}
COMMON = ("DIGIT", "SUPERSCRIPT", "SUBSCRIPT", "VULGAR", "FULLWIDTH", "ROMAN",
          "FEMININE", "MASCULINE", "MICRO",
          # Letterlike signs that case-fold onto letters (KELVIN SIGN ~ k, ANGSTROM SIGN ~ å,
          # OHM SIGN ~ ω): they sit next to Latin/Greek text in practice.
          "KELVIN", "ANGSTROM", "OHM")
LANG_SCRIPT = {"ru": "cyrillic", "uk": "cyrillic", "bg": "cyrillic", "el": "greek",
               "hy": "armenian", "he": "hebrew", "ar": "arabic", "fa": "arabic",
               "ur": "arabic", "hi": "devanagari", "th": "thai", "am": "ethiopic",
               "zh": "cjk", "ja": "cjk", "ko": "hangul"}

_BY_WORD: dict[str, list[int]] | None = None


def _word_chars_by_name() -> dict[str, list[int]]:
    """BMP code points matched by Python's \\w, grouped by the first word of their name."""
    global _BY_WORD
    if _BY_WORD is None:
        import unicodedata

        w = re.compile(r"\w")
        groups: dict[str, list[int]] = {}
        for cp in range(0x80, 0x10000):
            ch = chr(cp)
            if 0xD800 <= cp <= 0xDFFF or not w.fullmatch(ch):
                continue
            try:
                first = unicodedata.name(ch).split()[0].split("-")[0]
            except ValueError:
                continue
            groups.setdefault(first, []).append(cp)
        _BY_WORD = groups
    return _BY_WORD


def _code_points(scripts: list[str]) -> list[int]:
    by = _word_chars_by_name()
    words = list(COMMON) + [w for s in scripts for w in SCRIPTS[s]]
    return sorted({cp for w in words for cp in by.get(w, [])})


def _ranges(cps: list[int]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for cp in cps:
        if out and cp == out[-1][1] + 1:
            out[-1] = (out[-1][0], cp)
        else:
            out.append((cp, cp))
    return out


def scripts_of(pattern: str, lang: str | None) -> list[str]:
    """Scripts a rule touches: Latin always, plus any script its literals or lang use."""
    import unicodedata

    found = {"latin"}
    for ch in pattern:
        if ord(ch) < 0x80:
            continue
        try:
            first = unicodedata.name(ch).split()[0].split("-")[0]
        except ValueError:
            continue
        for name, words in SCRIPTS.items():
            if first in words:
                found.add(name)
    if lang and lang.split("-")[0] in LANG_SCRIPT:
        found.add(LANG_SCRIPT[lang.split("-")[0]])
    return sorted(found)


def letter_class(scripts: list[str]) -> str:
    """ASCII word characters, plus Python-\\w characters of the named scripts and COMMON.
    An empty list means ASCII only (what Python's \\w is under re.ASCII)."""
    parts = ["0-9A-Za-z_"]
    if scripts:
        for x, y in _ranges(_code_points(scripts)):
            parts.append(_u(x) if x == y else _rng(x, y))
    return "".join(parts)


def digit_class(scripts: list[str]) -> str:
    """ASCII digits plus the characters Python's \\d matches among the scope's characters."""
    parts = ["0-9"]
    if scripts:
        d = re.compile(r"\d")
        cps = [cp for cp in _code_points(scripts) if d.fullmatch(chr(cp))]
        for x, y in _ranges(cps):
            parts.append(_u(x) if x == y else _rng(x, y))
    return "".join(parts)


def scope_probes(scripts: list[str]) -> list[str]:
    """Characters to glue to each side of a sample: ASCII word/non-word characters, and
    for each in-scope script its first, last and middle word characters plus a
    non-word character from the same Unicode area."""
    out = ["_", "7", "x", " ", ".", "-", "\r", "\n", "\x1c", "\x85", "\ufeff", "\uff11",
           *CASE_PARTNERS["i"], CASE_PARTNERS["s"], CASE_PARTNERS["k"]]
    by = _word_chars_by_name()
    for s in scripts:
        cps = sorted(cp for w in SCRIPTS[s] for cp in by.get(w, []))
        if not cps:
            continue
        for cp in (cps[0], cps[len(cps) // 2], cps[-1]):
            out.append(chr(cp))
        lo, hi = cps[0], cps[-1]
        gap = next((cp for cp in range(lo, min(hi, lo + 4096)) if cp not in set(cps[:4096])
                    and not re.fullmatch(r"\w", chr(cp))), None)
        if gap is not None:
            out.append(chr(gap))
    return list(dict.fromkeys(out))


_META = set("\\^$.|?*+()[]{}")


def _is_letter(ch: str, L: str) -> bool:
    return ch not in _META and re.fullmatch(f"[{L}]", ch) is not None


def _optional(rest: str) -> bool:
    """Is the atom just ended made optional by the quantifier at rest[0]? `?`, `*`,
    `{0…}` and `{,n}` (Python 3.11+ reads a missing minimum as 0) all are."""
    if rest[:1] in ("?", "*"):
        return True
    m = re.match(r"\{(\d*)(,|\})", rest)
    return bool(m) and (m.group(1) == "" or int(m.group(1)) == 0)


def _starts_with_letter(s: str, L: str) -> bool:
    """True if regex text `s` can only begin a match with a letter of L (literal letter,
    or a (?:…)/(…) group whose every alternative does). Unsure → False."""
    if not s:
        return False
    if _is_letter(s[0], L):
        return not _optional(s[1:])
    if s.startswith("(?:"):
        body_start = 3
    elif s.startswith("(") and not s.startswith("(?"):
        body_start = 1
    else:
        return False
    depth, start, alts, i, in_cls = 1, body_start, [], body_start, False
    while i < len(s) and depth:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if in_cls:
            in_cls = c != "]"
        elif c == "[":
            in_cls = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                alts.append(s[start:i])
        elif c == "|" and depth == 1:
            alts.append(s[start:i])
            start = i + 1
        i += 1
    if depth or _optional(s[i:]):
        return False
    return all(_starts_with_letter(a, L) for a in alts)


def _ends_with_letter(s: str, L: str) -> bool:
    """True if regex text `s` (everything before a \\b) must end its match with a
    letter of L: a literal letter, or a closing group whose every alternative does."""
    if not s:
        return False
    if len(s) >= 2 and s[-2] == "\\":
        return False
    if _is_letter(s[-1], L):
        return not (len(s) >= 2 and s[-2] == "\\")
    if s[-1] != ")":
        return False
    depth, i = 0, len(s) - 1
    while i >= 0:  # find the matching "(" (escapes and classes are rare here; be strict)
        c = s[i]
        if c == ")" and (i == 0 or s[i - 1] != "\\"):
            depth += 1
        elif c == "(" and (i == 0 or s[i - 1] != "\\"):
            depth -= 1
            if depth == 0:
                break
        elif c in "[]":
            return False
        i -= 1
    if i < 0:
        return False
    body = s[i + 1:-1]
    if body.startswith("?:"):
        body = body[2:]
    elif body.startswith("?"):
        return False
    alts, d, start = [], 0, 0
    for k, c in enumerate(body):
        if c == "(":
            d += 1
        elif c == ")":
            d -= 1
        elif c == "|" and d == 0:
            alts.append(body[start:k])
            start = k + 1
    alts.append(body[start:])
    return all(_ends_with_letter(a, L) for a in alts)


# Python's case-insensitive matching treats more characters as equal than JavaScript's
# (without the u flag): U+0130/U+0131 ~ i, U+017F ~ s, KELVIN SIGN ~ k, ANGSTROM SIGN ~ a-ring,
# OHM SIGN ~ omega, Greek variant forms, title-case digraphs, and so on: 112 BMP
# characters in all. Rather than list them, ask Python: for every cased BMP character,
# its equivalence set is what `re.fullmatch(c, x, re.I)` accepts.
CASE_PARTNERS = {"i": "\u0130\u0131", "s": "\u017f", "k": "\u212a"}  # the ASCII ones
_LETTERLIKE = "\u0130\u0131\u017f\u212a\u212b\u2126"
_CASED: list[str] | None = None
_CASE_SETS: dict[str, str] = {}


def _cased() -> list[str]:
    global _CASED
    if _CASED is None:
        _CASED = [chr(cp) for cp in range(0x10000) if not 0xD800 <= cp <= 0xDFFF
                  and (chr(cp).lower() != chr(cp) or chr(cp).upper() != chr(cp)
                       or chr(cp) in _LETTERLIKE)]
    return _CASED


def case_set(c: str) -> str:
    """Characters Python's re.IGNORECASE treats as equal to `c` (BMP), sorted."""
    if c not in _CASE_SETS:
        rx = re.compile(re.escape(c), re.IGNORECASE)
        _CASE_SETS[c] = "".join(sorted({x for x in _cased() if rx.fullmatch(x)} | {c}))
    return _CASE_SETS[c]


def has_extra_partners(c: str) -> bool:
    """True if Python folds `c` with characters beyond its plain upper/lower pair: the
    cases JavaScript's /i (no u flag) does not reproduce."""
    simple = {c, c.lower(), c.upper()}
    return any(x not in simple for x in case_set(c))

# Python's \\s, exactly (JavaScript's lacks U+001C-U+001F and U+0085 and adds U+FEFF).
PY_SPACE = "\t\n\x0b\x0c\r\x1c\x1d\x1e\x1f \x85\xa0 " + "".join(
    chr(c) for c in range(0x2000, 0x200B)) + "    　"
ASCII_SPACE = " \t\n\r\x0b\x0c"


def _esc(chars: str) -> str:
    """Characters as class content; non-ASCII and controls as \\uXXXX escapes."""
    out = []
    for ch in chars:
        o = ord(ch)
        if o < 0x20 or o > 0x7E:
            out.append(_u(o))
        elif ch in "\\]^-[":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def _syntax_end(p: str, i: int) -> int:
    """p[i] == "(" and p[i+1] == "?": index just past the group's syntax prefix, which
    is copied verbatim (its letters are names and flags, not literals)."""
    j = i + 2
    if p.startswith("P<", j):
        return p.index(">", j) + 1
    if p.startswith("P=", j) or p.startswith("#", j):
        return p.index(")", j) + 1
    if p.startswith("<=", j) or p.startswith("<!", j):
        return j + 2
    if p[j:j + 1] in (":", "=", "!", ">"):
        return j + 1
    m = re.match(r"[aiLmsux-]+[:)]", p[j:])
    return j + m.end() if m else j


def _rewrite_classes(p: str, L: str, dotall: bool = False, multiline: bool = True,
                     D: str = "0-9", S: str = ASCII_SPACE, ignorecase: bool = False) -> str:
    """Rewrite engine-dependent constructs into forms both engines read like Python.
    L, D: letter and digit class contents; S: Python's \\s characters (raw)."""
    full_b = f"(?:(?<=[{L}])(?![{L}])|(?<![{L}])(?=[{L}]))"
    s_esc = _esc(S)
    out: list[str] = []
    i, in_cls, cls_start = 0, False, 0
    # Case-insensitivity per region: scoped modifiers (?i:…) / (?-i:…) change it until
    # their group closes, so keep a stack with one entry per open group.
    fold = ignorecase
    stack: list[bool] = []
    while i < len(p):
        c = p[i]
        if c == "\\" and i + 1 < len(p):
            n = p[i + 1]
            if n == "w":
                out.append(L if in_cls else f"[{L}]")
            elif n == "d":
                out.append(D if in_cls else f"[{D}]")
            elif n == "s":
                out.append(s_esc if in_cls else f"[{s_esc}]")
            elif n in "WDS" and in_cls:
                raise _NotFixable(f"\\{n} inside a character class")
            elif n == "W":
                out.append(f"[^{L}]")
            elif n == "D":
                out.append(f"[^{D}]")
            elif n == "S":
                out.append(f"[^{s_esc}]")
            elif n == "b" and not in_cls:
                prev_letter = _ends_with_letter(p[:i], L)
                if _starts_with_letter(p[i + 2:], L):
                    out.append(f"(?<![{L}])")
                elif prev_letter:
                    out.append(f"(?![{L}])")
                else:
                    out.append(full_b)
            elif n == "B" and not in_cls:
                # Not a boundary: both sides word, or both sides non-word — and, as in
                # Python (unlike JavaScript), never on an empty input.
                out.append(f"(?:(?<=[{L}])(?=[{L}])|(?<![{L}])(?![{L}])"
                           r"(?:(?<=[\s\S])|(?=[\s\S])))")
            elif n == "A" and not in_cls:
                out.append(r"(?<![\s\S])")
            elif n == "Z" and not in_cls:
                out.append(r"(?![\s\S])")
            elif n in "xu" and not in_cls:
                # An escaped literal (\x69, \u0069) is still a letter for case folding.
                m = re.match(r"\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})", p[i:])
                if m:
                    ch = chr(int(m.group(1) or m.group(2), 16))
                    out.append(f"[{_esc(case_set(ch))}]" if fold and has_extra_partners(ch)
                               else m.group(0))
                    i += m.end()
                    continue
                out.append(p[i:i + 2])
            else:
                out.append(p[i:i + 2])
            i += 2
            continue
        if in_cls:
            if c == "]" and i > cls_start:
                body = "".join(out[cls_start + 1:])
                out.append(_case_partners_for_class(body) if fold else "")
                in_cls = False
            out.append(c)
            i += 1
            continue
        if c == "(" and p[i + 1:i + 2] == "?":
            j = _syntax_end(p, i)
            syntax = p[i:j]
            m = re.fullmatch(r"\(\?([a-zA-Z]*)(?:-([a-zA-Z]*))?([:)])", syntax)
            if m and m.group(3) == ")":  # a global flag group: no new region
                pass
            else:
                stack.append(fold)
                if m:
                    if "i" in (m.group(1) or ""):
                        fold = True
                    if "i" in (m.group(2) or ""):
                        fold = False
            out.append(syntax)
            i = j
            continue
        if c == "(":
            stack.append(fold)
        elif c == ")" and stack:
            fold = stack.pop()
        # {,n}: Python reads "0 to n times"; JavaScript reads the literal text "{,n}".
        if c == "{":
            m = re.match(r"\{,(\d+)\}", p[i:])
            if m:
                out.append("{0," + m.group(1) + "}")
                i += m.end()
                continue
            m = re.match(r"\{\d*,?\d*\}", p[i:])
            if m:  # an ordinary quantifier: copy, its digits are not literals
                out.append(m.group(0))
                i += m.end()
                continue
        # Line semantics: JavaScript's . excludes \r, U+2028 and U+2029 too, and its
        # multiline ^/$ also break at them; Python's only at \n. Spell out Python's.
        if c == ".":
            out.append(r"[\s\S]" if dotall else r"[^\n]")
        elif c == "^":
            out.append(r"(?<![^\n])" if multiline else r"(?<![\s\S])")
        elif c == "$":
            out.append(r"(?![^\n])" if multiline else r"(?=\n?(?![\s\S]))")
        elif c == "[":
            in_cls = True
            cls_start = len(out)
            out.append(c)
            if p[i + 1:i + 2] == "^":
                out.append("^")
                i += 1
            if p[i + 1:i + 2] == "]":
                out.append("]")
                i += 1
        elif fold and has_extra_partners(c):
            out.append(f"[{_esc(case_set(c))}]")
        else:
            out.append(c)
        i += 1
    return "".join(out)


class _NotFixable(Exception):
    pass


def _case_partners_for_class(body: str) -> str:
    """Escapes for every character Python's case-insensitive class would match (in its
    positive form) beyond what the class lists literally, appended so JavaScript's /i
    class covers the same set, negated or not."""
    positive = body[1:] if body.startswith("^") else body
    try:
        folded = re.compile(f"[{positive}]", re.IGNORECASE)
        literal = re.compile(f"[{positive}]")
    except re.error:
        return ""
    # ASCII letters fold the same way in both engines' /i, so only non-ASCII partners
    # need spelling out.
    return "".join(_u(ord(x)) for x in _cased()
                   if ord(x) > 0x7F and folded.fullmatch(x) and not literal.fullmatch(x))


@dataclass
class FixResult:
    rule_id: str
    original: str
    fixed: str
    changes: list[str] = field(default_factory=list)
    not_fixed: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)  # scope the rewrite is exact for


def _effective(rule: Rule, engine_flags: dict[str, str]) -> dict[str, str]:
    """Flags each engine really uses for this rule: its own `flags` key, else the loader's."""
    from .engines import rule_flags

    out = {}
    for n, f in engine_flags.items():
        own = rule_flags(n, rule.flags)
        out[n] = own if own is not None else f
    return out


def fix_rule(rule: Rule, engine_flags: dict[str, str],
             extra_scripts: list[str] | None = None) -> FixResult:
    engine_flags = _effective(rule, engine_flags)
    p = rule.pattern
    res = FixResult(rule.id, p, p)
    # 1) leading global flags that every loader already applies
    m = re.match(r"\(\?([aiLmsux]+)\)", p)
    if m:
        need = set(m.group(1).lower())
        have = [set(f.lower()) for f in engine_flags.values()]
        if need <= {"i", "m"} and all(need <= h for h in have):
            p = p[m.end():]
            res.changes.append(f"dropped leading ({m.group(0)[1:-1]}): every loader already sets it")
        else:
            res.not_fixed.append(f"global flag group {m.group(0)} that not every loader applies")
    # 2) Python-only named groups, when not back-referenced by name
    if "(?P<" in p:
        if "(?P=" in p:
            res.not_fixed.append("named back-reference (?P=…)")
        else:
            p = re.sub(r"\(\?P<[A-Za-z_][A-Za-z0-9_]*>", "(", p)
            res.changes.append("(?P<name>…) → (…)")
    # 3) \w \W \b \A \Z
    pyf = engine_flags.get("python", "IM").upper()
    py_ascii = "A" in pyf
    ignorecase = "I" in pyf and not py_ascii  # scoped (?i:…)/(?-i:…) handled per region
    bare = re.sub(r"\\.", "", p)
    bare = re.sub(r"\[(?:\\.|[^\]])*\]", "", bare)
    triggers = (re.search(r"\\[wWbBAZdDsS]", p.replace("\\\\", "")) is not None
                or any(ch in bare for ch in ".^$") or re.search(r"\{,\d+\}", bare) is not None
                or re.search(r"[iskISK\[]", p) is not None)
    if triggers:
        scripts = [] if py_ascii else sorted(set(scripts_of(p, rule.lang)) | set(extra_scripts or []))
        L = letter_class(scripts)
        D = digit_class(scripts)
        S = ASCII_SPACE if py_ascii else PY_SPACE
        try:
            scoped = re.findall(r"\(\?([aiLmsux]*)(?:-([aiLmsux]*))?:", p)
            if any(set(on + off) - {"i"} for on, off in scoped):
                raise _NotFixable("scoped modifiers other than i (s, m, x, a…) change . ^ $ "
                                  "per region; not rewritten")
            q = _rewrite_classes(p, L, dotall="S" in pyf, multiline="M" in pyf, D=D, S=S,
                                 ignorecase=ignorecase)
        except _NotFixable as e:
            q = p
            res.not_fixed.append(str(e))
        if q != p:
            p = q
            res.scripts = scripts
            res.changes.append("\\w \\d \\s \\b \\A \\Z . ^ $ and case folding → explicit forms; "
                               "exact for " + (", ".join(scripts) + " (+common) BMP text" if scripts
                                               else "all text (Python runs this rule in ASCII mode)"))
    if re.search(r"\(\?-?[imsx]+(?:-[imsx]+)?:", p):
        res.not_fixed.append("scoped modifiers (?i:…)/(?-i:…) need ES2025 engines")
    res.fixed = p
    return res


def verify(results: list[FixResult], engines: dict, flags: dict, texts_for,
           deadline_s: float = 3.0, rules: dict | None = None) -> dict[str, str]:
    """Check each rewrite against the original under Python. Returns
    {rule_id: reason} for rewrites that must NOT be written (could not be verified,
    or differ). `engines` maps name -> Engine; `texts_for(original) -> list[str]`."""
    from .engines import get_engine

    py = get_engine("python")
    rejected: dict[str, str] = {}
    for x in results:
        if x.fixed == x.original:
            continue
        texts = texts_for(x)
        eff = _effective(rules[x.rule_id], flags) if rules else flags
        ref = py.run([x.original], texts, eff.get("python", "IM"), deadline_s)[0]
        if ref.timed_out:
            rejected[x.rule_id] = "the original rule hangs in Python, so the rewrite cannot be verified"
            continue
        if not ref.compiled:
            rejected[x.rule_id] = f"the original rule does not compile in Python ({ref.error})"
            continue
        if not any(ref.matched(j) for j in range(len(texts))):
            rejected[x.rule_id] = ("no tested input matches the original rule, so agreement "
                                   "would prove nothing; left unchanged")
            continue
        for n, e in engines.items():
            got = e.run([x.fixed], texts, eff.get(n), deadline_s)[0]
            if not got.compiled:
                rejected[x.rule_id] = f"rewrite fails in {n}: {got.error or 'timed out'}"
                break
            bad = [t for j, t in enumerate(texts) if got.matched(j) != ref.matched(j)]
            if bad:
                rejected[x.rule_id] = f"rewrite differs in {n} on {len(bad)} texts, e.g. {bad[0]!r}"
                break
    return rejected


def rewrite_file(path: str | Path, fixes: dict[str, str], rules: list[Rule], out: str | Path) -> Path:
    """Write `out` = `path` with each changed pattern scalar replaced in place."""
    if Path(path).suffix == ".json":
        return _rewrite_json(path, fixes, rules, out)
    text = Path(path).read_text(encoding="utf-8")
    root = yaml.compose(text)
    spans = []

    def pattern_node(item):
        if isinstance(item, yaml.ScalarNode):
            return item
        if isinstance(item, yaml.MappingNode):
            for k, v in item.value:
                if isinstance(k, yaml.ScalarNode) and k.value == "pattern":
                    return v
        return None

    seqs = []
    if isinstance(root, yaml.MappingNode):
        seqs = [v for _, v in root.value if isinstance(v, yaml.SequenceNode)]
    elif isinstance(root, yaml.SequenceNode):
        seqs = [root]
    nodes = [pattern_node(item) for s in seqs for item in s.value]
    nodes = [n for n in nodes if n is not None]
    if len(nodes) != len(rules):
        raise ValueError("could not map rules to YAML nodes; file not rewritten")
    expected = []
    for node, rule in zip(nodes, rules, strict=True):
        new = fixes.get(rule.id)
        if new is not None and new != rule.pattern:
            spans.append((node.start_mark.index, node.end_mark.index, _yaml_scalar(new)))
            expected.append(new)
        else:
            expected.append(rule.pattern)
    for a, b, rep in sorted(spans, reverse=True):
        text = text[:a] + rep + text[b:]
    _assert_round_trip(text, expected, rules)
    return _atomic_write(Path(out), text)


def _atomic_write(p: Path, text: str) -> Path:
    """Write via an exclusive, unpredictable temp file in the same directory, then
    rename over the target: no partial files, and no following a planted symlink."""
    import os
    import tempfile

    fd, tmp = tempfile.mkstemp(prefix=f".{p.name}.", suffix=".tmp", dir=p.parent or ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, p)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return p


def _yaml_scalar(s: str) -> str:
    """A YAML scalar that loads back as exactly `s`. Single quotes keep backslashes
    readable but fold line breaks, so anything with a control character is written as
    an escaped double-quoted scalar instead (JSON string syntax is valid YAML)."""
    import json

    special = (0x7F, 0x85, 0x2028, 0x2029, 0xFEFF)
    if any(ord(c) < 32 or ord(c) in special for c in s):
        out = json.dumps(s, ensure_ascii=False)
        # json leaves these literal; YAML would read them as line breaks or a BOM.
        for cp in special:
            out = out.replace(chr(cp), f"\\u{cp:04x}")
        return out
    return "'" + s.replace("'", "''") + "'"


def _assert_round_trip(text: str, expected: list[str], rules: list[Rule]) -> None:
    """Reload the file we are about to write and require every pattern to be exactly
    what we meant — unchanged rules included. Parsing alone proves nothing."""
    from .rules import RuleSet, _coerce, _line_index

    data = yaml.safe_load(text)
    rs = RuleSet(path="(output)", sha256="")
    lines = _line_index(text)
    if isinstance(data, dict):
        for cat, entries in data.items():
            if isinstance(entries, list):
                for i, e in enumerate(entries):
                    r = _coerce(e, str(cat), i, lines, rs.skipped)
                    if r:
                        rs.rules.append(r)
    elif isinstance(data, list):
        for i, e in enumerate(data):
            r = _coerce(e, "", i, lines, rs.skipped)
            if r:
                rs.rules.append(r)
    got = [r.pattern for r in rs.rules]
    if got != expected:
        bad = next(i for i, (a, b) in enumerate(zip(got, expected, strict=False)) if a != b) \
            if len(got) == len(expected) else -1
        where = rules[bad].id if bad >= 0 else "rule count"
        raise ValueError(f"rewrite would not round-trip ({where}); file not written")


def _rewrite_json(path, fixes: dict[str, str], rules: list[Rule], out) -> Path:
    import json

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    seqs = [v for v in data.values() if isinstance(v, list)] if isinstance(data, dict) else [data]
    items = [it for s in seqs for it in s if isinstance(it, (dict, str))]
    if len(items) != len(rules):
        raise ValueError("could not map rules to JSON entries; file not rewritten")
    k = 0
    for s in seqs:
        for j, it in enumerate(s):
            if not isinstance(it, (dict, str)):
                continue
            new = fixes.get(rules[k].id)
            if new is not None:
                if isinstance(it, str):
                    s[j] = new
                else:
                    it["pattern"] = new
            k += 1
    return _atomic_write(Path(out), json.dumps(data, ensure_ascii=False, indent=2))


def run_fix(rules_path, out, names: list[str], flags: dict, bundled_texts: list[str],
            extra_scripts: list[str] | None = None) -> dict:
    """Rewrite, verify, and write only verified rewrites. Returns a summary dict.

    `flags` maps engine -> loader flags; "python" is the reference and is always used
    for verification, whether or not Python is among `names`."""
    from .engines import get_engine
    from .rules import load_rules
    from .samples import positive_samples, variants

    rs = load_rules(rules_path)
    flags = {"python": "IM", **flags}
    # Construction needs the Python reference flags (ASCII mode, dotall, multiline) even
    # when Python is not a target engine.
    build = {"python": flags["python"], **{n: flags[n] for n in names if n in flags}}
    results = [fix_rule(r, build, extra_scripts) for r in rs.rules]
    changed = [x for x in results if x.fixed != x.original]
    missing = [n for n in names if not get_engine(n).available]
    if missing:
        return {"error": f"cannot verify without: {', '.join(missing)}", "written": None}

    by_id = {r.id: r for r in rs.rules}

    def texts_for(x: FixResult) -> list[str]:
        from .check import _pf, _py_bits

        own = positive_samples(x.original, _py_bits(_pf(flags, "python", by_id[x.rule_id])), n=12)
        # Probe the rewrite exactly where it changed: letters and non-letters from every
        # in-scope script glued to each side of the samples.
        probes = scope_probes(x.scripts) if x.scripts else []
        cores = list(dict.fromkeys(t.strip() for t in own))
        edges = [f"{c}{t}{d}" for t in cores[:6] for c in probes for d in ("", c)]
        edges += [f"{t}{c}" for t in cores[:6] for c in probes]
        # Every case partner Python accepts, swapped into every sample (all alternatives).
        for t in cores:
            for ch in dict.fromkeys(t):
                if has_extra_partners(ch):
                    edges.extend(t.replace(ch, b) for b in case_set(ch) if b != ch)
        edges = edges[:2000]
        return list(dict.fromkeys(own + [v for t in own for v in variants(t)] + edges
                                  + bundled_texts))

    rejected = verify(changed, {n: get_engine(n) for n in names}, flags, texts_for,
                      rules={r.id: r for r in rs.rules})
    keep = [x for x in changed if x.rule_id not in rejected]
    rewrite_file(rules_path, {x.rule_id: x.fixed for x in keep}, rs.rules, out)
    return {
        "rules": len(rs.rules),
        "written": str(out),
        "rewritten": [{"rule_id": x.rule_id, "changes": x.changes, "scripts": x.scripts}
                      for x in keep],
        "rejected": rejected,
        "not_fixable": [{"rule_id": x.rule_id, "why": n} for x in results for n in x.not_fixed],
        "engines": names,
        "bundled_texts": len(bundled_texts),
    }
