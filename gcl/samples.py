"""Generate strings a rule is *meant* to match, from the rule itself.

The question `gcl check` asks is "does this rule still fire in the other engine on
text it fires on here?". User cases rarely hit every rule, so we derive positive
examples from each pattern's parse tree (Python's own regex parser) and take a few
branch choices for variety. The rule is never run here; the engine runners decide,
out of process, which samples really match. That makes every rule testable even with
no cases at all.
"""

from __future__ import annotations

import re
import unicodedata

try:  # Python 3.11+
    from re import _constants as C
    from re import _parser as P
except ImportError:  # pragma: no cover
    import sre_constants as C  # type: ignore
    import sre_parse as P  # type: ignore

_CATEGORY_CHAR = {
    C.CATEGORY_DIGIT: "7", C.CATEGORY_NOT_DIGIT: "x",
    C.CATEGORY_SPACE: " ", C.CATEGORY_NOT_SPACE: "x",
    C.CATEGORY_WORD: "a", C.CATEGORY_NOT_WORD: " ",
    C.CATEGORY_LINEBREAK: "\n", C.CATEGORY_NOT_LINEBREAK: "x",
}
_FILLERS = [" ", "x", "a", "0", ".", "-", "\n"]


class _Gen:
    def __init__(self, variant: int):
        self.variant = variant
        self.groups: dict[int, str] = {}
        self.branch_seen = 0
        self.work = 0

    def seq(self, items) -> str:
        self.work += 1 + len(items)
        if self.work > MAX_WORK:
            raise _TooBig
        out = "".join(self.node(op, av) for op, av in items)
        if len(out) > MAX_SAMPLE_LEN:
            raise _TooBig
        return out

    def node(self, op, av) -> str:
        if op is C.LITERAL:
            return chr(av)
        if op is C.NOT_LITERAL:
            return next(f for f in _FILLERS if ord(f) != av)
        if op is C.ANY:
            # Every third variant uses \r: engines disagree on whether "." matches it.
            return "\r" if self.variant % 3 == 2 else " "
        if op is C.IN:
            return self.in_set(av)
        if op is C.BRANCH:
            alts = av[1]
            # Different variants walk different alternatives; nested branches shift.
            k = (self.variant + self.branch_seen) % len(alts)
            self.branch_seen += 1
            return self.seq(alts[k])
        if op is C.SUBPATTERN:
            gid, body = av[0], av[-1]
            s = self.seq(body)
            if gid:
                self.groups[gid] = s
            return s
        if op in (C.MAX_REPEAT, C.MIN_REPEAT, getattr(C, "POSSESSIVE_REPEAT", None)):
            lo, hi, body = av
            # The minimum is required; an optional repeat is taken once on odd variants.
            n = min(lo, 200) if lo else (1 if (self.variant % 2 and hi) else 0)
            parts = []
            total = 0
            for _ in range(n):
                part = self.seq(body)
                total += len(part)
                if total > MAX_SAMPLE_LEN:
                    raise _TooBig
                parts.append(part)
            return "".join(parts)
        if op is C.GROUPREF:
            return self.groups.get(av, "")
        if op is getattr(C, "ATOMIC_GROUP", None):
            return self.seq(av)
        # AT (anchors/boundaries), ASSERT, ASSERT_NOT, GROUPREF_EXISTS: emit nothing.
        if op is C.GROUPREF_EXISTS:
            return self.seq(av[1]) if av[1] else ""
        return ""

    def in_set(self, items) -> str:
        negate = any(op is C.NEGATE for op, _ in items)
        if negate:
            # Pick a filler the negated class does not contain.
            members = [(op, av) for op, av in items if op is not C.NEGATE]
            for f in _FILLERS:
                if not _in(members, f):
                    return f
            return "x"
        for op, av in items:
            if op is C.LITERAL:
                return chr(av)
            if op is C.RANGE:
                return chr(av[0])
            if op is C.CATEGORY:
                return _CATEGORY_CHAR.get(av, "a")
        return "a"


def _in(members, ch) -> bool:
    o = ord(ch)
    for op, av in members:
        if op is C.LITERAL and av == o:
            return True
        if op is C.RANGE and av[0] <= o <= av[1]:
            return True
        if op is C.CATEGORY and re.fullmatch(
                {C.CATEGORY_DIGIT: r"\d", C.CATEGORY_SPACE: r"\s",
                 C.CATEGORY_WORD: r"\w"}.get(av, r"(?!)"), ch):
            return True
    return False


MAX_SAMPLE_LEN = 4000
# Parse-tree nodes visited per rule, all variants together. Nested empty repeats are
# cheap in output but not in work, so length alone does not bound them.
MAX_WORK = 200_000


class _TooBig(Exception):
    pass


def positive_samples(pattern: str, flags: int = re.I | re.M, n: int = 6) -> list[str]:
    """Up to `n` strings the rule is meant to match, each bare and space-padded.

    The rule is only *parsed* here, never run: a rule is untrusted input and may
    backtrack catastrophically, so whether a sample really matches is decided by the
    engine runners, out of process and under a deadline. Generation is capped at
    MAX_SAMPLE_LEN characters (nested bounded repeats can otherwise explode).
    """
    try:
        tree = P.parse(pattern, flags)
    except (re.error, ValueError, OverflowError, RecursionError):
        return []
    out: list[str] = []
    seen: set[str] = set()
    spent = 0  # one work budget for the whole rule, so a pathological tree costs at most
    #            MAX_WORK node visits however many variants are tried
    for v in range(n * 2):
        g = _Gen(v)
        g.work = spent
        try:
            s = g.seq(tree)
        except _TooBig:
            break  # budget gone: further variants would only hit it again
        except (RecursionError, ValueError, TypeError):
            spent = g.work
            continue
        spent = g.work
        core = s.strip()
        if not core or core in seen:
            continue
        seen.add(core)
        # Lookarounds and boundaries emit nothing; the padded copy satisfies most of them.
        out.extend(dict.fromkeys([s, f" {s} "]))
        if len(seen) >= n:
            break
    return out


def variants(text: str) -> list[str]:
    """Spellings of the same text that a robust rule should treat alike."""
    out = []
    nfd = unicodedata.normalize("NFD", text)
    if nfd != text:
        out.append(nfd)
    up = text.upper()
    if up != text:
        out.append(up)
    # Line terminators beside the text: multiline ^/$ break at \r and U+2028 in
    # JavaScript, only at \n in Python.
    core = text.strip()
    if core:
        out += [f"x\r{core}", f"{core}\rx", f"x\u2028{core}"]
    return out
