"""`gcl check`: does every rule do the same thing in every engine that loads it?

For each rule:
  1. lint the source for engine-dependent syntax (hazards);
  2. compile it in every engine — a compile failure is reported on its own, never
     folded into "did not match", because a loader that skips bad rules turns it
     into silent loss of protection;
  3. run it on texts it is meant to match (generated from the rule), on the user's
     cases, and on normalization variants, in every engine, and report each text
     where engines disagree — per rule, so one rule cannot mask another;
  4. shrink each disagreement to a minimal witness string (delta debugging);
  5. time it on adversarial long inputs (catastrophic backtracking).
"""

from __future__ import annotations

import re
import time
import unicodedata
from dataclasses import dataclass, field

from .engines import Engine, get_engine, rule_flags
from .lint import JS_ONLY, Hazard, lint
from .rules import Rule, RuleSet
from .samples import positive_samples, variants


@dataclass
class Finding:
    kind: str           # compile_split | match_split | timeout | slow | engine_missing
    level: str          # error | warning | note
    rule_id: str
    title: str
    detail: str
    engines: dict = field(default_factory=dict)  # engine -> verdict / error / ms
    witness: str | None = None
    original: str | None = None

    def to_dict(self) -> dict:
        # An empty witness is a real result (the rule disagrees on ""), so keep "" there.
        keep = {"witness", "original"}
        return {k: v for k, v in self.__dict__.items()
                if v is not None and (k in keep or v not in ({}, ""))}


@dataclass
class CheckResult:
    ruleset: RuleSet
    engines: dict                   # name -> meta (version, flags) or {"missing": True}
    hazards: list[Hazard]
    findings: list[Finding]
    stats: dict
    complete: bool                  # False if any requested engine was unavailable

    def rules_with(self, kind: str) -> set[str]:
        return {f.rule_id for f in self.findings if f.kind == kind}


MAX_DDMIN_STEPS = 60


def _blank_terms(t: str) -> str:
    for ch in _LINE_TERMS:
        t = t.replace(ch, " ")
    return t
_LINE_TERMS = ("\r", "\u2028", "\u2029")
_last_ddmin_capped = False


def _ddmin(text: str, still_fails) -> str:
    """Classic delta debugging over characters. `still_fails(list[str]) -> list[bool]`
    evaluates a batch of candidates at once (one engine call per step). Stops after
    MAX_DDMIN_STEPS; `_last_ddmin_capped` records whether it did (then the witness is
    smaller than the input but not necessarily 1-minimal)."""
    global _last_ddmin_capped
    chars = list(text)
    n = 2
    steps = 0
    _last_ddmin_capped = False
    while len(chars) >= 2:
        if steps >= MAX_DDMIN_STEPS:
            _last_ddmin_capped = True
            break
        steps += 1
        size = max(1, len(chars) // n)
        chunks = [chars[i:i + size] for i in range(0, len(chars), size)]
        subsets = ["".join(c) for c in chunks]
        complements = ["".join(c for k, ch in enumerate(chunks) if k != i for c in ch)
                       for i in range(len(chunks))]
        cands = [c for c in subsets + complements if c]
        verdicts = still_fails(cands)
        hit = next((c for c, ok in zip(cands, verdicts, strict=True) if ok), None)
        if hit is not None:
            chars = list(hit)
            n = 2 if hit in subsets else max(n - 1, 2)
        elif size == 1:
            break
        else:
            n = min(len(chars), n * 2)
    if len(chars) == 1 and still_fails([""])[0]:
        return ""
    return "".join(chars)


def _adversarial(samples: list[str], n: int = 4000) -> list[str]:
    """Long inputs that make backtracking regexes blow up: the rule's own sample text
    repeated, runs of its first character (separator lines like '=====' are common in
    tool output), each with a non-matching tail, plus generic runs."""
    # Every input is exactly n characters: n-1 of pattern material plus a tail that
    # matches nothing, so the measured size is the size reported.
    out = ["a" * (n - 1) + "!", " " * (n - 1) + "!", ("aa " * n)[:n]]
    for s in samples[:2]:
        core = s.strip() or "a"
        out.append((core * (n // max(len(core), 1) + 1))[:n - 1] + "\u0000")
        out.append((core[0] * (n - 1)) + "\u0000")
    return out


def _describe(text: str) -> str:
    """Short, faithful description of a long adversarial input for a report."""
    if len(text) <= 120:
        return text
    for k in range(1, 12):
        unit = text[:k]
        body = text[:-1] if text[-1] in "\u0000!" else text
        if unit * (len(body) // k) == body[: k * (len(body) // k)] and len(body) // k > 8:
            tail = text[len(unit) * (len(body) // k):]
            return f"{unit!r} \u00d7 {len(body) // k:,}" + (f" + {tail!r}" if tail else "")
    return text[:100] + f"\u2026 ({len(text):,} chars)"


def _pf(flags: dict, engine: str, rule: Rule) -> str | None:
    """Flags for this rule in this engine: its own `flags` key, else the loader default."""
    own = rule_flags(engine, rule.flags)
    return own if own is not None else flags.get(engine)


def _py_bits(spec: str | None) -> int:
    if spec is None:
        return re.IGNORECASE | re.MULTILINE
    bits = 0
    for ch in spec.upper():
        bits |= {"I": re.I, "M": re.M, "S": re.S, "X": re.X, "A": re.A, "U": re.U}[ch]
    return bits


def _hang_text(rule: Rule, texts: list[str], engine: Engine, name: str, flags: dict,
               deadline_s: float) -> str | None:
    """Which single input makes the rule hang? Run the rule once per text (as separate
    'patterns', so the streaming runner reports each one) and stop at the first hang."""
    texts = texts[:400]
    res = engine.run([rule.pattern] * len(texts), [], None, deadline_s,
                     per_pattern_texts=[[t] for t in texts],
                     pattern_flags=[_pf(flags, name, rule)] * len(texts), stop_on_timeout=True)
    for t, x in zip(texts, res, strict=True):
        if x.timed_out:
            return t
    return None


def _is_letter(ch: str) -> bool:
    return unicodedata.category(ch)[0] in ("L", "N")


def _has_literal_word(pattern: str) -> bool:
    """Does the rule spell out at least one word (3+ letters outside any [...] class)?
    A rule made only of character classes is keyed on a script, not on words."""
    bare = re.sub(r"\\.", " ", pattern)
    bare = re.sub(r"\[[^\]]*\]", " ", bare)
    return re.search(r"[^\W\d_]{3,}", bare) is not None


def _why_benign(rule: Rule, text: str, langs: list[str], span: list | None) -> str:
    """A specific reason when we can see one; otherwise a neutral prompt to review."""
    if not _has_literal_word(rule.pattern):
        where = f"ordinary {langs[0]} text" if len(langs) == 1 else "ordinary text"
        return (f"The rule is made of character classes only, so it fires on {where} by "
                "script, not on an attack. (Homoglyph attacks are mixed scripts inside one "
                "token; match that adjacency instead.)")
    # The span comes from an engine runner: the rule is never executed in this process.
    if span and span[1] > span[0]:
        a, b = span
        matched = text[a:b]
        inside = (a > 0 and _is_letter(text[a - 1]) and _is_letter(text[a])) or \
                 (b < len(text) and _is_letter(text[b]) and _is_letter(text[b - 1]))
        if inside:
            word_start = a
            while word_start > 0 and _is_letter(text[word_start - 1]):
                word_start -= 1
            word_end = b
            while word_end < len(text) and _is_letter(text[word_end]):
                word_end += 1
            return (f"The match \u201c{matched}\u201d sits inside the longer word "
                    f"\u201c{text[word_start:word_end]}\u201d: likely a missing word boundary.")
    return "Ordinary text triggers it; review the rule's trigger words."


def run_check(ruleset: RuleSet, engine_names: list[str], cases: list[dict] | None = None,
              benign: list[dict] | None = None, flags: dict | None = None,
              deadline_s: float = 3.0, slow_ms: float = 250.0,
              minimize: bool = True, redos: bool = True, progress=None,
              max_len: int | None = None) -> CheckResult:
    flags = flags or {}
    say = progress or (lambda *_: None)
    rules = ruleset.rules
    hazards = lint(rules)
    if "node" not in engine_names:  # JS-only hazards are noise for a Python-only loader
        hazards = [h for h in hazards if h.code not in JS_ONLY]
    findings: list[Finding] = []

    engines: dict[str, Engine] = {}
    meta: dict[str, dict] = {}
    for name in engine_names:
        e = get_engine(name)
        if e.available:
            engines[name] = e
        else:
            meta[name] = {"missing": True}
            findings.append(Finding("engine_missing", "error", "*", f"{name} not available",
                                    f"Runtime for '{name}' was not found; results are "
                                    "incomplete for it. This is never reported as a pass."))
    complete = len(engines) == len(engine_names) and not ruleset.skipped
    findings.extend(Finding("unreadable_rule", "error", "*", "Rule entry not read",
                            f"{why}. The run is incomplete: a malformed entry may be a "
                            "rule the loader also cannot use.") for why in ruleset.skipped)
    names = list(engines)

    # Texts each rule is checked on: its own positive samples (+ variants), plus cases.
    case_texts = [c["text"] for c in (cases or [])]
    benign = benign or []
    benign_texts = [b["text"] for b in benign]
    per_rule_texts: list[list[str]] = []
    for r in rules:
        own = positive_samples(r.pattern, _py_bits(_pf(flags, "python", r)))
        texts = own + [v for s in own for v in variants(s)]
        per_rule_texts.append(texts)
    all_texts = sorted({t for ts in per_rule_texts for t in ts} | set(case_texts)
                       | set(benign_texts))
    index = {t: j for j, t in enumerate(all_texts)}

    patterns = [r.pattern for r in rules]
    results = {}
    for name, e in engines.items():
        say(f"{name}: {len(patterns)} rules x {len(all_texts)} texts")
        t0 = time.perf_counter()
        results[name] = e.run(patterns, all_texts, flags.get(name), deadline_s,
                              pattern_flags=[rule_flags(name, r.flags) for r in rules])
        meta[name] = dict(e.meta, seconds=round(time.perf_counter() - t0, 2))

    # A rule "has samples" only if an engine confirmed one of its generated texts matches.
    ref = results.get("python") or (next(iter(results.values())) if results else None)

    def confirmed(i):
        if ref is None:
            return False
        return any(ref[i].matched(index[t]) for t in per_rule_texts[i])

    stats = {"rules": len(rules), "texts": len(all_texts), "case_texts": len(case_texts),
             "benign_texts": len(benign_texts),
             "rules_without_samples": sum(1 for i in range(len(rules)) if not confirmed(i))}

    for i, r in enumerate(rules):
        res = {n: results[n][i] for n in names}
        # 1) compile / timeout split
        status = {n: ("timeout" if x.timed_out else ("error" if x.error else "ok"))
                  for n, x in res.items()}
        if len(set(status.values())) > 1 or any(v != "ok" for v in status.values()):
            bad = {n: (res[n].error or "timed out") for n in names if status[n] != "ok"}
            ok = [n for n in names if status[n] == "ok"]
            if any(v == "timeout" for v in status.values()):
                hung_in = [n for n in names if status[n] == "timeout"]
                order = list(dict.fromkeys(per_rule_texts[i] + case_texts + benign_texts
                                           + all_texts))
                w = _hang_text(r, order, engines[hung_in[0]], hung_in[0], flags,
                               min(deadline_s, 1.5))
                findings.append(Finding("timeout", "error", r.id, "Rule hangs",
                                        f"Exceeded {deadline_s}s on the check texts in: "
                                        f"{', '.join(hung_in)}."
                                        + (" The input below alone makes it hang." if w else
                                           " None of the first 400 inputs tried one at a time "
                                           "hangs it on its own; the single trigger was not isolated."),
                                        engines=bad, witness=w))
            errs = [n for n in names if status[n] == "error"]
            if errs:
                where = f"compiles in {', '.join(ok)} but not in {', '.join(errs)}" if ok \
                    else f"does not compile in {', '.join(errs)}"
                findings.append(Finding(
                    "compile_split", "error", r.id, "Rule does not compile everywhere",
                    f"The rule {where}. A loader that skips uncompilable rules (common: "
                    "try/catch around the compile) loses this rule silently.", engines=bad))
            continue
        # 2) match split on every text the engines ran (own samples, cases, benign
        #    texts and other rules' samples alike), per rule
        splits = []
        for j, t in enumerate(all_texts):
            verdicts = {n: res[n].matched(j) for n in names}
            if len(set(verdicts.values())) > 1:
                splits.append((t, verdicts))
        if splits:
            # Texts that differ only because of a line terminator (\r, U+2028, U+2029)
            # are a narrower problem than a rule that stops matching ordinary text.
            plain = [sp for sp in splits if not any(ch in sp[0] for ch in _LINE_TERMS)]
            if not plain:
                # Causality, not presence: blank out the terminators and re-run. If the
                # engines still disagree, the line terminator was not the reason.
                blanked = list(dict.fromkeys(_blank_terms(t) for t, _ in splits))
                again = {n: engines[n].run([r.pattern], blanked, _pf(flags, n, r), deadline_s)[0]
                         for n in names}
                for k, t in enumerate(blanked):
                    v = {n: again[n].matched(k) for n in names}
                    if len(set(v.values())) > 1:
                        plain.append((t, v))
            pool = plain or splits
            t, verdicts = min(pool, key=lambda s: len(s[0]))
            fired = [n for n, v in verdicts.items() if v]
            silent = [n for n, v in verdicts.items() if not v]
            kind, level, title = ("match_split", "error", "Engines disagree") if plain else \
                ("line_split", "warning", "Engines disagree on line terminators")
            extra = "" if plain else (" Every disagreement involves \\r, U+2028 or U+2029, which "
                                      "JavaScript treats as line breaks for . ^ $ and Python does not.")
            f = Finding(
                kind, level, r.id, title,
                f"On {len(pool)} of {len(all_texts)} texts the rule matches in "
                f"{', '.join(fired)} but not in {', '.join(silent)}.{extra}",
                engines={n: bool(v) for n, v in verdicts.items()}, original=t)
            if minimize and len(names) >= 2:
                f.witness = _minimize(r, t, engines, names, flags, deadline_s)
                if _last_ddmin_capped:
                    f.detail += " (Shrinking stopped at its step limit; the witness may not be minimal.)"
            findings.append(f)
        # 3) fires on ordinary text (any engine): script-blind or over-broad rules
        hits = [b for b in benign
                if any(res[n].matched(index[b["text"]]) for n in names)]
        if hits:
            langs = sorted({b.get("lang", "?") for b in hits})
            by_lang = {lg: sum(1 for b in hits if b.get("lang") == lg) for lg in langs}
            per = {lg: sum(1 for b in benign if b.get("lang") == lg) for lg in langs}
            original = min((b["text"] for b in hits), key=len)
            j = index[original]
            span = next((res[n].hits[j] for n in names if res[n].hits and res[n].hits[j]), None)
            f = Finding(
                "benign_hit", "warning", r.id, "Fires on ordinary text",
                "Matches benign text: " + ", ".join(f"{lg} {by_lang[lg]}/{per[lg]}" for lg in langs)
                + ". " + _why_benign(r, original, langs, span), original=original)
            if minimize:
                f.witness = _minimize_hit(r, f.original, engines, names, flags, deadline_s)
                if _last_ddmin_capped:
                    f.detail += " (Shrinking stopped at its step limit; the witness may not be minimal.)"
            findings.append(f)

    if redos and engines:
        hung = {f.rule_id for f in findings if f.kind == "timeout"}
        findings += [f for f in _timing(rules, per_rule_texts, engines, flags, deadline_s,
                                        slow_ms, say, max_len) if f.rule_id not in hung]

    return CheckResult(ruleset, meta, hazards, findings, stats, complete)


def _minimize(rule: Rule, text: str, engines, names, flags, deadline_s) -> str:
    want = None

    def verdicts(cands):
        per = {n: engines[n].run([rule.pattern], cands, _pf(flags, n, rule), deadline_s)[0]
               for n in names}
        return [tuple(per[n].matched(k) for n in names) for k in range(len(cands))]

    want = verdicts([text])[0]

    def still(cands):
        return [v == want for v in verdicts(cands)]

    return _ddmin(text, still)


def _minimize_hit(rule: Rule, text: str, engines, names, flags, deadline_s) -> str:
    """Smallest part of a benign text that still triggers the rule."""
    def still(cands):
        per = [engines[n].run([rule.pattern], cands, _pf(flags, n, rule), deadline_s)[0]
               for n in names]
        return [any(x.matched(k) for x in per) for k in range(len(cands))]

    return _ddmin(text, still)


SMALL, LARGE = 2000, 8000


def _timing(rules, per_rule_texts, engines, flags, deadline_s, slow_ms, say,
            max_len: int | None = None) -> list[Finding]:
    """Time every rule on adversarial inputs at two sizes. A fixed threshold undersells
    a quadratic rule (fast at 4 KB, seconds at 32 KB), so the finding is about growth:
    with 4x the input, linear time grows ~4x, quadratic ~16x."""
    import math

    out = []
    large_n = max_len or LARGE
    small_n = large_n // 4
    if small_n < 100:
        raise ValueError("max_len must be at least 400 characters")
    say(f"timing: adversarial inputs at {small_n:,} and {large_n:,} characters")
    patterns = [r.pattern for r in rules]
    for name, e in engines.items():
        pflags = [rule_flags(name, r.flags) for r in rules]
        small = e.run(patterns, [], flags.get(name), deadline_s, pattern_flags=pflags,
                      per_pattern_texts=[_adversarial(ts, small_n) for ts in per_rule_texts])
        large = e.run(patterns, [], flags.get(name), deadline_s, pattern_flags=pflags,
                      per_pattern_texts=[_adversarial(ts, large_n) for ts in per_rule_texts])
        for i, r in enumerate(rules):
            s_, l_ = small[i], large[i]
            if s_.timed_out or l_.timed_out:
                size = small_n if s_.timed_out else large_n
                w = _hang_text(r, _adversarial(per_rule_texts[i], size), e, name, flags,
                               deadline_s)
                out.append(Finding("timeout", "error", r.id, "Catastrophic backtracking",
                                   f"{name}: no result within {deadline_s}s on "
                                   f"{size:,}-character inputs."
                                   + (f" Hanging input: {_describe(w)}." if w else
                                      " (The single hanging input could not be isolated.)"),
                                   engines={name: "timeout"}, witness=w))
                continue
            if s_.ms is None or l_.ms is None:
                continue
            # Slowest single input at each size: one tool output is scanned at a time.
            t1 = max(s_.max_ms if s_.max_ms is not None else s_.ms, 0.01)
            t2 = l_.max_ms if l_.max_ms is not None else l_.ms
            k = math.log(max(t2 / t1, 1e-9)) / math.log(large_n / small_n)
            if (k >= 1.6 and t2 >= 20) or t2 > slow_ms:
                at_100k = t2 * (100_000 / large_n) ** max(k, 1)
                cap = (f" Measured at your --max-len of {large_n:,}: {t2:.0f} ms for one input."
                       if max_len else "")
                out.append(Finding(
                    "slow", "warning" if t2 < 1000 else "error", r.id,
                    "Superlinear time on long input" if k >= 1.6 else "Slow on long input",
                    f"{name}: slowest input of {small_n:,}→{large_n:,} chars took {t1:.0f}→{t2:.0f} ms "
                    f"(time ~ n^{k:.1f}); extrapolated to 100 KB of such text: "
                    f"~{at_100k / 1000:.0f} s per scan.{cap}",
                    engines={name: {"ms_small": t1, "ms_large": t2, "exponent": round(k, 2)}}))
    seen = set()
    dedup = []
    for f in out:
        key = (f.kind, f.rule_id, tuple(f.engines))
        if key not in seen:
            seen.add(key)
            dedup.append(f)
    return dedup
