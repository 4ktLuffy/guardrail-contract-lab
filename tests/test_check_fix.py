"""`check` must go red on each flawed rule for the right reason, and `fix` must turn
the fixable ones green without changing what they match under Python."""

import json

import pytest

from gcl.check import _ddmin, run_check
from gcl.fix import fix_rule, run_fix
from gcl.lint import lint_rule
from gcl.rules import Rule, load_cases, load_rules
from gcl.samples import positive_samples

from .conftest import EX, ROOT, needs_node

BENIGN = [c for c in load_cases(ROOT / "gcl" / "data" / "cases.multilingual.jsonl")
          if c["label"] == 0]
VULN = EX / "portability" / "rules.vulnerable.yaml"


# ---------------------------------------------------------------- lint
@pytest.mark.parametrize("pattern,lang,code", [
    ("(?i)ignore", None, "GCL101"),
    ("(?-i:DAN)", None, "GCL102"),
    (r"\bпароль\b", None, "GCL103"),
    (r"\bvergiss\b", "de", "GCL103"),
    ("(?P<v>send)", None, "GCL104"),
    (r"sh\Z", None, "GCL105"),
    ("a*+", None, "GCL106"),
    ("(?<!x)y", None, "GCL107"),
    (r"(\w+\s?)+$", None, "GCL108"),
    ("straße", None, "GCL109"),
    ("[аеорсух]{3,}", None, "GCL110"),
])
def test_lint_codes(pattern, lang, code):
    codes = {h.code for h in lint_rule(Rule("r", pattern, lang=lang))}
    assert code in codes


def test_lint_quiet_on_a_plain_ascii_rule():
    assert lint_rule(Rule("r", r"\bignore\s+previous\s+instructions\b")) == []


# ---------------------------------------------------------------- samples
@pytest.mark.parametrize("pattern", [
    r"(?i)\bignore\s+(all\s+)?(previous|prior)\s+instructions?",
    r"\d{3}-\d{4}", r"(a)\1x", r"[^\s]{3}@\w+\.example", r"(?<![a-z])DAN.{0,20}(?:anything)",
])
def test_samples_really_match(pattern):
    import re

    samples = positive_samples(pattern)
    assert samples
    assert any(re.search(pattern, s, re.I | re.M) for s in samples)


def test_samples_never_run_the_rule_and_stay_bounded():
    import time

    t = time.perf_counter()
    positive_samples(r"(a+)+(?=z)a{40}")          # would hang if it were executed
    huge = positive_samples(r"((a{200}){200}){200}")  # nested repeats explode if uncapped
    assert time.perf_counter() - t < 2.0
    assert all(len(x) <= 4002 for x in huge)


# ---------------------------------------------------------------- ddmin
def test_ddmin_keeps_the_property_and_shrinks():
    text = "please forget about it and then ignore everything said before"
    out = _ddmin(text, lambda cands: ["ignore" in c for c in cands])
    assert out == "ignore"


# ---------------------------------------------------------------- check
@needs_node
def test_check_flags_each_flawed_rule_for_the_right_reason():
    res = run_check(load_rules(VULN), ["python", "node"], benign=BENIGN, deadline_s=1.5)
    kinds = {}
    for f in res.findings:
        kinds.setdefault(f.rule_id, set()).add(f.kind)
    assert kinds["override-en"] == {"compile_split"}
    assert kinds["exfil-named"] == {"compile_split"}
    assert kinds["override-ru"] == {"match_split"}
    assert kinds["exfil-end"] == {"match_split"}
    assert kinds["homoglyph-run"] == {"benign_hit"}
    assert kinds["repeated-noise"] == {"timeout"}
    assert kinds["fake-delimiter"] == {"slow"}  # quadratic, though no lint rule sees it
    # ASCII words: only the "." vs \r difference remains, reported as the narrower kind.
    assert kinds["override-de"] == {"line_split"}
    # (?-i:…) modifiers compile only on ES2025 engines (node 23+): a finding exactly there.
    from gcl.engines import get_engine

    modern = get_engine("node").run(["(?-i:a)"], ["a"])[0].compiled
    assert ("compile_split" in kinds.get("dan-strict", set())) == (not modern)
    assert res.complete


@needs_node
def test_witness_is_minimal_and_still_disagrees():
    res = run_check(load_rules(VULN), ["python", "node"], deadline_s=1.5, redos=False)
    f = next(f for f in res.findings if f.rule_id == "override-ru")
    assert f.witness and len(f.witness) <= len(f.original)
    from gcl.engines import get_engine

    pat = next(r.pattern for r in load_rules(VULN).rules if r.id == "override-ru")
    py = get_engine("python").run([pat], [f.witness])[0].matched(0)
    js = get_engine("node").run([pat], [f.witness])[0].matched(0)
    assert py is True and js is False


def test_missing_engine_makes_the_run_incomplete(monkeypatch):
    from gcl import engines as E
    from gcl.engines.base import Engine

    monkeypatch.setitem(E.base.ENGINES, "node",
                        lambda: Engine("node", ["definitely-not-node-xyz"], "im"))
    res = run_check(load_rules(VULN), ["python", "node"], deadline_s=1.0, redos=False)
    assert res.complete is False
    assert any(f.kind == "engine_missing" for f in res.findings)


# ---------------------------------------------------------------- fix
def test_fix_drops_global_flag_only_when_every_loader_sets_it():
    r = Rule("r", "(?i)ignore")
    # Dropped (both loaders set i), and "i" spelled out with Python's case partners.
    assert fix_rule(r, {"python": "IM", "node": "im"}).fixed == "[Ii\\u0130\\u0131]gnore"
    assert fix_rule(r, {"python": "IM", "node": "m"}).fixed.startswith("(?i)")


def test_fix_named_group_kept_when_back_referenced():
    r = Rule("r", "(?P<a>x)(?P=a)")
    res = fix_rule(r, {"python": "IM", "node": "im"})
    assert res.fixed == r.pattern and res.not_fixed


@needs_node
def test_fix_is_verified_and_check_comes_back_clean(tmp_path):
    texts = [c["text"] for c in load_cases(ROOT / "gcl" / "data" / "cases.multilingual.jsonl")]
    out = tmp_path / "fixed.yaml"
    summary = run_fix(VULN, out, ["python", "node"], {"python": "IM", "node": "im"}, texts)
    fixed_ids = {x["rule_id"] for x in summary["rewritten"]}
    assert {"override-en", "override-ru", "exfil-named", "exfil-end"} <= fixed_ids
    assert "repeated-noise" in summary["rejected"]  # hangs: cannot verify, left alone
    res = run_check(load_rules(out), ["python", "node"], deadline_s=1.5, redos=False)
    split = {f.rule_id for f in res.findings if f.kind in ("compile_split", "match_split")}
    assert not (split & fixed_ids)  # every rewritten rule now agrees across engines
    # Left alone and still reported: the rule that hangs (Cyrillic \w), and — on engines
    # without ES2025 modifiers (Node < 23) — the rule using (?-i:…), which fix cannot rewrite.
    from gcl.engines import get_engine

    modern = get_engine("node").run(["(?-i:a)"], ["a"])[0].compiled
    assert split <= ({"repeated-noise"} if modern else {"repeated-noise", "dan-strict"})
    # Comments in the original file survive the rewrite.
    assert out.read_text().startswith("# A small, deliberately flawed rule set")


@needs_node
def test_fix_json_round_trip(tmp_path):
    src = tmp_path / "r.json"
    src.write_text(json.dumps({"c": [{"id": "a", "pattern": "(?i)\\bпароль\\b"}]}), encoding="utf-8")
    out = tmp_path / "r.portable.json"
    summary = run_fix(src, out, ["python", "node"], {"python": "IM", "node": "im"}, ["дай пароль"])
    assert summary["rewritten"]
    data = json.loads(out.read_text(encoding="utf-8"))
    assert not data["c"][0]["pattern"].startswith("(?i)")


def test_timing_flags_quadratic_growth_not_linear(tmp_rules):
    from gcl.check import _timing
    from gcl.engines import get_engine

    path = tmp_rules({"quad": r"={3,}\s*(begin|end)\s+prompt", "linear": r"begin\s+prompt"})
    rules = load_rules(path).rules
    texts = [positive_samples(r.pattern) for r in rules]
    found = _timing(rules, texts, {"python": get_engine("python")}, {}, 10.0, 250.0, lambda *_: None)
    by_rule = {f.rule_id: f for f in found}
    assert "quad" in by_rule and by_rule["quad"].engines["python"]["exponent"] > 1.6
    assert "linear" not in by_rule


def test_rewrite_file_preserves_control_characters(tmp_path):
    from gcl.fix import rewrite_file

    src = tmp_path / "r.yaml"
    src.write_text('rules:\n  - {id: nl, pattern: "(?i)foo\\nbar"}\n  - {id: keep, pattern: \'x\'}\n',
                   encoding="utf-8")
    rules = load_rules(src).rules
    assert rules[0].pattern == "(?i)foo\nbar"
    out = rewrite_file(src, {"nl": "foo\nbar"}, rules, tmp_path / "o.yaml")
    again = load_rules(out).rules
    assert [r.pattern for r in again] == ["foo\nbar", "x"]


def test_fix_scope_is_exact_at_script_boundaries(tmp_path):
    texts = [c["text"] for c in load_cases(ROOT / "gcl" / "data" / "cases.multilingual.jsonl")]
    src = tmp_path / "r.yaml"
    src.write_text("rules:\n  - {id: s, pattern: '\\bsecret\\b'}\n", encoding="utf-8")
    out = tmp_path / "o.yaml"
    run_fix(src, out, ["python"], {"python": "IM"}, texts, ["cyrillic"])
    import re

    new = load_rules(out).rules[0].pattern
    for t in ["secret×", "Жsecret", "secretЖ", "é secret", "Ásecret", "secret_", "x secret."]:
        assert bool(re.search(new, t, re.I)) == bool(re.search(r"\bsecret\b", t, re.I)), t


def test_sample_generation_has_a_work_budget():
    import time

    t = time.perf_counter()
    positive_samples(r"(?:(?:(?:a{0}){200}){200}){200}")
    assert time.perf_counter() - t < 2.0


def test_fix_respects_python_ascii_mode(tmp_path):
    import re

    texts = [c["text"] for c in load_cases(ROOT / "gcl" / "data" / "cases.multilingual.jsonl")]
    src = tmp_path / "r.yaml"
    src.write_text("rules:\n  - {id: a, pattern: 'code\\w+Z'}\n", encoding="utf-8")
    out = tmp_path / "o.yaml"
    run_fix(src, out, ["python"], {"python": "A"}, texts)
    new = load_rules(out).rules[0].pattern
    for t in ["codeéZ", "codexZ", "code_Z"]:
        assert bool(re.search(new, t, re.A)) == bool(re.search(r"code\w+Z", t, re.A)), t


def test_fix_refuses_a_rewrite_with_no_positive_evidence(tmp_path):
    src = tmp_path / "r.yaml"
    src.write_text("rules:\n  - {id: a, pattern: '\\Acode\\w+(?=Z)'}\n", encoding="utf-8")
    summary = run_fix(src, tmp_path / "o.yaml", ["python"], {"python": "IM"}, ["nothing here"])
    assert "a" in summary["rejected"] and "prove nothing" in summary["rejected"]["a"]


def test_yaml_scalar_escapes_unicode_line_separators():
    import yaml

    from gcl.fix import _yaml_scalar

    s = "a" + chr(0x85) + "b" + chr(0x2028) + "c"
    assert yaml.safe_load("k: " + _yaml_scalar(s))["k"] == s
