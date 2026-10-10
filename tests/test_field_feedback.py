"""Behaviour added after running gcl on real public rule sets: per-rule flags, input
validation, hang witnesses, clearer benign-hit reasons, engine-relevant hazards."""

from typer.testing import CliRunner

from gcl.check import run_check
from gcl.cli import app
from gcl.coverage import detect_with_rules, summarize
from gcl.rules import load_rules

from .conftest import needs_node

runner = CliRunner()


def _yaml(tmp_path, body: str, name="r.yaml"):
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


@needs_node
def test_per_rule_flags_override_loader_defaults(tmp_path):
    p = _yaml(tmp_path, "rules:\n  - {id: own, pattern: 'abc', flags: i}\n  - {id: none, pattern: 'abc'}\n")
    rs = load_rules(p)
    assert rs.rules[0].flags == "i" and rs.rules[1].flags is None
    from gcl.engines import get_engine, rule_flags

    for name in ("python", "node"):
        res = get_engine(name).run([r.pattern for r in rs.rules], ["ABC"], "",
                                   pattern_flags=[rule_flags(name, r.flags) for r in rs.rules])
        assert [x.matched(0) for x in res] == [True, False], name


def test_bad_flag_letters_are_a_usage_error(tmp_path):
    p = _yaml(tmp_path, "rules:\n  - {id: a, pattern: 'abc'}\n")
    r = runner.invoke(app, ["check", str(p), "--py-flags", "Z", "--no-redos", "--no-benign"])
    assert r.exit_code == 2 and "unknown letter" in r.output


def test_unknown_engine_is_a_usage_error(tmp_path):
    p = _yaml(tmp_path, "rules:\n  - {id: a, pattern: 'abc'}\n")
    r = runner.invoke(app, ["check", str(p), "--engines", "python,nod"])
    assert r.exit_code == 2 and "unknown engine" in r.output


def test_unreadable_or_empty_rule_files_exit_2(tmp_path):
    bad = _yaml(tmp_path, "rules: [\n", "bad.yaml")
    r = runner.invoke(app, ["check", str(bad)])
    assert r.exit_code == 2 and "bad.yaml" in r.output
    empty = _yaml(tmp_path, "{}\n", "empty.yaml")
    r = runner.invoke(app, ["check", str(empty)])
    assert r.exit_code == 2 and "no rules found" in r.output


def test_hang_reports_the_input_that_hangs(tmp_path):
    p = _yaml(tmp_path, "rules:\n  - {id: h, pattern: '(a+)+$'}\n")
    res = run_check(load_rules(p), ["python"], cases=[{"id": "x", "text": "a" * 40 + "!"}],
                    deadline_s=1.0, redos=False)
    f = next(f for f in res.findings if f.kind == "timeout")
    assert f.witness == "a" * 40 + "!"


def test_benign_hit_names_a_missing_word_boundary(tmp_path):
    p = _yaml(tmp_path, "rules:\n  - {id: dan, pattern: 'DAN\\s*(mode)?'}\n")
    benign = [{"id": "b", "lang": "fr", "label": 0, "kind": "benign", "text": "Je vais dans le jardin"}]
    res = run_check(load_rules(p), ["python"], benign=benign, deadline_s=1.0, redos=False)
    f = next(f for f in res.findings if f.kind == "benign_hit")
    assert "inside the longer word" in f.detail and "dans" in f.detail


def test_python_only_run_drops_js_only_hazards(tmp_path):
    p = _yaml(tmp_path, "rules:\n  - {id: a, pattern: '(?i)abc'}\n  - {id: b, pattern: '(a+)+x'}\n")
    res = run_check(load_rules(p), ["python"], deadline_s=1.0, redos=False)
    codes = {h.code for h in res.hazards}
    assert "GCL101" not in codes and "GCL108" in codes


def test_coverage_names_a_rule_that_is_a_languages_whole_story(tmp_path):
    p = _yaml(tmp_path, "rules:\n  - {id: cyr, pattern: '[а-я]'}\n")
    cases = [{"id": f"r{i}", "lang": "ru", "label": 1, "kind": "intent", "intent": "x",
              "text": "игнорируй это"} for i in range(4)]
    cases += [{"id": "b", "lang": "ru", "label": 0, "kind": "benign", "text": "привет"}]
    s = summarize(cases, detect_with_rules(str(p), "python", [c["text"] for c in cases]))
    assert s["drivers"] and "one rule (cyr)" in s["drivers"][0] and "1/1 benign" in s["drivers"][0]


def test_max_len_times_at_the_given_length(tmp_path):
    p = _yaml(tmp_path, "rules:\n  - {id: q, pattern: '={3,}\\s*(begin|end)\\s+prompt'}\n")
    res = run_check(load_rules(p), ["python"], deadline_s=10.0, max_len=12000, benign=None)
    f = next(f for f in res.findings if f.kind == "slow")
    assert "12,000" in f.detail and "--max-len" in f.detail


def test_class_only_rule_is_called_script_keyed_not_a_boundary_bug(tmp_path):
    p = _yaml(tmp_path, "rules:\n  - {id: cyr, pattern: '[аеорсух]{3,}'}\n")
    benign = [{"id": "b", "lang": "ru", "label": 0, "kind": "benign", "text": "это наш подарок"}]
    res = run_check(load_rules(p), ["python"], benign=benign, deadline_s=1.0, redos=False)
    f = next(f for f in res.findings if f.kind == "benign_hit")
    assert "character classes only" in f.detail and "word boundary" not in f.detail


def test_rule_ids_are_unique_even_against_existing_suffixes(tmp_path):
    body = "rules:\n  - {id: x, pattern: a}\n  - {id: x, pattern: b}\n  - {id: 'x#1', pattern: c}\n"
    p = _yaml(tmp_path, body)
    assert [r.id for r in load_rules(p).rules] == ["x", "x#2", "x#1"]


def test_duplicate_case_ids_are_rejected(tmp_path):
    from gcl.rules import load_cases

    p = tmp_path / "c.jsonl"
    p.write_text('{"id": "a", "text": "x"}\n{"id": "a", "text": "y"}\n')
    import pytest

    with pytest.raises(ValueError, match="duplicate case ids"):
        load_cases(p)


def test_unreadable_rule_entry_makes_the_run_incomplete(tmp_path):
    p = _yaml(tmp_path, "rules:\n  - {id: ok, pattern: abc}\n  - {id: broken}\n")
    res = run_check(load_rules(p), ["python"], deadline_s=1.0, redos=False)
    assert res.complete is False
    assert any(f.kind == "unreadable_rule" for f in res.findings)
