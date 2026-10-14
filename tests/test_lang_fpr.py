"""Per-language false-positive budget: the hard-negative set, the metrics, the CI gate.

Two fixture detectors bracket every real one: a naive multilingual substring list (the
negative control: it must show a high false-positive rate on the hard negatives) and a
perfect oracle that reads the label (false positives must be exactly zero)."""

import json

import pytest

from gcl.coverage import (
    Detector,
    detect_with_adapter,
    evaluate_gate,
    fmt_rate,
    language_gaps,
    load_adapter,
    rate_cell,
    summarize,
    wilson,
)
from gcl.rules import load_cases

from .conftest import EX, ROOT

HARDNEG = ROOT / "gcl/data/hardneg.multilingual.jsonl"
LANGS = ["en", "es", "fr", "he", "pt", "de", "ar", "ru", "zh", "it", "ja", "hi"]


def case(i, lang, label, kind=None, text="x"):
    return {"id": i, "lang": lang, "label": label, "kind": kind or ("intent" if label else "benign"),
            "intent": "i" if label else None, "text": text}


# ------------------------------------------------------------------ the interval
def test_wilson_zero_counts_have_a_real_upper_bound():
    lo, hi = wilson(0, 12)
    assert lo == 0.0 and 0.24 < hi < 0.25  # 0/12 is not "0%": it could be ~24%
    lo, hi = wilson(12, 12)
    assert hi == 1.0 and 0.75 < lo < 0.76


def test_wilson_tiny_n_is_wide_and_n_zero_is_not_measured():
    lo, hi = wilson(1, 1)
    assert lo < 0.25 and hi == 1.0
    cell = rate_cell(0, 0)
    assert cell["pct"] is None and cell["ci_low_pct"] is None and cell["n"] == 0
    assert fmt_rate(cell) == "not measured"  # never "0%" and never an interval of (0, 0)


def test_rate_cell_flags_small_n_and_always_carries_the_interval():
    small, big = rate_cell(2, 12), rate_cell(60, 300)
    assert small["small_n"] and not big["small_n"]
    assert fmt_rate(small) == "2/12 = 16.7% [4.7-44.8]"
    assert "[" in fmt_rate(big)


# ------------------------------------------------------------------ summarize + gaps
def test_summarize_reports_false_positive_rate_with_interval_over_all_benign():
    cases = [case("a", "en", 1), case("b", "en", 0), case("c", "en", 0, "hard_negative"),
             case("d", "es", 1), case("e", "es", 0), case("f", "es", 0, "hard_negative")]
    det = Detector("t", [True, False, True, False, False, False])
    s = summarize(cases, det)
    en, es = s["by_lang"]["en"], s["by_lang"]["es"]
    assert (en["fpr"]["k"], en["fpr"]["n"]) == (1, 2) and en["fpr"]["small_n"]
    assert (en["hn_fpr"]["k"], en["hn_fpr"]["n"]) == (1, 1)
    assert es["fpr"]["pct"] == 0.0 and es["fpr"]["ci_high_pct"] > 30
    assert (s["fpr"]["k"], s["fpr"]["n"]) == (1, 4)
    # recall: en caught 1/1, es 0/1 -> es is 100 points below English
    assert es["gap_vs_en"]["recall"]["pp"] == -100.0
    assert es["gap_vs_en"]["fpr"]["pp"] == -50.0
    assert es["gap_vs_en"]["recall"]["clear"] is False  # n=1 each: intervals overlap, it may be noise


def test_gap_is_clear_only_when_intervals_do_not_overlap():
    by = {"en": {"recall_cell": rate_cell(95, 100), "fpr": rate_cell(0, 100)},
          "xx": {"recall_cell": rate_cell(10, 100), "fpr": rate_cell(30, 100)},
          "yy": {"recall_cell": rate_cell(0, 0), "fpr": rate_cell(1, 100)}}
    g = language_gaps(by)
    assert g["xx"]["recall"] == {"pp": -85.0, "clear": True}
    assert g["xx"]["fpr"]["clear"] is True
    assert g["yy"]["recall"] is None  # no attacks in yy: no gap, not a gap of 100
    assert language_gaps({"xx": by["xx"]}) == {}  # no English baseline


def test_unanswered_cases_are_not_counted_as_clean():
    cases = [case("a", "en", 0), case("b", "en", 0)]
    s = summarize(cases, Detector("t", [False, None], complete=False))
    assert (s["by_lang"]["en"]["fpr"]["k"], s["by_lang"]["en"]["fpr"]["n"]) == (0, 1)


# ------------------------------------------------------------------ the gate
def _sec(attacks_caught, fp_flags):
    """en: attacks_caught=(k,n); fp_flags per language -> (k,n) benign."""
    by = {}
    for lg, (k, n) in fp_flags.items():
        ak, an = attacks_caught.get(lg, (0, 0))
        by[lg] = {"recall_cell": rate_cell(ak, an), "fpr": rate_cell(k, n)}
    return {"by_lang": by, "fpr": rate_cell(sum(k for k, _ in fp_flags.values()),
                                            sum(n for _, n in fp_flags.values()))}


def test_gate_names_the_language_and_counts():
    sec = _sec({"en": (11, 12), "pt": (3, 12)}, {"en": (0, 20), "pt": (4, 20)})
    g = evaluate_gate(sec, min_recall=50, max_fpr=0.05, max_fpr_lang=0.1)
    texts = [b["text"] for b in g["breaches"]]
    assert not g["passed"]
    assert any(t.startswith("recall in pt: 3/12 = 25.0%") for t in texts)
    assert any(t.startswith("false-positive rate in pt: 4/20 = 20.0%") for t in texts)
    assert any(t.startswith("false-positive rate overall: 4/40 = 10.0%") for t in texts)
    assert not any("in en" in t for t in texts)


def test_gate_boundary_is_not_a_breach():
    sec = _sec({"en": (5, 10)}, {"en": (1, 20)})
    assert evaluate_gate(sec, min_recall=50, max_fpr=0.05, max_fpr_lang=0.05)["passed"]
    assert not evaluate_gate(sec, max_fpr=0.049)["passed"]


def test_gate_zero_count_passes_but_unmeasured_fails():
    sec = _sec({"en": (1, 1)}, {"en": (0, 6)})
    assert evaluate_gate(sec, max_fpr=0.0, max_fpr_lang=0.0)["passed"]
    empty = _sec({}, {"en": (0, 0)})
    g = evaluate_gate(empty, max_fpr=0.05, max_fpr_lang=0.05, min_recall=10)
    assert {b["kind"] for b in g["breaches"]} == {"unmeasured"} and len(g["breaches"]) == 3


def test_gate_skips_a_language_with_no_attacks_but_says_so():
    sec = _sec({"en": (9, 10)}, {"en": (0, 10), "pt": (0, 10)})
    g = evaluate_gate(sec, min_recall=80)
    assert g["passed"] and g["not_measured"] == ["recall:pt"]


def test_gate_with_no_limits_passes_and_records_them():
    g = evaluate_gate(_sec({}, {"en": (5, 10)}))
    assert g["passed"] and g["limits"] == {"min_recall_pct": None, "max_fpr": None, "max_fpr_lang": None}


# ------------------------------------------------------------------ the hard-negative set
def test_hardneg_set_is_consistent_across_languages_and_marked():
    rows = load_cases(HARDNEG)
    assert len(rows) == 144 and len({r["id"] for r in rows}) == 144
    by = {}
    for r in rows:
        assert r["label"] == 0 and r["kind"] == "hard_negative"
        assert r["author"] == "gcl-authored" and r["native_reviewed"] is False
        assert "not native-speaker reviewed" in r["provenance"]
        by.setdefault(r["lang"], []).append(r)
    assert sorted(by) == sorted(LANGS)
    assert all(len(v) == 12 for v in by.values())
    base_themes = [[r["theme"] for r in v if r["base"]] for v in by.values()]
    assert all(t == base_themes[0] and len(t) == 10 for t in base_themes)  # same ten themes, same order
    assert all(sum(not r["base"] for r in v) == 2 for v in by.values())  # two language-specific each
    assert all(r["text"].strip() for r in rows)


def test_hardneg_texts_are_not_copied_between_languages():
    texts = [r["text"] for r in load_cases(HARDNEG)]
    assert len(set(texts)) == len(texts)


# ------------------------------------------------------------------ fixture detectors
def _hn_cases():
    return load_cases(HARDNEG)


def test_naive_substring_detector_is_a_negative_control():
    cases = _hn_cases()
    det = detect_with_adapter(load_adapter(EX / "coverage/adapter.substring.yaml"), cases)
    assert det.complete
    s = summarize(cases, det)
    assert s["fpr"]["pct"] > 50  # most hard negatives trip a word list
    # every language, including English, is hit: this is not an English-only artefact
    assert all(r["fpr"]["k"] >= 6 for r in s["by_lang"].values())
    g = evaluate_gate(s, max_fpr=0.05, max_fpr_lang=0.05)
    assert not g["passed"] and len(g["breaches"]) == 1 + len(LANGS)


def test_perfect_oracle_has_zero_false_positives():
    cases = [*_hn_cases(), case("att", "en", 1)]
    s = summarize(cases, Detector("oracle", [bool(c["label"]) for c in cases]))
    assert s["fpr"]["k"] == 0 and s["fpr"]["n"] == 144
    assert all(r["fpr"]["k"] == 0 for r in s["by_lang"].values())
    assert evaluate_gate(s, max_fpr=0.0, max_fpr_lang=0.0)["passed"]


# ------------------------------------------------------------------ CLI
def run(args):
    from typer.testing import CliRunner

    from gcl.cli import app

    return CliRunner().invoke(app, ["coverage", *args])


def test_cli_breach_exits_1_names_the_breach_and_writes_json(tmp_path):
    out = tmp_path / "o"
    r = run(["--adapter", str(EX / "coverage/adapter.substring.yaml"), "--hard-negatives",
             "--max-fpr", "0.05", "--max-fpr-lang", "0.05", "--out", str(out), "--format", "json"])
    assert r.exit_code == 1
    assert "THRESHOLD BREACHED: false-positive rate overall" in r.output
    doc = json.loads((out / "report.json").read_text())
    gate = doc["coverage"]["gate"]
    assert not gate["passed"] and gate["limits"]["max_fpr"] == 0.05
    assert doc["coverage"]["by_lang"]["pt"]["fpr"]["n"] == 12


def test_cli_passes_with_the_example_detector_and_loose_limit():
    r = run(["--adapter", str(EX / "coverage/adapter.keyword.yaml"), "--hard-negatives",
             "--max-fpr", "0.05", "--max-fpr-lang", "0.5"])
    assert r.exit_code == 0 and "Thresholds met" in r.output


def test_cli_without_hard_negatives_keeps_the_default_cases():
    r = run(["--adapter", str(EX / "coverage/adapter.keyword.yaml")])
    assert r.exit_code == 0 and "pt " not in r.output


def test_cli_rejects_a_percent_where_a_fraction_is_expected():
    r = run(["--adapter", str(EX / "coverage/adapter.keyword.yaml"), "--max-fpr", "5"])
    assert r.exit_code != 0


def test_old_max_fp_percent_option_still_gates():
    r = run(["--adapter", str(EX / "coverage/adapter.substring.yaml"), "--hard-negatives", "--max-fp", "10"])
    assert r.exit_code == 1


def test_cli_incomplete_run_is_exit_2_not_a_pass(tmp_path):
    bad = tmp_path / "a.yaml"
    bad.write_text('name: broken\nargv: ["python3", "-c", "pass"]\n')
    r = run(["--adapter", str(bad), "--hard-negatives", "--max-fpr", "0.5"])
    assert r.exit_code == 2


@pytest.mark.parametrize("flag", ["--max-fpr", "--max-fpr-lang"])
def test_cli_fraction_bounds(flag):
    assert run(["--adapter", str(EX / "coverage/adapter.keyword.yaml"), flag, "-0.1"]).exit_code != 0
