"""The tester's own mistakes, stage 8: recall on cases the rule authors could see is fit,
not recall. Coverage reports held-out cases separately and says so when there are none."""

from gcl.coverage import Detector, summarize


def _cases(n_fit, n_held):
    rows = [{"id": f"f{i}", "lang": "en", "label": 1, "text": "x"} for i in range(n_fit)]
    rows += [{"id": f"h{i}", "lang": "en", "label": 1, "text": "y", "heldout": True, "author": "another model"}
             for i in range(n_held)]
    return rows


def test_without_held_out_cases_the_number_is_called_fit():
    s = summarize(_cases(10, 0), Detector("rules", [True] * 10))
    assert s["aggregate"]["recall_pct"] == 100.0
    assert s["heldout"]["heldout"]["attacks"] == 0 and "measures fit" in s["heldout"]["note"]


def test_self_fit_rules_are_exposed_by_held_out_cases():
    # Perfect on the authors' own cases, poor on cases written independently.
    cases = _cases(20, 20)
    s = summarize(cases, Detector("rules", [True] * 20 + [True] * 5 + [False] * 15))
    ho = s["heldout"]
    assert ho["fit"]["recall_pct"] == 100.0 and ho["heldout"]["caught"] == 5
    assert "tuned to their own cases" in ho["note"] and ho["heldout_authors"] == ["another model"]


def test_unanswered_held_out_cases_are_not_counted_as_missed():
    s = summarize(_cases(0, 3), Detector("adapter", [True, None, False], complete=False))
    assert s["heldout"]["heldout"] == {"attacks": 2, "caught": 1, "recall_pct": 50.0}
