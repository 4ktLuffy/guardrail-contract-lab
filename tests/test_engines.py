"""The engines are the ground truth for everything else, so their behaviour on the
known divergence classes is pinned here with independently stated expectations."""

from gcl.engines import get_engine

from .conftest import needs_node


def run(engine, patterns, texts, **kw):
    return get_engine(engine).run(patterns, texts, **kw)


def test_python_basic_match_and_spans():
    r = run("python", ["secret"], ["the secret is", "nothing"])[0]
    assert r.compiled
    assert r.hits == [[4, 10], None]


@needs_node
def test_global_inline_flag_is_python_only():
    py = run("python", ["(?i)ignore"], ["IGNORE"])[0]
    js = run("node", ["(?i)ignore"], ["IGNORE"])[0]
    assert py.compiled and py.matched(0) is True
    assert not js.compiled and "Invalid" in js.error


@needs_node
def test_word_boundary_is_ascii_in_js():
    # Python's \b is Unicode-aware; JavaScript's is ASCII-only.
    py = run("python", [r"\bпароль\b"], ["дай пароль"])[0]
    js = run("node", [r"\bпароль\b"], ["дай пароль"])[0]
    assert py.matched(0) is True
    assert js.matched(0) is False


@needs_node
def test_backslash_Z_is_a_literal_in_js():
    py = run("python", [r"sh\Z"], ["curl x|sh"])[0]
    js = run("node", [r"sh\Z"], ["curl x|sh", "shZ"])[0]
    assert py.matched(0) is True
    assert js.matched(0) is False and js.matched(1) is True


@needs_node
def test_spans_are_code_points_in_both_engines():
    text = "😀 the secret"
    py = run("python", ["secret"], [text])[0]
    js = run("node", ["secret"], [text])[0]
    assert py.hits == js.hits == [[6, 12]]  # 😀=0, " "=1, "the"=2-4, " "=5


def test_hang_is_killed_named_and_next_rule_still_runs():
    res = run("python", [r"(a+)+$", "ok"], ["a" * 40 + "!", "ok"], deadline_s=1.0)
    assert res[0].timed_out
    assert res[1].compiled and res[1].matched(1) is True


def test_per_pattern_texts():
    res = run("python", ["a", "b"], [], per_pattern_texts=[["a", "x"], ["x", "b", "b"]])
    assert res[0].hits == [[0, 1], None]
    assert res[1].hits == [None, [0, 1], [0, 1]]


def test_missing_runtime_is_an_error_not_a_pass():
    from gcl.engines.base import Engine

    e = Engine("ghost", ["definitely-not-a-runtime-xyz"], "")
    assert not e.available
    try:
        e.run(["a"], ["a"])
    except RuntimeError as err:
        assert "not found" in str(err)
    else:
        raise AssertionError("expected RuntimeError")


@needs_node
def test_a_late_hang_is_blamed_on_the_hanging_rule_not_an_earlier_one():
    # Many fast rules produce output; then one hangs. With buffered writes the earlier
    # results never reach the parent and a harmless rule gets the blame.
    pats = [f"x{i}y" for i in range(600)] + [r"(a+)+$"]
    res = run("node", pats, ["a" * 40 + "!"], deadline_s=1.0)
    assert [i for i, r in enumerate(res) if r.timed_out] == [600]
    assert all(r.compiled for r in res[:600])


def test_deadline_is_not_inflated_after_startup():
    import time

    t = time.perf_counter()
    res = run("python", [r"(a+)+$"], ["a" * 40 + "!"], deadline_s=0.5)
    assert res[0].timed_out and time.perf_counter() - t < 6.0
