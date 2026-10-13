"""Route parity (`--extra routes`): the same guard on every way to the same action."""
import json
import sys
from types import SimpleNamespace

import pytest

from gcl.enforce import mcp_surfaces as ms
from gcl.enforce import routes as rt
from gcl.enforce.adapters import NemoServer, Observation, ReferenceGateway, ReferenceMCPGateway
from gcl.enforce.contracts import run_contracts

ONLY = {"none", "r01", "r02", "r03", "r04", "r05"}


def _routes(run):
    return {r["scenario"]["id"]: r for r in run["results"] if r["scenario"]["mode"] == "route"}


@pytest.fixture(scope="module")
def strict(tmp_path_factory):
    return run_contracts(ReferenceGateway(sys.executable, tmp_path_factory.mktemp("s"), "strict"), 10,
                         extra=("routes",), only=ONLY, settle_s=0.3)


@pytest.fixture(scope="module")
def naive(tmp_path_factory):
    return run_contracts(ReferenceGateway(sys.executable, tmp_path_factory.mktemp("n"), "naive"), 10,
                         extra=("routes",), only=ONLY, settle_s=0.3)


# --- the plan ---------------------------------------------------------------------------------------------
def test_an_adapter_declares_its_routes_and_an_mcp_gateway_has_the_mcp_ones(tmp_path):
    ref = rt.plan(ReferenceGateway(sys.executable, tmp_path, "strict"))
    assert [(rid, r.id) for rid, r in ref] == [("r01", "chat"), ("r02", "chat_stream"), ("r03", "messages"),
                                               ("r04", "responses"), ("r05", "completions")]
    mcp = rt.plan(ReferenceMCPGateway(sys.executable, tmp_path, "strict"))
    assert [r.surface for _, r in mcp] == ["m00", "m16", "m15", "m09", "m10"]
    assert all(r.surface in ms.BY_ID for _, r in mcp)
    assert not rt.routes_of(NemoServer(sys.executable, tmp_path, "default"))


def test_routes_need_an_adapter_with_routes(tmp_path):
    with pytest.raises(ValueError, match="declares routes"):
        run_contracts(NemoServer(sys.executable, tmp_path, "default"), 5, extra=("routes",))


def test_request_shapes_and_reply_extraction():
    path, body = rt.build_request(rt.MESSAGES, "hi", "m")
    assert path == "/v1/messages" and body["messages"] == [{"role": "user", "content": "hi"}] and body["max_tokens"]
    assert rt.build_request(rt.COMPLETIONS, "hi", "m")[1]["prompt"] == "hi"
    assert rt.build_request(rt.RESPONSES, "hi", "m")[1]["input"] == "hi"
    assert rt.build_request(rt.CHAT_STREAM, "hi", "m")[1]["stream"] is True
    assert "stream" not in rt.build_request(rt.CHAT, "hi", "m")[1]
    chat = json.dumps({"choices": [{"message": {"content": "A B"}}]})
    assert "A B" in rt.client_texts(rt.CHAT, chat)
    assert "A B" in rt.client_texts(rt.MESSAGES, json.dumps({"content": [{"type": "text", "text": "A B"}]}))
    assert "A B" in rt.client_texts(rt.COMPLETIONS, json.dumps({"choices": [{"text": "A B"}]}))
    assert "A B" in rt.client_texts(rt.RESPONSES, json.dumps({"output": [{"content": [{"text": "A B"}]}]}))
    sse = "".join(f'data: {json.dumps({"choices": [{"delta": {"content": c}}]})}\n\n' for c in ("Dis", "regard"))
    assert "Disregard" in rt.client_texts(rt.CHAT_STREAM, sse + "data: [DONE]\n\n")


# --- proof rules (synthetic sessions) ---------------------------------------------------------------------
def _obs(status=200, finished=True, transport=False, text="{}"):
    return Observation(status, text, finished, 0.1, "", transport)


def _ends(rid="r03", kind="control", in_text=None, out_text=None):
    m_in, m_out = rt._markers(rid, "x", kind)
    atk = kind == "in", kind == "out"
    p_in = f"{m_in} {ms.ATTACK_TEXT if atk[0] else ms.BENIGN_NOTE}"
    p_out = f"{m_out} {ms.ATTACK_REPLY_TEXT if atk[1] else ms.BENIGN_REPLY_TEXT}"
    return [rt.End("request", m_in, p_in, [p_in] if in_text is None else in_text),
            rt.End("reply", m_out, p_out, [p_out] if out_text is None else out_text)]


def test_control_is_carried_only_when_both_ends_got_their_text():
    assert rt.judge_control(_obs(), _ends())[0] == "carried"
    stripped = _ends(in_text=[ms.BENIGN_NOTE], out_text=["x " + ms.BENIGN_REPLY_TEXT.lower()])
    out = rt.judge_control(_obs(), stripped)[0]
    assert (out, ms.policy_of(out, False)) == ("carried, marker stripped", "held")
    assert rt.judge_control(_obs(), _ends(), settled=False)[0] == "unsettled"


def test_not_carried_needs_a_proper_answer_and_never_reads_as_held():
    nothing = _ends(in_text=[], out_text=["{}"])
    for status in (404, 405, 501, 200):
        out = rt.judge_control(_obs(status), nothing)[0]
        assert (out, ms.policy_of(out, False)) == ("not carried", "n/a"), status
    for obs in (_obs(None, False, True), _obs(200, False)):
        out = rt.judge_control(obs, nothing)[0]
        assert out in ("transport failure", "no answer") and ms.policy_of(out, False) == "unverified"
    for status in (400, 401, 403, 429, 500, 502):   # a refusal is not "the route is absent"
        out = rt.judge_control(_obs(status), nothing)[0]
        assert (out, ms.policy_of(out, False)) == ("unexpected status", "unverified"), status
    part = _ends(in_text=["please record"], out_text=["{}"])
    assert rt.judge_control(_obs(), part)[0] == "text altered"


def _event(marker, valid=True, delivered=True):
    return {"body_text": f"x {marker} y", "valid": valid, "mode": "surface_block", "answered": {"verdict": "BLOCK"},
            "delivery": {"delivered": delivered}, "stage": "input"}


def test_attack_outcomes_at_one_far_end():
    end = _ends(kind="in", in_text=[])[0]
    sentence = ms.ATTACK_TEXT
    assert rt.judge_attack(_obs(), end, [], True)[0] == "dropped unscanned"
    assert rt.judge_attack(_obs(), end, [_event(end.marker)], True)[0] == "stopped"
    assert rt.judge_attack(_obs(), end, [_event(end.marker, delivered=False)], True)[0] == "unconfirmed"
    leaked = rt.End("request", end.marker, end.payload, [end.payload])
    assert rt.judge_attack(_obs(), leaked, [], True)[0] == "passed unscanned"
    assert rt.judge_attack(_obs(), leaked, [_event(end.marker)], True)[0] == "passed despite block"
    bare = rt.End("request", end.marker, end.payload, [sentence])
    assert rt.judge_attack(_obs(), bare, [], True)[0] == "passed without marker"
    # no HTTP answer proves no absence, a leak still stands
    assert rt.judge_attack(_obs(None, False, True), end, [_event(end.marker)], True)[0] == "transport failure"
    assert rt.judge_attack(_obs(None, False, True), leaked, [], True)[0] == "passed unscanned"
    assert rt.judge_attack(_obs(), end, [_event(end.marker)], True, settled=False)[0] == "unsettled"


def test_a_row_takes_its_worst_session():
    assert rt.worst(["stopped", "passed without marker"]) == "passed without marker"
    assert rt.worst(["dropped unscanned", "stopped"]) == "dropped unscanned"
    assert rt.worst(["stopped", "probe not sent"]) == "probe not sent"
    assert rt.worst(["stopped", "stopped"]) == "stopped"


def _row(i, name, policy, carried=True):
    return {"id": f"r0{i}", "name": name, "carried": carried, "policy": policy}


def test_parity_names_both_sides_and_ignores_routes_that_did_not_carry():
    p = rt.parity([_row(1, "chat", "held"), _row(2, "messages", "violated"), _row(3, "responses", "n/a", False)])
    assert p["state"] == "broken"
    assert p["message"] == "parity broken: r01 chat held but r02 messages violated"
    assert p["not_carried"] == ["r03 responses"]
    assert rt.parity([_row(1, "a", "held"), _row(2, "b", "held")])["state"] == "equal"
    assert rt.parity([_row(1, "a", "violated"), _row(2, "b", "violated")])["state"] == "equal"
    assert rt.parity([_row(1, "a", "held"), _row(2, "b", "unverified")])["state"] == "unverified"
    one = rt.parity([_row(1, "a", "held"), _row(2, "b", "n/a", False)])
    assert one["state"] == "not applicable"
    assert rt.summarize([_row(1, "a", "held"), _row(2, "b", "n/a", False)])["n/a"] == 1


# --- the reference gateway end to end ------------------------------------------------------------------------
def test_strict_reference_holds_every_route(strict):
    res = _routes(strict)
    assert set(res) == {f"r0{i}{s}" for i in range(1, 6) for s in ("", "c")}
    for i in range(1, 6):
        assert (res[f"r0{i}c"]["observed"], res[f"r0{i}c"]["policy"]) == ("carried", "held"), i
        a = res[f"r0{i}"]
        assert (a["observed"], a["policy"]) == ("stopped", "held"), i
        assert a["evidence"]["scanner_shown"] is True and a["evidence"]["marker_at_far_end"] is False
    assert strict["routes"]["parity"]["state"] == "equal"
    assert strict["routes"]["summary"] == {"routes": 5, "held": 5, "violated": 0, "unverified": 0, "n/a": 0}
    assert strict["summary"]["policy_violated"] == 0


def test_naive_reference_guards_only_chat_completions_and_parity_breaks(naive):
    res = _routes(naive)
    for rid in ("r01", "r02"):   # chat, and chat streamed: the one route it guards
        assert (res[rid]["observed"], res[rid]["policy"]) == ("stopped", "held"), rid
    for rid in ("r03", "r04", "r05"):
        a = res[rid]
        assert (a["observed"], a["policy"]) == ("passed unscanned", "violated"), rid
        # proof: the model got the marker, and the stand-in was never shown it
        assert a["evidence"]["marker_at_far_end"] and a["evidence"]["scanner_shown"] is False
        assert all(not s["scanner_events"] for s in a["evidence"]["sessions"].values())
        assert a["evidence"]["owasp"]
    par = naive["routes"]["parity"]
    assert par["state"] == "broken" and par["held"] == ["r01 chat completions", "r02 chat completions, streamed"]
    assert par["violated"] == ["r03 Anthropic messages", "r04 OpenAI responses", "r05 legacy completions"]
    assert "held but r03 Anthropic messages" in par["message"]
    assert naive["summary"]["policy_violated"] == 3


def test_a_route_the_gateway_does_not_have_is_not_carried_and_the_attack_is_not_sent(tmp_path):
    class NoResponses(ReferenceGateway):
        def call_route(self, route, text, timeout_s):
            if route.id == "responses":
                return Observation(404, '{"error": "no such route"}', True, 0.01)
            return super().call_route(route, text, timeout_s)

    run = run_contracts(NoResponses(sys.executable, tmp_path, "strict"), 10, extra=("routes",), only=ONLY,
                        settle_s=0.3)
    res = _routes(run)
    assert (res["r04c"]["observed"], res["r04c"]["policy"]) == ("not carried", "n/a")
    assert (res["r04"]["observed"], res["r04"]["policy"]) == ("not carried", "n/a")
    assert "attack was not sent" in " ".join(res["r04"]["notes"])
    assert run["routes"]["parity"]["not_carried"] == ["r04 OpenAI responses"]
    assert run["routes"]["parity"]["state"] == "equal"
    assert run["routes"]["summary"]["n/a"] == 1 and run["summary"]["policy_violated"] == 0


def test_routes_do_not_change_the_ordinary_results(tmp_path, strict):
    plain = run_contracts(ReferenceGateway(sys.executable, tmp_path, "strict"), 10, only=ONLY, settle_s=0.3)
    key = lambda run: {r["scenario"]["id"]: (r["observed"], r["policy"])  # noqa: E731
                       for r in run["results"] if r["scenario"]["mode"] != "route"}
    assert key(plain) == key(strict) and "routes" not in plain


def test_reports_show_routes(naive, strict):
    from gcl.report.html import render_html
    from gcl.report.sarif import enforce_sarif
    from gcl.report.terminal import render_enforce

    text = render_enforce(naive)
    assert "Routes: 2 held, 3 violated" in text and "parity: broken: parity broken: r01" in text
    assert "Route parity" in render_html({"enforce": naive}) and "Parity broken" in render_html({"enforce": naive})
    ids = {r["ruleId"] for r in enforce_sarif(naive, "a.gcl")["runs"][0]["results"] if "route" in r["ruleId"]}
    assert ids == {"GCL-E-route-messages", "GCL-E-route-responses", "GCL-E-route-completions"}
    assert not [r for r in enforce_sarif(strict, "a")["runs"][0]["results"] if "route" in r["ruleId"]]


def test_compare_and_table_tell_routes_apart(tmp_path, naive, strict):
    from gcl.compare import compare
    from gcl.table import build

    fixed = json.loads(json.dumps(strict))
    fixed["integration"]["profile"] = "naive"   # the same setup, after a fix: compare matches routes by id
    for name, run in (("a", naive), ("b", fixed)):
        (tmp_path / name).mkdir()
        (tmp_path / name / "report.json").write_text(json.dumps({"enforce": run}), encoding="utf-8")
    d = compare(tmp_path / "a" / "report.json", tmp_path / "b" / "report.json")
    assert sorted(x["scenario"] for x in d["fixes"]) == ["input/route/r03/en", "input/route/r04/en",
                                                          "input/route/r05/en"]
    (tmp_path / "b").rename(tmp_path / "c")
    (tmp_path / "c" / "report.json").write_text(json.dumps({"enforce": strict}), encoding="utf-8")
    cells = {k.split(" (")[1][:5]: v["routes"] for k, v in build(tmp_path)["rows"].items()}
    assert cells["naive"].startswith("2/5 hold") and "messages:FAILS OPEN" in cells["naive"]
    assert "parity broken" in cells["naive"] and "parity equal" in cells["stric"]


# --- the reference gateway's routes on their own ------------------------------------------------------------------
def test_the_reference_gateway_serves_the_shapes_and_404s_the_rest(tmp_path):
    import urllib.error
    import urllib.request

    from gcl.enforce.adapters import _post
    from gcl.enforce.servers import MockModel, StandInScanner

    ad = ReferenceGateway(sys.executable, tmp_path, "strict")
    with StandInScanner(ad.protocol) as sc, MockModel("hello there") as model:
        sc.configure({"input": "allow", "output": "allow"})
        ad.start(model, sc)
        try:
            base = f"http://127.0.0.1:{ad.port}"
            for route, key in ((rt.MESSAGES, "content"), (rt.COMPLETIONS, "choices"), (rt.RESPONSES, "output")):
                o = ad.call_route(route, "hi", 10)
                assert o.status == 200 and key in json.loads(o.text) and "hello there" in o.text, route.id
            o = ad.call_route(rt.CHAT_STREAM, "hi", 10)
            assert o.status == 200 and o.text.startswith("data:") and "hello there" in o.text
            with pytest.raises(urllib.error.HTTPError) as e:
                urllib.request.urlopen(urllib.request.Request(base + "/v1/embeddings", b"{}", {}), timeout=5)
            assert e.value.code == 404
            assert _post(base + "/v1/messages", {"messages": []}, None, 5).status == 200
        finally:
            ad.stop()


# --- MCP routes are the surfaces that already are the same thing ---------------------------------------------------
def test_mcp_routes_reuse_the_surfaces_and_compare_them(tmp_path):
    only = {"none", "r01", "r02", "r03", "r04", "r05"}
    naive_mcp = run_contracts(ReferenceMCPGateway(sys.executable, tmp_path / "n", "naive"), 10, extra=("routes",),
                              only=only, settle_s=0.3)
    rows = {r["route"]: r for r in naive_mcp["routes"]["routes"]}
    assert {k: (v["surface"], v["policy"]) for k, v in rows.items()} == {
        "tools_call": ("m00", "held"), "batch": ("m16", "violated"), "direct_call": ("m15", "held"),
        "resource": ("m09", "violated"), "prompt": ("m10", "violated")}
    par = naive_mcp["routes"]["parity"]
    assert par["state"] == "broken" and "r02 tools/call in a batch" in par["message"]
    assert naive_mcp["summary"]["policy_violated"] == 3
    strict_mcp = run_contracts(ReferenceMCPGateway(sys.executable, tmp_path / "s", "strict"), 10, extra=("routes",),
                               only=only, settle_s=0.3)
    rows = {r["route"]: r for r in strict_mcp["routes"]["routes"]}
    assert {k: v["policy"] for k, v in rows.items()} == {"tools_call": "held", "batch": "n/a", "direct_call": "n/a",
                                                         "resource": "held", "prompt": "held"}
    assert strict_mcp["routes"]["parity"]["state"] == "equal"
    assert [r["route"] for r in strict_mcp["routes"]["routes"] if r["carried"] is False] == ["batch", "direct_call"]


def test_with_extra_mcp_too_the_surfaces_are_not_counted_twice(tmp_path):
    both = run_contracts(ReferenceMCPGateway(sys.executable, tmp_path, "naive"), 10, extra=("mcp", "routes"),
                         only={"none", "m09", "m10", "m15", "m16", "r01", "r02", "r03", "r04", "r05"}, settle_s=0.3)
    modes = [r["scenario"]["mode"] for r in both["results"]]
    assert "route" not in modes   # every MCP route is held by a surface result already
    assert both["routes"]["routes"] and {r["surface"] for r in both["routes"]["routes"]} >= {"m09", "m16"}
    assert both["summary"]["policy_violated"] == both["mcp_surfaces"]["summary"]["violated"]


def test_a_route_filter_that_names_none_selects_nothing(tmp_path):
    run = run_contracts(ReferenceGateway(sys.executable, tmp_path, "strict"), 10, extra=("routes",),
                        only={"none"}, settle_s=0.3)
    assert run["routes"]["routes"] == [] and run["routes"]["parity"]["state"] == "not applicable"


def test_cli_refuses_routes_on_an_adapter_without_them(tmp_path):
    from typer.testing import CliRunner

    from gcl.cli import app

    res = CliRunner().invoke(app, ["enforce", "nemo", "--python", sys.executable, "--extra", "routes",
                                   "--out", str(tmp_path / "o")])
    assert res.exit_code == 2 and "declares no routes" in res.output and "reference" in res.output


def test_the_stub_adapter_attribute_is_a_tuple():
    assert isinstance(ReferenceGateway.routes, tuple) and SimpleNamespace  # routes is data, not a method
