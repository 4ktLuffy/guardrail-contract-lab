"""The mock MCP server places a payload in each surface m01..m18; gcl's raw MCP client
sees it over HTTP directly and over the stdio bridge. mcp_surface=None is the old server."""
import json
import sys
from pathlib import Path

import pytest

from gcl.enforce import mcp_client as mc
from gcl.enforce.servers import MockModel

BRIDGE = str(Path(mc.__file__).parent / "drivers" / "stdio_mcp_server.py")
PAY = "GCL-A-t1-r1 payload"
CALL = {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "gcl_probe", "arguments": {"note": "hello"}}}
LIST = {"jsonrpc": "2.0", "id": 5, "method": "tools/list"}


def run(m, transport, steps):
    if transport == "http":
        return mc.http_session(m.base + "/mcp", None, steps, 10)
    return mc.stdio_session([sys.executable, BRIDGE, "--mock", m.base], None, steps, 10)


def dumps(x):
    return json.dumps(x, ensure_ascii=False)


@pytest.fixture(scope="module")
def mock():
    with MockModel("scripted GCL-R") as m:
        yield m


@pytest.fixture(params=["http", "stdio"])
def transport(request):
    return request.param


def surf(mock, transport, s, steps, payload=PAY):
    mock.set_mcp_surface(s, payload)
    try:
        return run(mock, transport, steps)
    finally:
        mock.set_mcp_surface(None)


def test_none_surface_is_the_plain_server(mock, transport):
    ex = run(mock, transport, [LIST, CALL])
    assert ex.finished, ex.error
    assert ex.response_to(HANDSHAKE)["result"]["capabilities"] == {"tools": {}}
    tool = ex.response_to(5)["result"]["tools"][0]
    assert tool == {"name": "gcl_probe", "description": "Record a note.", "inputSchema": {
        "type": "object", "properties": {"note": {"type": "string"}}, "required": ["note"]}}
    assert ex.response_to(7)["result"] == {"content": [{"type": "text", "text": "scripted GCL-R"}], "isError": False}
    assert all(e["via"] != "sse" for e in ex.log)


HANDSHAKE = mc.HANDSHAKE_ID


@pytest.mark.parametrize("s,where", [
    ("m01", lambda r: r["content"][1]["text"]),
    ("m02", lambda r: r["structuredContent"]["note"]),
    ("m03", lambda r: r["content"][1]["resource"]["text"]),
    ("m04", lambda r: r["content"][0]["text"]),
    ("m13", lambda r: r["content"][0]["text"] + PAY),  # the baseline reply, only delivered as SSE
])
def test_tool_result_surfaces(mock, transport, s, where):
    ex = surf(mock, transport, s, [CALL])
    assert ex.finished, ex.error
    r = ex.response_to(7)["result"]
    if s == "m13":
        assert r["content"][0]["text"] == "scripted GCL-R"
    else:
        assert PAY in where(r)
    if transport == "http":
        assert any(e["via"] == "sse" for e in ex.log) == (s == "m13")
    if s == "m04":
        assert r["isError"] is True
    if s == "m02":
        tl = surf(mock, transport, s, [LIST]).response_to(5)["result"]["tools"][0]
        assert "outputSchema" in tl


def test_m05_error_message(mock, transport):
    ex = surf(mock, transport, "m05", [CALL])
    assert ex.response_to(7)["error"]["message"] == PAY


def test_m06_m07_tools_list(mock, transport):
    t = surf(mock, transport, "m06", [LIST]).response_to(5)["result"]["tools"][0]
    assert PAY in t["description"]
    t = surf(mock, transport, "m07", [LIST]).response_to(5)["result"]["tools"][0]
    assert t["inputSchema"]["properties"]["note"]["description"] == PAY and t["description"] == "Record a note."


def test_m08_rug_pull(mock, transport):
    l2 = dict(LIST, id=6)
    ex = surf(mock, transport, "m08", [LIST, CALL, l2])
    assert PAY not in dumps(ex.response_to(5))
    assert PAY in dumps(ex.response_to(6))
    assert any(isinstance(m, dict) and m.get("method") == "notifications/tools/list_changed" for m in ex.received())


def test_m09_m10_resources_prompts(mock, transport):
    ex = surf(mock, transport, "m09", [{"jsonrpc": "2.0", "id": 1, "method": "resources/list"},
                                       {"jsonrpc": "2.0", "id": 2, "method": "resources/read",
                                        "params": {"uri": "gcl://note"}}])
    assert ex.response_to(1)["result"]["resources"]
    assert ex.response_to(2)["result"]["contents"][0]["text"] == PAY
    ex = surf(mock, transport, "m10", [{"jsonrpc": "2.0", "id": 1, "method": "prompts/list"},
                                       {"jsonrpc": "2.0", "id": 2, "method": "prompts/get",
                                        "params": {"name": "gcl_prompt"}}])
    assert ex.response_to(1)["result"]["prompts"]
    assert ex.response_to(2)["result"]["messages"][0]["content"]["text"] == PAY


def test_m11_log_notification_before_result(mock, transport):
    ex = surf(mock, transport, "m11", [CALL])
    rec = ex.received()
    i = next(k for k, m in enumerate(rec) if m.get("method") == "notifications/message")
    assert rec[i]["params"]["data"] == PAY and rec[i]["params"]["level"] == "info"
    assert rec.index(ex.response_to(7)) > i


def test_m12_sampling_request_answered_in_stream(mock, transport):
    n = len(mock.mcp_received)
    ex = surf(mock, transport, "m12", [CALL])
    assert ex.finished, ex.error
    req = next(m for m in ex.received() if m.get("method") == "sampling/createMessage")
    assert req["params"]["messages"][0]["content"]["text"] == PAY
    got = [e["msg"] for e in mock.mcp_received[n:]]
    ans = next(m for m in got if m.get("method") is None and m.get("id") == req["id"])
    assert ans["result"]["role"] == "assistant"
    assert ex.response_to(7)["result"]["content"][0]["text"] == "scripted GCL-R"


def test_sse_surface_without_accept_falls_back(mock):
    mock.set_mcp_surface("m11", PAY)
    try:
        ex = mc.http_session(mock.base + "/mcp", {"Accept": "application/json"}, [CALL], 10)
    finally:
        mock.set_mcp_surface(None)
    assert ex.response_to(7)["result"]["content"]
    assert all(e["via"] != "sse" for e in ex.log)
    assert mock.mcp_undelivered and mock.mcp_undelivered[-1]["surface"] == "m11"


def test_m14_nested_argument_reaches_server(mock, transport):
    n = len(mock.mcp_received)
    call = dict(CALL, params={"name": "gcl_probe", "arguments": {"note": "ok", "meta": {"tags": [PAY]}}})
    ex = surf(mock, transport, "m14", [LIST, call])
    assert "meta" in ex.response_to(5)["result"]["tools"][0]["inputSchema"]["properties"]
    assert any(PAY in dumps(e["msg"]) for e in mock.mcp_received[n:])
    assert PAY in mock.tool_events[-1]["body"]


def test_m15_hidden_tool(mock, transport):
    call = dict(CALL, params={"name": "gcl_hidden", "arguments": {"note": PAY}})
    ex = surf(mock, transport, "m15", [LIST, call])
    assert [t["name"] for t in ex.response_to(5)["result"]["tools"]] == ["gcl_probe"]
    assert "result" in ex.response_to(7) and PAY in mock.tool_events[-1]["body"]
    # without the surface the same call is refused, as before
    ex = run(mock, transport, [call])
    assert "error" in ex.response_to(7)


def test_m16_batch(mock, transport):
    n = len(mock.mcp_received)
    ex = surf(mock, transport, "m16", [[LIST, CALL]])
    assert ex.response_to(5)["result"]["tools"] and ex.response_to(7)["result"]["content"]
    got = [e["msg"] for e in mock.mcp_received[n:]]
    assert any(m.get("method") == "tools/call" for m in got) and any(m.get("method") == "tools/list" for m in got)
    assert any(e["msg"] == [LIST, CALL] or isinstance(e["msg"], list) for e in ex.log if e["dir"] == "sent")


def test_received_records_session_and_transport(mock, transport):
    n = len(mock.mcp_received)
    run(mock, transport, [CALL])
    rec = mock.mcp_received[n:]
    assert {r["transport"] for r in rec} == {transport}
    assert all(r["session"] for r in rec[1:])


def test_m17_instructions_in_the_initialize_result(mock, transport):
    ex = surf(mock, transport, "m17", [LIST])
    assert ex.finished, ex.error
    assert ex.response_to(HANDSHAKE)["result"]["instructions"] == PAY
    assert "instructions" not in run(mock, transport, [LIST]).response_to(HANDSHAKE)["result"]


def test_m18_tool_title(mock, transport):
    t = surf(mock, transport, "m18", [LIST]).response_to(5)["result"]["tools"][0]
    assert t["title"] == PAY and t["description"] == "Record a note."
    assert "title" not in run(mock, transport, [LIST]).response_to(5)["result"]["tools"][0]


# --- m19..m34: the places the first eighteen surfaces left out -----------------------------------------
def _call(rid=7, **params):
    return {"jsonrpc": "2.0", "id": rid, "method": "tools/call",
            "params": {"name": "gcl_probe", "arguments": {"note": "hello"}, **params}}


def _sent_to_server(mock, n):
    return dumps([e["msg"] for e in mock.mcp_received[n:]])


def test_m19_m20_completion(mock, transport):
    req = {"jsonrpc": "2.0", "id": 5, "method": "completion/complete", "params": {
        "ref": {"type": "ref/prompt", "name": "gcl_prompt"}, "argument": {"name": "note", "value": PAY}}}
    n = len(mock.mcp_received)
    ex = surf(mock, transport, "m19", [req])
    assert ex.finished, ex.error
    assert PAY in _sent_to_server(mock, n)
    assert ex.response_to(HANDSHAKE)["result"]["capabilities"]["completions"] == {}
    assert PAY not in dumps(ex.response_to(5))
    assert ex.response_to(5)["result"]["completion"]["values"] == ["note-1"]
    ex = surf(mock, transport, "m20", [req])
    assert ex.response_to(5)["result"]["completion"]["values"] == [PAY]


def test_m21_m22_resource_templates(mock, transport):
    req = {"jsonrpc": "2.0", "id": 5, "method": "resources/templates/list"}
    t = surf(mock, transport, "m21", [req]).response_to(5)["result"]["resourceTemplates"][0]
    assert t["description"] == PAY and "{id}" in t["uriTemplate"]
    t = surf(mock, transport, "m22", [req]).response_to(5)["result"]["resourceTemplates"][0]
    assert PAY in t["uriTemplate"] and t["description"] == "A resource template."


def test_m23_m31_m33_tool_result_places(mock, transport):
    r = surf(mock, transport, "m23", [_call()]).response_to(7)["result"]
    link = r["content"][1]
    assert link["type"] == "resource_link" and link["description"] == PAY and link["uri"]
    assert surf(mock, transport, "m31", [_call()]).response_to(7)["result"]["_meta"] == {"gcl/note": PAY}
    err = surf(mock, transport, "m33", [_call()]).response_to(7)["error"]
    assert err["data"] == PAY and err["message"] != PAY and isinstance(err["code"], int)


def test_m24_m25_tool_fields(mock, transport):
    t = surf(mock, transport, "m24", [LIST]).response_to(5)["result"]["tools"][0]
    assert t["outputSchema"]["properties"]["note"]["description"] == PAY and t["description"] == "Record a note."
    t = surf(mock, transport, "m25", [LIST]).response_to(5)["result"]["tools"][0]
    assert t["annotations"]["title"] == PAY and t["annotations"]["readOnlyHint"] is False


def test_m26_m27_m34_elicitation_requests_are_answered_in_the_stream(mock, transport):
    schema = lambda p: p["requestedSchema"]["properties"]["note"]["description"]  # noqa: E731
    for sid, where in (("m26", lambda p: p["message"]), ("m27", schema), ("m34", lambda p: p["url"])):
        n = len(mock.mcp_received)
        ex = surf(mock, transport, sid, [_call()])
        assert ex.finished, (sid, ex.error)
        req = next(m for m in ex.received() if m.get("method") == "elicitation/create")
        assert PAY in where(req["params"]), sid
        assert (req["params"].get("mode") == "url") == (sid == "m34")
        ans = next(e["msg"] for e in mock.mcp_received[n:]
                   if e["msg"].get("id") == req["id"] and "method" not in e["msg"])
        assert ans["result"] == {"action": "decline"}


def test_m28_m30_the_clients_answers_carry_the_payload_to_the_server(mock, transport):
    n = len(mock.mcp_received)
    accept = mc.Answers({"elicitation/create": {"action": "accept", "content": {"note": PAY}}})
    ex = surf(mock, transport, "m28", [accept, _call()])
    assert ex.finished, ex.error
    ans = [e["msg"] for e in mock.mcp_received[n:] if "method" not in e["msg"] and e["msg"].get("id")]
    assert ans[0]["result"]["content"] == {"note": PAY}
    assert all(not isinstance(e["msg"], mc.Answers) for e in ex.log if e["dir"] == "sent")   # Answers sends nothing
    n = len(mock.mcp_received)
    roots = mc.Answers({"roots/list": {"roots": [{"uri": "file:///x", "name": PAY}]}})
    ex = surf(mock, transport, "m30", [roots, _call()])
    assert any(m.get("method") == "roots/list" for m in ex.received())
    ans = [e["msg"] for e in mock.mcp_received[n:] if "method" not in e["msg"] and e["msg"].get("id")]
    assert ans[0]["result"]["roots"][0]["name"] == PAY


def test_m29_progress_message_only_for_a_request_with_a_token(mock, transport):
    ex = surf(mock, transport, "m29", [_call(_meta={"progressToken": "tok"})])
    note = next(m for m in ex.received() if m.get("method") == "notifications/progress")
    assert note["params"] == {"progressToken": "tok", "progress": 1, "total": 1, "message": PAY}
    ex = surf(mock, transport, "m29", [_call()])
    assert not any(m.get("method") == "notifications/progress" for m in ex.received())


def test_m32_request_meta_reaches_the_server(mock, transport):
    n = len(mock.mcp_received)
    surf(mock, transport, "m32", [_call(_meta={"gcl/note": PAY})])
    assert PAY in _sent_to_server(mock, n)


def test_resource_template_lists_are_paged_too(mock):
    mock.set_mcp_paging(1, 2)
    try:
        req = {"jsonrpc": "2.0", "id": 5, "method": "resources/templates/list"}
        ex = mc.http_session(mock.base + "/mcp", None, [req], 10)
    finally:
        mock.set_mcp_paging()
    got = [t["name"] for rid in (5, "5.1", "5.2") for t in ex.response_to(rid)["result"]["resourceTemplates"]]
    assert got == ["decoy-0", "decoy-1", "note-template"]
