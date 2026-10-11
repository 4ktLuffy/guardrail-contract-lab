"""The two localhost servers every enforcement scenario runs against.

MockModel — an OpenAI-compatible chat-completions endpoint with a scripted reply. It
records every request it receives: that record is the *provider boundary*. If a blocked
prompt shows up here, the guardrail did not stop it, whatever the client was told.

StandInScanner — answers the integration's own scanner protocol with a scripted verdict
per stage (input or output), or fails in a chosen way. It records every request too, so a
scenario can prove the scanner was actually consulted.
"""

from __future__ import annotations

import json
import re
import select
import socket
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable


class _IPv6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6


class _Server:
    """A ThreadingHTTPServer on a free localhost port, run in a daemon thread."""

    handler_factory: Callable

    host = "127.0.0.1"

    def __enter__(self):
        self._stop = threading.Event()
        cls = _IPv6Server if ":" in self.host else ThreadingHTTPServer
        self._srv = cls((self.host, 0), self.handler_factory())
        self._srv.daemon_threads = True
        self.port = self._srv.server_address[1]
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._srv.shutdown()
        self._srv.server_close()

    @property
    def base(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{host}:{self.port}"


class MockModel(_Server):
    """OpenAI-compatible /v1/chat/completions with a fixed reply (streamed or not)."""

    def __init__(self, reply: str, model: str = "gcl-mock", judge: StandInScanner | None = None,
                 host: str = "127.0.0.1"):
        self.reply, self.model, self.host = reply, model, host
        self.judge = judge  # requests for judge.protocol.judge_model are the guard's, not the model's
        # Tool mode: when a request offers tools and carries no tool result yet, answer with
        # a call to the first tool, its argument the scenario's tool marker (GCL-T-<id>).
        # The tool's only effect is a POST to /gcl/tool, recorded in tool_events.
        self.tools_mode = False
        self.tool_events: list[dict] = []
        self.mcp_sessions = 0
        self.mcp_valid_sessions: set[str] = set()
        self.mcp_rejected: list[dict] = []
        self.events: list[dict] = []        # append-only: {"t", "body", "reply"}
        self.unexpected: list[str] = []
        self.inflight = 0
        self._lock = threading.Lock()

    @property
    def requests(self) -> list[dict]:
        return [e["body"] for e in self.events]

    def last_activity(self) -> float:
        """When the model or the probe tool last saw a request."""
        return max([e["t"] for e in self.events] + [e["t"] for e in self.tool_events] + [0.0])

    @property
    def openai_base(self) -> str:
        return f"{self.base}/v1"

    @property
    def tool_url(self) -> str:
        return f"{self.base}/gcl/tool"

    def received_text(self) -> str:
        """Everything the model was sent, as one string (debugging aid)."""
        return json.dumps(self.requests, ensure_ascii=False)

    def reset(self, reply: str | None = None) -> None:
        """Change the scripted reply. The record is never cleared: scenarios attribute
        events by sentinel and time window, so a late call is not lost."""
        if reply is not None:
            self.reply = reply

    def handler_factory(self):
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, code: int, obj) -> None:
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _mcp(self, raw: bytes):
                """A minimal MCP server (streamable HTTP, JSON responses): one tool,
                gcl_probe. A tools/call is recorded as a provider event (its arguments
                are what reached the server) and answered with the scripted reply."""
                try:
                    msg = json.loads(raw or b"{}")
                except ValueError:
                    self._json(400, {"error": "bad json"})
                    return
                method, mid = msg.get("method"), msg.get("id")
                if mid is None:  # a notification
                    self.send_response(202)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                sid_in = self.headers.get("Mcp-Session-Id")
                stdio = self.headers.get("X-GCL-Transport") == "stdio"  # the stdio bridge has no HTTP session
                if method == "initialize":
                    # A fresh session per client: proxies key their state on it, and a
                    # shared id would merge scenarios into one conversation.
                    outer.mcp_sessions += 1
                    self._mcp_session = f"gcl-mcp-{outer.mcp_sessions}"
                    outer.mcp_valid_sessions.add(self._mcp_session)
                    result = {"protocolVersion": (msg.get("params") or {}).get("protocolVersion", "2025-03-26"),
                              "capabilities": {"tools": {}}, "serverInfo": {"name": "gcl-mock", "version": "1"}}
                elif method == "tools/list":
                    result = {"tools": [{"name": "gcl_probe", "description": "Record a note.",
                                         "inputSchema": {"type": "object", "properties": {"note": {"type": "string"}},
                                                         "required": ["note"]}}]}
                elif method == "tools/call":
                    params = msg.get("params") or {}
                    ok_session = stdio or sid_in in outer.mcp_valid_sessions
                    ok_tool = params.get("name") == "gcl_probe" and isinstance(params.get("arguments"), dict)
                    if not (ok_session and ok_tool):
                        # Not executed: recorded apart from provider and tool events.
                        outer.mcp_rejected.append({"t": time.monotonic(), "session": sid_in, "params": params})
                        b = json.dumps({"jsonrpc": "2.0", "id": mid, "error": {
                            "code": -32602, "message": "unknown session or tool"}}).encode()
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(b)))
                        self.end_headers()
                        self.wfile.write(b)
                        return
                    meta = {"session": sid_in or "stdio", "rpc_id": mid}
                    outer.events.append({"t": time.monotonic(), "body": params, "reply": outer.reply, **meta})
                    outer.tool_events.append({"t": time.monotonic(), "body": json.dumps(params, ensure_ascii=False),
                                              **meta})
                    result = {"content": [{"type": "text", "text": outer.reply}], "isError": False}
                else:
                    result = {}
                b = json.dumps({"jsonrpc": "2.0", "id": mid, "result": result}, ensure_ascii=False).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                sid = getattr(self, "_mcp_session", None) or self.headers.get("Mcp-Session-Id") or "gcl-mcp-0"
                self.send_header("Mcp-Session-Id", sid)
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def do_GET(self):
                if self.path.rstrip("/").endswith("/models"):
                    self._json(200, {"object": "list", "data": [{"id": outer.model, "object": "model"}]})
                else:
                    outer.unexpected.append(f"GET {self.path}")
                    self._json(404, {"error": "not found"})

            def do_POST(self):
                with outer._lock:
                    outer.inflight += 1
                try:
                    self._post()
                finally:
                    with outer._lock:
                        outer.inflight -= 1

            def _post(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n)
                if self.path.rstrip("/").endswith("/mcp"):
                    self._mcp(raw)
                    return
                if self.path.rstrip("/").endswith("/gcl/tool"):
                    outer.tool_events.append({"t": time.monotonic(), "body": raw.decode("utf-8", "replace")})
                    self._json(200, {"ok": True})
                    return
                if not self.path.rstrip("/").endswith("/chat/completions"):
                    outer.unexpected.append(f"POST {self.path}")
                    self._json(404, {"error": "not found"})
                    return
                try:
                    body = json.loads(raw or b"{}")
                except ValueError:
                    body = {"_unparseable": raw.decode("utf-8", "replace")}
                j = outer.judge
                jm = j.protocol.judge_model if j is not None else None
                name = body.get("model") if isinstance(body, dict) else None
                if j is not None and name in (jm, f"{jm}-input", f"{jm}-output"):
                    # A per-stage judge name fixes the stage; the bare name leaves it to the body.
                    stage = name.rsplit("-", 1)[1] if name != jm else None
                    with outer._lock:
                        outer.inflight -= 1  # the scanner counts this one
                    try:
                        j.serve(self, stage, raw, by_name=stage is not None)
                    finally:
                        with outer._lock:
                            outer.inflight += 1
                    return
                outer.events.append({"t": time.monotonic(), "body": body, "reply": outer.reply})
                created = int(time.time())
                msgs = body.get("messages") or []
                if (outer.tools_mode and body.get("tools") and not body.get("stream")
                        and not any(isinstance(m, dict) and m.get("role") == "tool" for m in msgs)):
                    # The tool marker carries the scenario's full tag (id and run id), so a tool
                    # run can never be charged to the same id in another run.
                    ids = re.findall(r"GCL-U-([io]\d{2}(?:-[0-9a-f]{6})?)\b", json.dumps(msgs, ensure_ascii=False))
                    fn = (body["tools"][0].get("function") or {}).get("name", "gcl_probe")
                    sid = ids[-1] if ids else "x"
                    call = {"id": f"call_gcl_{sid}", "type": "function",
                            "function": {"name": fn, "arguments": json.dumps({"note": f"GCL-T-{sid}"})}}
                    self._json(200, {"id": "gcl-1", "object": "chat.completion", "created": created,
                                     "model": outer.model,
                                     "choices": [{"index": 0, "message": {"role": "assistant", "content": None,
                                                                          "tool_calls": [call]},
                                                  "finish_reason": "tool_calls"}],
                                     "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})
                    return
                if body.get("stream"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    words = outer.reply.split(" ")
                    for k, w in enumerate(words):
                        chunk = {"id": "gcl-1", "object": "chat.completion.chunk", "created": created,
                                 "model": outer.model,
                                 "choices": [{"index": 0, "delta": {"content": w + (" " if k < len(words) - 1 else "")},
                                              "finish_reason": None}]}
                        self.wfile.write(f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n".encode())
                    end = {"id": "gcl-1", "object": "chat.completion.chunk", "created": created, "model": outer.model,
                           "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}
                    self.wfile.write(f"data: {json.dumps(end)}\n\ndata: [DONE]\n\n".encode())
                    return
                self._json(200, {
                    "id": "gcl-1", "object": "chat.completion", "created": created, "model": outer.model,
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": outer.reply},
                                 "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                })

        return H


@dataclass
class Protocol:
    """How one integration talks to its scanner."""

    name: str
    verdicts: dict                      # "allow" | "block" | "modify" -> response builder
    # Which stage a request says it is for; None if it names no stage this protocol
    # defines (recorded, answered 400, never counted as a consultation).
    stage_of: Callable[[dict], str | None] = lambda body: "input"
    path: str = ""                      # path suffix the integration must POST to ("" = any)
    malformed: bytes = b"<html>upstream error</html>"
    wrong_schema: dict = field(default_factory=lambda: {"status": "ok"})
    # LLM-as-judge guards: the verdict is the *content* of a chat completion. When set,
    # every answer that has a body (verdicts and content faults) is wrapped by it; an
    # HTTP-level "error" stays a 500.
    envelope: Callable[[str], dict] | None = None
    # The guard calls the same endpoint as the model (routed by model name), so the
    # stage comes from the request body and "refused" cannot be staged for it alone.
    shared_endpoint: bool = False
    judge_model: str = "gcl-judge"
    # One guard client serves both stages (one URL): adapters point it at the input
    # listener, the stage comes from the body, and "refused" closes that one listener.
    single_listener: bool = False
    # Stage = the listener the request arrived on, whatever the body says (protocols whose
    # body carries no stage, with one URL per stage).
    trust_listener: bool = False
    # Several valid routes, or templated ones ("/guards/<name>/validate"); checked exactly
    # (query string and trailing slash ignored). Empty: `path` (suffix) applies.
    routes: tuple = ()
    # The text the guard was asked to check, from a request body (for ECHO_TEXT and for
    # binding consultation evidence to that text). None: the whole body.
    scanned: Callable[[dict], str | None] | None = None
    # Static answers to GET requests (a policy source, an identity endpoint): route
    # template -> JSON body. Recorded as events, never counted as consultations.
    get_routes: dict = field(default_factory=dict)
    # Static answers to other POST routes the integration calls (trace upload, preload):
    # route template -> JSON body. Recorded, never counted as consultations.
    static_posts: dict = field(default_factory=dict)
    # Protocol-specific faults: mode name -> full response body (sent with HTTP 200).
    extra_faults: dict = field(default_factory=dict)
    # Overrides for built-in content faults when verdicts are plain text, not JSON:
    # mode ("unknown_verdict", "verdict_type") -> the text to answer with.
    variants: dict = field(default_factory=dict)
    # How the answers were built, so a result that rests on their exact shape can say so:
    # "integration" (the integration under test defines the protocol: an LLM judge's
    # output format, its own webhook or guardrail API), "vendor_schema" (a third party's
    # published API reference), "recorded" (real replies captured from the vendor),
    # "client_code" (rebuilt by reading the integration's client of a third-party API),
    # "guessed".
    provenance: str = "guessed"
    provenance_source: str = ""
    # Verdicts ("allow", "block", "modify") answered with recorded real replies instead,
    # and the request shape they were captured for (e.g. {"messages": 1}): a scenario
    # whose request does not positively match it gets a guessed answer.
    recorded_modes: tuple = ()
    recorded_shape: dict = field(default_factory=dict)


# Modes a stage can be put in. Verdict modes answer correctly; fault modes misbehave.
VERDICTS = ("allow", "block", "modify")
# Faults of the *policy source* (where an integration fetches its rules), for protocols
# with GET routes: the policy is not found, or the source errors.
POLICY_FAULTS = ("policy_missing", "policy_error")
FAULTS = ("error", "timeout", "malformed", "empty", "wrong_schema", "unknown_verdict", "verdict_type",
          "refused")
# Planned after every other scenario (so earlier scenario ids stay stable), and only where
# the protocol's block answer is JSON with a verdict field to null.
LATE_FAULTS = ("null_verdict",)


def null_expressible(proto: Protocol) -> bool:
    try:
        fn = proto.verdicts["block"]
        block = fn({}, "", "input") if fn.__code__.co_argcount >= 3 else fn({}, "")
        fn = proto.verdicts["allow"]
        allow = fn({}, "", "input") if fn.__code__.co_argcount >= 3 else fn({}, "")
    except Exception:
        return False
    return _fault_on_operative(block, allow, "null_verdict")[1]


class StandInScanner:
    """A scanner answering `protocol` with modes[stage] (default "allow").

    One listener per stage, each on a port fixed for the whole run, so the system under
    test is configured once (adapters point the input hook at `base_for("input")` and the
    output hook at `base_for("output")`) and a stage's "refused" can be tested without
    touching the other. `configure()` changes behaviour between scenarios; "refused"
    closes that stage's listening socket and the next configure reopens it.

    Every request is appended to `events` with the listener it arrived on, what the body
    claimed, which mode answered and when. Nothing is ever cleared.
    """

    STAGES = ("input", "output")

    def __init__(self, protocol: Protocol):
        self.protocol = protocol
        self.modes: dict[str, str] = {}
        self.modify_text = ""
        self.events: list[dict] = []
        self.inflight = 0
        self.stalled = 0
        self.latency_s = 0.0  # delay before every answer: a detector that takes time to decide
        self.policy_fault: str | None = None  # applies to GET policy routes only
        self.by_sid: dict[str, tuple[dict, str]] = {}
        self._lock = threading.Lock()
        self._release = threading.Event()
        self._srv: dict[str, ThreadingHTTPServer | None] = {st: None for st in self.STAGES}
        self.ports: dict[str, int] = {st: 0 for st in self.STAGES}

    def __enter__(self):
        for st in self.STAGES:
            self._open(st)
        return self

    def __exit__(self, *exc):
        self._release.set()  # let any stalled "timeout" handler go
        for st in self.STAGES:
            self._close(st)

    def _open(self, stage: str) -> None:
        srv = ThreadingHTTPServer(("127.0.0.1", self.ports[stage]), self.handler_factory(stage))
        srv.daemon_threads = True
        self.ports[stage] = srv.server_address[1]
        self._srv[stage] = srv
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    def _close(self, stage: str) -> None:
        srv = self._srv[stage]
        if srv is not None:
            srv.shutdown()
            srv.server_close()
            self._srv[stage] = None

    @property
    def port(self) -> int:
        return self.ports["input"]

    @property
    def base(self) -> str:
        return self.base_for("input")

    def base_for(self, stage: str) -> str:
        return f"http://127.0.0.1:{self.ports[stage]}"

    def configure(self, modes: dict[str, str], modify_text: str = "", sid: str | None = None) -> None:
        """Set behaviour for the next scenario. With `sid`, the behaviour is also kept for
        that scenario: a late retry carrying its markers is answered the same way after
        the run has moved on, instead of with the newer scenario's behaviour."""
        # A policy-source fault is not a check verdict: the check endpoint stays healthy
        # (answering allow) and only the policy routes misbehave.
        self.policy_fault = next((m for m in modes.values() if m in POLICY_FAULTS), None)
        modes = {k: ("allow" if v in POLICY_FAULTS else v) for k, v in modes.items()}
        self.modes, self.modify_text = dict(modes), modify_text
        if sid is not None:
            self.by_sid[sid] = (dict(modes), modify_text)
        self.release_stalled()
        any_refused = any(m == "refused" for m in self.modes.values())
        for st in self.STAGES:
            refused = self.modes.get(st) == "refused"
            if self.protocol.single_listener and st == "input":
                refused = any_refused
            if refused and self._srv[st] is not None:
                self._close(st)
            elif not refused and self._srv[st] is None:
                self._open(st)

    def release_stalled(self) -> None:
        """Free handlers held by a "timeout" mode: they close without an answer."""
        self._release.set()
        self._release = threading.Event()

    def last_activity(self) -> float:
        """When the scanner last received or finished answering a request."""
        return max((max(e["t"], e.get("t_done") or 0.0) for e in self.events), default=0.0)

    def consulted(self, stage: str | None = None, sentinel: str | None = None,
                  since: float = 0.0) -> int:
        """Requests that arrived on `stage`'s listener, claimed that stage, and (if given)
        carry `sentinel` in their body."""
        n = 0
        for e in self.events:
            if e["t"] < since or not e["valid"] or (stage and e["stage"] != stage):
                continue
            if sentinel and sentinel not in e["body_text"]:
                continue
            n += 1
        return n

    def serve(self, h: BaseHTTPRequestHandler, listener: str | None, raw: bytes, by_name: bool = False) -> None:
        """Answer one request on handler `h`. `listener` is the stage whose port it came
        in on, or None for a shared endpoint (the body then says which stage)."""
        with self._lock:
            self.inflight += 1
        try:
            self._serve(h, listener, raw, by_name)
        finally:
            with self._lock:
                self.inflight -= 1

    def _serve(self, h: BaseHTTPRequestHandler, listener: str | None, raw: bytes, by_name: bool = False) -> None:
        proto = self.protocol

        sent: dict = {}
        current: dict = {}  # the event being answered, once recorded

        def send(code: int, body: bytes, ctype: str = "application/json"):
            if "ev" in current:  # answering is done once the bytes go out, not after
                current["ev"]["t_done"] = current["ev"]["t_sent"] = time.monotonic()
            # A receipt of what reached the integration, not what we meant to send: a
            # write lands in the kernel buffer even after the peer hung up, so check for
            # a closed peer first; a write error means it was not delivered either.
            gone = _peer_gone(h)
            try:
                h.send_response(code)
                h.send_header("Content-Type", ctype)
                h.send_header("Content-Length", str(len(body)))
                h.end_headers()
                h.wfile.write(body)
                h.wfile.flush()
            except OSError:
                gone = True
            sent.update(delivered=not gone, status=code, bytes=len(body), t_sent=time.monotonic())

        def content(text: str, code: int = 200, ctype: str = "application/json"):
            if proto.envelope is not None:
                send(code, json.dumps(proto.envelope(text), ensure_ascii=False).encode())
            else:
                send(code, text.encode(), ctype)

        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            body = {}
        path = h.path.split("?", 1)[0].rstrip("/")
        for route, answer in proto.static_posts.items():
            if re.fullmatch(re.sub(r"<[^>/]+>", "[^/]+", route.rstrip("/")), path):
                self.events.append({"t": time.monotonic(), "stage": listener, "claimed_stage": None, "path": h.path,
                                    "valid": False, "mode": "static", "body": body, "scanned": None,
                                    "body_text": raw.decode("utf-8", "replace"), "answered": answer,
                                    "fault_expressed": True, "t_done": time.monotonic()})
                send(200, json.dumps(answer).encode())
                return
        claimed = proto.stage_of(body) if isinstance(body, dict) else None
        path_ok = _path_ok(proto, h.path)
        if listener is not None and (by_name or proto.trust_listener):
            valid, stage = path_ok, listener      # the stage is fixed by name or by port
        else:
            by_body = listener is None or proto.single_listener
            valid = path_ok and claimed in self.STAGES and (by_body or claimed == listener)
            stage = claimed if by_body else listener
        # Snapshot everything the answer depends on now: the scenario this request belongs
        # to (by its markers) if known, else the current configuration.
        text = raw.decode("utf-8", "replace")
        ids = set(re.findall(r"GCL-[UMRT]-([io]\d{2})\b", text))
        modes, modify_text = (self.by_sid[next(iter(ids))] if len(ids) == 1 and next(iter(ids)) in self.by_sid
                              else (self.modes, self.modify_text))
        mode = modes.get(stage, "allow") if valid else "rejected"
        scanned = proto.scanned(body) if (proto.scanned and isinstance(body, dict)) else None
        ev = {"t": time.monotonic(), "stage": stage, "claimed_stage": claimed,
              "path": h.path, "valid": valid, "mode": mode, "body": body, "scanned": scanned,
              "body_text": text, "answered": None, "fault_expressed": True, "t_done": None}
        self.events.append(ev)
        current["ev"] = ev
        if not valid:
            ev["answered"] = "400 (wrong path or stage)"
            send(400, b'{"error": "gcl stand-in: unexpected path or stage"}')
            ev["t_done"] = time.monotonic()
            return
        try:
            self._answer(ev, body, stage, mode, modify_text, send, content, h)
        finally:
            ev["t_done"] = time.monotonic()
            if sent:
                ev["delivery"] = dict(sent)

    def _answer(self, ev, body, stage, mode, modify_text, send, content, h=None) -> None:
        proto = self.protocol
        release = self._release
        if self.latency_s:
            time.sleep(self.latency_s)

        def verdict(name):
            fn = proto.verdicts[name]
            return fn(body, modify_text, stage) if fn.__code__.co_argcount >= 3 else fn(body, modify_text)

        if mode in VERDICTS:
            resp = verdict(mode)
            ev["answered"] = resp
            content(resp if isinstance(resp, str) else json.dumps(resp, ensure_ascii=False))
        elif mode in proto.variants:
            ev["answered"] = proto.variants[mode]
            content(proto.variants[mode])
        elif mode == "error":
            ev["answered"] = "500"
            send(500, b'{"error": "internal"}')
        elif mode == "timeout":
            ev["answered"] = "(held open, no answer)"
            t0 = time.monotonic()
            with self._lock:
                self.stalled += 1
            try:
                # Never answer while the scenario runs; note when the integration gives up
                # (its own timeout fired) or when gcl let go (the scenario was over).
                ended = "released by gcl"
                while not release.wait(0.1):
                    if time.monotonic() - t0 > 300:
                        ended = "gcl's 300 s cap"
                        break
                    if h is not None and _peer_gone(h):
                        ended = "integration gave up"
                        break
                ev["stall"] = {"ended": ended, "s": round(time.monotonic() - t0, 3)}
            finally:
                with self._lock:
                    self.stalled -= 1
        elif mode == "malformed":
            ev["answered"] = proto.malformed.decode()
            content(proto.malformed.decode(), ctype="text/html")
        elif mode == "empty":
            ev["answered"] = ""
            content("")
        elif mode == "wrong_schema":
            ev["answered"] = proto.wrong_schema
            content(json.dumps(proto.wrong_schema))
        elif mode in ("unknown_verdict", "verdict_type", "null_verdict"):
            block, allow = verdict("block"), verdict("allow")
            # Only the fields that decide the verdict — those that differ between the allow
            # and the block answer — are rewritten. If none can be, the fault was not
            # expressed and the scenario is judged unverified, not held.
            resp, changed = _fault_on_operative(block, allow, mode)
            ev["fault_expressed"] = changed
            ev["answered"] = resp
            content(resp if isinstance(resp, str) else json.dumps(resp))
        elif mode in proto.extra_faults:
            ev["answered"] = proto.extra_faults[mode]
            send(200, json.dumps(proto.extra_faults[mode], ensure_ascii=False).encode())
        else:
            ev["answered"] = "500 (unknown gcl mode)"
            send(500, b'{"error": "unknown gcl mode"}')

    def serve_get(self, h: BaseHTTPRequestHandler, listener: str) -> None:
        path = h.path.split("?", 1)[0].rstrip("/")
        fault = self.policy_fault
        for route, body in self.protocol.get_routes.items():
            if re.fullmatch(re.sub(r"<[^>/]+>", "[^/]+", route.rstrip("/")), path):
                if fault and "polic" in route:
                    code = 404 if fault == "policy_missing" else 500
                    b = b'{"error": "gcl stand-in: policy source fault"}'
                else:
                    b, code = json.dumps(body).encode(), 200
                break
        else:
            b, code = b'{"error": "not found"}', 404
        self.events.append({"t": time.monotonic(), "stage": listener, "claimed_stage": None, "path": h.path,
                            "valid": False, "mode": "GET", "body": {}, "scanned": None, "body_text": "",
                            "answered": code, "fault_expressed": True, "t_done": time.monotonic()})
        h.send_response(code)
        h.send_header("Content-Type", "application/json")
        h.send_header("Content-Length", str(len(b)))
        h.end_headers()
        h.wfile.write(b)

    def handler_factory(self, listener: str):
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                outer.serve(self, listener, self.rfile.read(n))

            def do_GET(self):
                outer.serve_get(self, listener)

        return H


def _peer_gone(h) -> bool:
    """Has the client of handler `h` closed its side of the connection?"""
    sock = getattr(h, "connection", None)
    if sock is None:
        return False
    try:
        readable, _, _ = select.select([sock], [], [], 0)
        return bool(readable) and sock.recv(1, socket.MSG_PEEK) == b""
    except (OSError, ValueError):
        return True


def _path_ok(proto: Protocol, path: str) -> bool:
    path = path.split("?", 1)[0].rstrip("/") or "/"
    if proto.routes:
        return any(re.fullmatch(re.sub(r"<[^>/]+>", "[^/]+", r.rstrip("/")), path) for r in proto.routes)
    return not proto.path or path.endswith(proto.path.rstrip("/"))


def _leaves(obj, prefix=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _leaves(v, (*prefix, k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _leaves(v, (*prefix, i))
    else:
        yield prefix, obj


def _get(obj, path):
    for k in path:
        try:
            obj = obj[k]
        except (KeyError, IndexError, TypeError):
            return None
    return obj


def _set(obj, path, value):
    obj = json.loads(json.dumps(obj))
    cur = obj
    for k in path[:-1]:
        cur = cur[k]
    cur[path[-1]] = value
    return obj


def _fault_on_operative(block, allow, mode: str):
    """Apply unknown_verdict / verdict_type to the operative verdict fields only: leaves
    of the block answer whose value differs from the allow answer (or that the allow
    answer lacks). Returns (answer, changed)."""
    if not isinstance(block, (dict, list)):
        return block, False
    operative = [(p, v) for p, v in _leaves(block)
                 if not isinstance(allow, (dict, list)) or _get(allow, p) != v]
    # Named verdict fields first, then booleans, then the rest (a reason string last).
    operative.sort(key=lambda pv: (not (pv[0] and pv[0][-1] in _VERDICT_KEYS), not isinstance(pv[1], bool)))
    out, changed = block, False
    for p, v in operative:
        if not p:
            continue
        if mode == "unknown_verdict":
            if isinstance(v, bool) or (isinstance(v, str) and v):
                return _set(out, p, "DENY_UNKNOWN" if isinstance(v, str) else "unknown"), True
        elif mode == "null_verdict":
            # Unknown *and* falsy: "unknown" and "DENY_UNKNOWN" are truthy or share a prefix
            # with a block word, so a parser that tests truthiness or a prefix fails safe on
            # them by accident. null does not.
            if isinstance(v, (bool, str)):
                return _set(out, p, None), True
        else:  # verdict_type: the same meaning in the wrong type
            if isinstance(v, bool):
                out, changed = _set(out, p, "true" if v else "false"), True
            elif isinstance(v, str) and v.isupper() and v.lower() != v:
                out, changed = _set(out, p, v.lower()), True
            elif isinstance(v, (int, float)) and not isinstance(v, bool):
                out, changed = _set(out, p, str(v)), True
    return out, changed


_VERDICT_KEYS = ("action", "verdict", "decision", "result", "outcome", "status", "flagged", "blocked",
                 "is_safe", "safe", "jailbreak", "violation", "violations_detected", "required_action")


def _walk(obj, fn):
    """Apply `fn(key, value) -> (changed, new)` depth-first; returns (changed, copy)."""
    if isinstance(obj, dict):
        changed, out = False, {}
        for k, v in obj.items():
            hit, nv = fn(k, v)
            if not hit:
                hit, nv = _walk(v, fn)
            changed |= hit
            out[k] = nv
        return changed, out
    if isinstance(obj, list):
        changed, out = False, []
        for v in obj:
            hit, nv = _walk(v, fn)
            changed |= hit
            out.append(nv)
        return changed, out
    return False, obj


def _type_confuse(resp):
    """The block verdict with the right meaning in the wrong type, at any depth:
    booleans as strings ("true"/"false"), upper-case verdict keywords in lower case. What
    a scanner written in another language, or a hand-rolled JSON template, sends. A
    parser that tests truthiness reads the string "false" as true."""
    def fn(key, val):
        if isinstance(val, bool):
            return True, "true" if val else "false"
        if isinstance(val, str) and key in _VERDICT_KEYS and val.isupper():
            return True, val.lower()
        return False, val
    return _walk(resp, fn)[1]


def _mangle_verdict(resp):
    """The block verdict with its verdict field (at any depth) set to a value the
    protocol does not define — what a scanner upgrade or a typo produces. A robust parser
    must not read an unknown verdict as allow. Only the first verdict field is changed."""
    done = [False]

    def fn(key, val):
        if done[0]:
            return False, val
        if key in _VERDICT_KEYS and isinstance(val, (str, bool)):
            done[0] = True
            return True, "DENY_UNKNOWN" if isinstance(val, str) else "unknown"
        return False, val
    out = _walk(resp, fn)[1]
    if done[0]:
        return out
    for key, val in out.items() if isinstance(out, dict) else ():
        if isinstance(val, bool):  # no named verdict field: the first top-level boolean
            out = dict(out)
            out[key] = "unknown"
            return out
    return out
