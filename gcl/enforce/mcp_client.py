"""A raw JSON-RPC MCP client, standard library only.

No SDK: gcl must see every byte a gateway returns, including what an SDK would swallow or
reorder (SSE events, notifications, server requests, batches, error bodies). A session is
the handshake (initialize, notifications/initialized) plus the caller's steps; each step is
a JSON-RPC message (dict) or a batch (list), ids chosen by the caller, or a callable
`step(exchange) -> message | batch | None` evaluated just before sending, so a step can use
an earlier response of the same session (a tool name read back from tools/list); None sends
nothing. The client answers
server requests with a fixed benign result (sampling/createMessage), a decline
(elicitation/create) or an empty list (roots/list), and records everything, in order, in the
Exchange. Every wait is bounded by one absolute deadline and every read by a byte cap.
"""

from __future__ import annotations

import contextlib
import http.client
import json
import os
import queue
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

_MAX_BODY = 1 << 20      # at most 1 MiB kept of any one HTTP response
_MAX_TOTAL = 4 << 20     # and 4 MiB of a whole session
_ANSWER_TEXT = "GCL client: sampling answered with a fixed benign result."
HANDSHAKE_ID = "gcl-init"


@dataclass
class Exchange:
    """Every message of one session, in order: {"dir": "sent"|"recv", "msg", "via":
    "json"|"sse"|"stdio", "status": int|None, "t"}. A non-JSON body is recorded as
    {"_raw": text}. `finished`: every step ran before the deadline and every request id the
    steps sent (inside batches too; not notifications, not gcl's own answers to server
    requests) got a proper answer; `error`: why not. `truncated`: a byte cap cut a response."""
    log: list[dict] = field(default_factory=list)
    error: str = ""
    finished: bool = False
    session_id: str | None = None
    truncated: bool = False
    refused: set = field(default_factory=set)   # ids of a batch the server refused as a whole
    # Request ids whose POST got an HTTP 4xx and no JSON-RPC message answering them (a
    # gateway that refuses with a bare status, or with a body it cannot deliver). Not a proper
    # answer, so `finished` stays False; `http_refusal` says that every missing answer was such
    # a refusal: nothing came back, and the session ended, rather than hung or broke.
    http_refused: dict = field(default_factory=dict)
    http_refusal: bool = False

    def add(self, direction: str, msg, via: str, status: int | None = None) -> None:
        self.log.append({"dir": direction, "msg": msg, "via": via, "status": status, "t": time.monotonic()})

    def received(self) -> list:
        return [e["msg"] for e in self.log if e["dir"] == "recv"]

    def sent(self) -> list:
        return [e["msg"] for e in self.log if e["dir"] == "sent"]

    def response_to(self, rid) -> dict | None:
        """The received response (result or error) for request id `rid`, if any."""
        for m in self.received():
            if isinstance(m, dict) and m.get("id") == rid and m.get("method") is None and "_raw" not in m:
                return m
        return None

    def proper(self, rid) -> bool:
        """Request `rid` got a proper answer: a JSON-RPC result or error object for it, with
        HTTP status below 400 or an error object (a 5xx page, or a result under 4xx/5xx, is not).
        A batch refused as a whole, with one error object whose id is null, answers every
        request in it."""
        if rid in self.refused:
            return True
        for e in self.log:
            m = e["msg"]
            if (e["dir"] == "recv" and isinstance(m, dict) and "_raw" not in m and m.get("id") == rid
                    and m.get("method") is None and ("result" in m or "error" in m)
                    and (e["status"] is None or e["status"] < 400 or "error" in m)):
                return True
        return False

    def conclude(self, expected: list) -> None:
        """Set `finished` from the ids the steps sent: every one needs a proper answer."""
        missing = [i for i in expected if not self.proper(i)]
        if not missing:
            self.finished = True
            return
        self.finished = False
        if all(i in self.http_refused for i in missing):
            self.http_refusal = True
            self.error = self.error or (f"refused: HTTP {self.http_refused[missing[0]]} without a JSON-RPC "
                                        f"answer to {missing}")
            return
        bad = sorted({e["status"] for e in self.log if e["dir"] == "recv" and (e["status"] or 0) >= 400})
        self.error = self.error or (f"transport failure: HTTP {bad[0]} without a JSON-RPC answer to {missing}"
                                    if bad else f"no answer to request id(s) {missing}")

    def text(self) -> str:
        """Everything received, as one string."""
        return json.dumps(self.received(), ensure_ascii=False)


def auto_answer(req: dict) -> dict:
    """The client's reply to a server request."""
    method, rid = req.get("method"), req.get("id")
    if method == "sampling/createMessage":
        result = {"role": "assistant", "content": {"type": "text", "text": _ANSWER_TEXT},
                  "model": "gcl-client", "stopReason": "endTurn"}
    elif method == "elicitation/create":
        result = {"action": "decline"}
    elif method == "roots/list":
        result = {"roots": []}
    elif method == "ping":
        result = {}
    else:
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found"}}
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def is_server_request(msg) -> bool:
    return isinstance(msg, dict) and msg.get("method") is not None and msg.get("id") is not None


def _initialize(protocol: str) -> dict:
    return {"jsonrpc": "2.0", "id": HANDSHAKE_ID, "method": "initialize", "params": {
        "protocolVersion": protocol, "clientInfo": {"name": "gcl", "version": "1"},
        "capabilities": {"sampling": {}, "elicitation": {}, "roots": {}}}}


def _resolve(step, ex: Exchange):
    """A step as the message to send: callables see the exchange so far. None: send nothing."""
    return step(ex) if callable(step) else step


def _request_ids(step) -> list:
    if step is None:
        return []
    msgs = step if isinstance(step, list) else [step]
    return [m["id"] for m in msgs if isinstance(m, dict) and m.get("method") is not None and m.get("id") is not None]


class _Http:
    """One MCP streamable-HTTP session: carries Mcp-Session-Id, reads JSON or SSE replies."""

    def __init__(self, url: str, headers: dict | None, deadline: float, ex: Exchange):
        self.url, self.base_headers, self.deadline, self.ex = url, dict(headers or {}), deadline, ex
        self.parts = urlsplit(url)
        self.total = 0
        self.protocol: str | None = None

    def _conn(self) -> http.client.HTTPConnection:
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("deadline reached")
        cls = http.client.HTTPSConnection if self.parts.scheme == "https" else http.client.HTTPConnection
        return cls(self.parts.hostname, self.parts.port, timeout=left)

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        h.update(self.base_headers)
        if self.ex.session_id:
            h["Mcp-Session-Id"] = self.ex.session_id
        if self.protocol:
            h["Mcp-Protocol-Version"] = self.protocol
        return h

    def post(self, msg, record: bool = True, answer: bool = True) -> None:
        """POST one message or batch; record the reply, answering server requests as they come."""
        if record:
            self.ex.add("sent", msg, "json")
        mark = len(self.ex.log)
        conn = self._conn()
        try:
            path = (self.parts.path or "/") + (f"?{self.parts.query}" if self.parts.query else "")
            conn.request("POST", path, json.dumps(msg, ensure_ascii=False).encode(), self._headers())
            resp = conn.getresponse()
            sid = resp.getheader("Mcp-Session-Id")
            if sid and not self.ex.session_id:
                self.ex.session_id = sid
            if "text/event-stream" in (resp.getheader("Content-Type") or ""):
                self._sse(conn, resp, answer)
            else:
                body = self._read(resp)
                self._record_body(body, resp.status)
                if 400 <= resp.status < 500:
                    answered = {e["msg"].get("id") for e in self.ex.log[mark:]
                                if e["dir"] == "recv" and isinstance(e["msg"], dict) and "_raw" not in e["msg"]}
                    for rid in _request_ids(msg):
                        if rid not in answered:
                            self.ex.http_refused[rid] = resp.status
        finally:
            conn.close()
        if isinstance(msg, list) and any(
                e["dir"] == "recv" and isinstance(e["msg"], dict) and "error" in e["msg"] and e["msg"].get("id") is None
                and e["msg"].get("method") is None for e in self.ex.log[mark:]):
            self.ex.refused.update(_request_ids(msg))

    def _room(self) -> int:
        """Bytes still allowed for the next response: the per-response cap, and what is left
        of the per-session total."""
        return max(0, min(_MAX_BODY, _MAX_TOTAL - self.total))

    def _read(self, resp) -> str:
        room = self._room()
        raw = resp.read(room + 1)
        if len(raw) > room:
            self.ex.truncated = True
            self.ex.error = self.ex.error or f"response truncated at the byte cap ({room} bytes)"
            raw = raw[:room]
        self.total += len(raw)
        return raw.decode("utf-8", "replace")

    def _record_body(self, body: str, status: int) -> None:
        if not body.strip():
            if status >= 400:  # an error status with no body is still an answer worth recording
                self.ex.add("recv", {"_raw": body}, "json", status)
            return
        try:
            obj = json.loads(body)
        except ValueError:
            self.ex.add("recv", {"_raw": body}, "json", status)
            return
        for m in obj if isinstance(obj, list) else [obj]:
            self.ex.add("recv", m, "json", status)

    def _sse(self, conn, resp, answer: bool) -> None:
        data: list[str] = []
        size = 0
        while True:
            left = self.deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("deadline reached")
            if conn.sock is not None:
                conn.sock.settimeout(left)
            try:
                raw = resp.readline(_MAX_BODY)
            except TimeoutError:
                raise
            except OSError as e:
                # A stream that dies mid-way is a failed session, not a short answer.
                self.ex.error = self.ex.error or f"transport failure: {type(e).__name__}: {e}"
                raise
            if not raw:
                break
            size += len(raw)
            self.total += len(raw)
            if size > _MAX_BODY or self.total > _MAX_TOTAL or (len(raw) >= _MAX_BODY and not raw.endswith(b"\n")):
                self.ex.truncated = True
                self.ex.error = self.ex.error or "event stream truncated at the byte cap"
                break
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if line.startswith("data:"):
                data.append(line[5:].removeprefix(" "))
            elif not line and data:
                self._event("\n".join(data), resp.status, conn, answer)
                data = []
        if data:
            self._event("\n".join(data), resp.status, conn, answer)

    def _event(self, text: str, status: int, conn, answer: bool) -> None:
        try:
            msg = json.loads(text)
        except ValueError:
            self.ex.add("recv", {"_raw": text}, "sse", status)
            return
        for m in msg if isinstance(msg, list) else [msg]:
            self.ex.add("recv", m, "sse", status)
            if answer and is_server_request(m):
                # The server holds its stream open for this answer, so it goes out on a
                # second connection while this one keeps reading.
                self.answer(m)

    def answer(self, req: dict) -> None:
        reply = auto_answer(req)
        self.ex.add("sent", reply, "json")
        c = self._conn()
        try:
            path = (self.parts.path or "/") + (f"?{self.parts.query}" if self.parts.query else "")
            c.request("POST", path, json.dumps(reply).encode(), self._headers())
            r = c.getresponse()
            self._record_body(self._read(r), r.status)
        finally:
            c.close()


def http_session(url: str, headers: dict | None, steps: list, timeout_s: float = 30.0,
                 protocol: str = "2025-03-26") -> Exchange:
    """Handshake, then each step (a JSON-RPC message, a batch list, or a callable returning
    one; see the module docstring) as one POST. `headers`
    are added to every request (Authorization, a routing key). The session id the server
    returns in Mcp-Session-Id is carried on every later request."""
    ex = Exchange()
    deadline = time.monotonic() + timeout_s
    cli = _Http(url, headers, deadline, ex)
    try:
        cli.post(_initialize(protocol))
        init = ex.response_to(HANDSHAKE_ID)
        if not init or "result" not in init:
            ex.conclude([HANDSHAKE_ID])  # a refused handshake is an ending, not a hang
            ex.error = ex.error or "initialize got no result"
            return ex
        cli.protocol = (init["result"] or {}).get("protocolVersion") or protocol
        cli.post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        expected: list = [HANDSHAKE_ID]
        for step in steps:
            msg = _resolve(step, ex)
            if msg is None:
                continue
            expected += _request_ids(msg)
            cli.post(msg)
        ex.conclude(expected)
    except (OSError, http.client.HTTPException) as e:
        ex.error = ex.error or f"{type(e).__name__}: {e}"
    return ex


def post_answer(url: str, headers: dict | None, session_id: str | None, req: dict,
                timeout_s: float = 5.0) -> Exchange:
    """POST the auto answer to server request `req` on an existing session."""
    ex = Exchange(session_id=session_id)
    try:
        _Http(url, headers, time.monotonic() + timeout_s, ex).answer(req)
    except (OSError, http.client.HTTPException) as e:
        ex.error = f"{type(e).__name__}: {e}"
    return ex


def _kill_group(proc: subprocess.Popen) -> None:
    """Like Adapter.stop: the child is its own session leader, so signal its group."""
    def sig(s):
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, s)
    sig(signal.SIGTERM)
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=5)
    sig(signal.SIGKILL)
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=5)


def stdio_session(argv: list[str], env: dict | None, steps: list, timeout_s: float = 30.0,
                  protocol: str = "2025-03-26", cwd: str | None = None) -> Exchange:
    """The same session over a child process speaking newline-delimited JSON-RPC."""
    ex = Exchange()
    deadline = time.monotonic() + timeout_s
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env=env, cwd=cwd, start_new_session=True)
    except OSError as e:
        ex.error = f"{type(e).__name__}: {e}"
        return ex
    lines: queue.Queue = queue.Queue()

    def pump() -> None:
        total = 0
        for raw in proc.stdout:
            total += len(raw)
            if total > _MAX_TOTAL:
                ex.truncated = True
                lines.put("\0cap")
                return
            lines.put(raw.decode("utf-8", "replace").strip())
        lines.put(None)

    threading.Thread(target=pump, daemon=True).start()

    def send(msg) -> None:
        ex.add("sent", msg, "stdio")
        proc.stdin.write((json.dumps(msg, ensure_ascii=False) + "\n").encode())
        proc.stdin.flush()

    def collect(wait_ids: list) -> None:
        """Read lines until every id in wait_ids has a response; answer server requests."""
        pending = set(map(json.dumps, wait_ids))
        while pending:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("deadline reached")
            try:
                line = lines.get(timeout=left)
            except queue.Empty:
                raise TimeoutError("deadline reached") from None
            if line is None:
                raise EOFError("server closed stdout")
            if line == "\0cap":
                raise OSError(f"output truncated at {_MAX_TOTAL} bytes")
            if not line:
                continue
            try:
                m = json.loads(line)
            except ValueError:
                ex.add("recv", {"_raw": line}, "stdio")
                continue
            for one in m if isinstance(m, list) else [m]:
                ex.add("recv", one, "stdio")
                if is_server_request(one):
                    send(auto_answer(one))
                elif isinstance(one, dict) and one.get("method") is None:
                    pending.discard(json.dumps(one.get("id")))

    try:
        send(_initialize(protocol))
        collect([HANDSHAKE_ID])
        init = ex.response_to(HANDSHAKE_ID)
        if not init or "result" not in init:
            ex.conclude([HANDSHAKE_ID])
            ex.error = ex.error or "initialize got no result"
            return ex
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        expected: list = [HANDSHAKE_ID]
        for step in steps:
            msg = _resolve(step, ex)
            if msg is None:
                continue
            expected += _request_ids(msg)
            send(msg)
            collect(_request_ids(msg))
        ex.conclude(expected)
    except (OSError, EOFError, TimeoutError) as e:
        ex.error = f"{type(e).__name__}: {e}"
    finally:
        with contextlib.suppress(OSError):
            proc.stdin.close()
        _kill_group(proc)
    return ex
