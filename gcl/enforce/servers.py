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
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable


class _Server:
    """A ThreadingHTTPServer on a free localhost port, run in a daemon thread."""

    handler_factory: Callable

    def __enter__(self):
        self._stop = threading.Event()
        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), self.handler_factory())
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
        return f"http://127.0.0.1:{self.port}"


class MockModel(_Server):
    """OpenAI-compatible /v1/chat/completions with a fixed reply (streamed or not)."""

    def __init__(self, reply: str, model: str = "gcl-mock", judge: StandInScanner | None = None):
        self.reply, self.model = reply, model
        self.judge = judge  # requests for judge.protocol.judge_model are the guard's, not the model's
        self.events: list[dict] = []        # append-only: {"t", "body", "reply"}
        self.unexpected: list[str] = []
        self.inflight = 0
        self._lock = threading.Lock()

    @property
    def requests(self) -> list[dict]:
        return [e["body"] for e in self.events]

    def last_activity(self) -> float:
        return self.events[-1]["t"] if self.events else 0.0

    @property
    def openai_base(self) -> str:
        return f"{self.base}/v1"

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
                if not self.path.rstrip("/").endswith("/chat/completions"):
                    outer.unexpected.append(f"POST {self.path}")
                    self._json(404, {"error": "not found"})
                    return
                try:
                    body = json.loads(raw or b"{}")
                except ValueError:
                    body = {"_unparseable": raw.decode("utf-8", "replace")}
                j = outer.judge
                if j is not None and isinstance(body, dict) and body.get("model") == j.protocol.judge_model:
                    with outer._lock:
                        outer.inflight -= 1  # the scanner counts this one
                    try:
                        j.serve(self, None, raw)
                    finally:
                        with outer._lock:
                            outer.inflight += 1
                    return
                outer.events.append({"t": time.monotonic(), "body": body, "reply": outer.reply})
                created = int(time.time())
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
    # Protocol-specific faults: mode name -> full response body (sent with HTTP 200).
    extra_faults: dict = field(default_factory=dict)
    # Overrides for built-in content faults when verdicts are plain text, not JSON:
    # mode ("unknown_verdict", "verdict_type") -> the text to answer with.
    variants: dict = field(default_factory=dict)


# Modes a stage can be put in. Verdict modes answer correctly; fault modes misbehave.
VERDICTS = ("allow", "block", "modify")
FAULTS = ("error", "timeout", "malformed", "empty", "wrong_schema", "unknown_verdict", "verdict_type",
          "refused")


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

    def configure(self, modes: dict[str, str], modify_text: str = "") -> None:
        self.modes, self.modify_text = dict(modes), modify_text
        self.release_stalled()
        for st in self.STAGES:
            refused = self.modes.get(st) == "refused"
            if refused and self._srv[st] is not None:
                self._close(st)
            elif not refused and self._srv[st] is None:
                self._open(st)

    def release_stalled(self) -> None:
        """Free handlers held by a "timeout" mode: they close without an answer."""
        self._release.set()
        self._release = threading.Event()

    def last_activity(self) -> float:
        return self.events[-1]["t"] if self.events else 0.0

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

    def serve(self, h: BaseHTTPRequestHandler, listener: str | None, raw: bytes) -> None:
        """Answer one request on handler `h`. `listener` is the stage whose port it came
        in on, or None for a shared endpoint (the body then says which stage)."""
        with self._lock:
            self.inflight += 1
        try:
            self._serve(h, listener, raw)
        finally:
            with self._lock:
                self.inflight -= 1

    def _serve(self, h: BaseHTTPRequestHandler, listener: str | None, raw: bytes) -> None:
        proto = self.protocol

        def send(code: int, body: bytes, ctype: str = "application/json"):
            h.send_response(code)
            h.send_header("Content-Type", ctype)
            h.send_header("Content-Length", str(len(body)))
            h.end_headers()
            h.wfile.write(body)

        def content(text: str, code: int = 200, ctype: str = "application/json"):
            if proto.envelope is not None:
                send(code, json.dumps(proto.envelope(text), ensure_ascii=False).encode())
            else:
                send(code, text.encode(), ctype)

        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            body = {}
        claimed = proto.stage_of(body) if isinstance(body, dict) else None
        path_ok = not proto.path or h.path.rstrip("/").endswith(proto.path)
        valid = path_ok and claimed in self.STAGES and (listener is None or claimed == listener)
        stage = listener or claimed
        mode = self.modes.get(stage, "allow") if valid else "rejected"
        ev = {"t": time.monotonic(), "stage": stage, "claimed_stage": claimed,
              "path": h.path, "valid": valid, "mode": mode, "body": body,
              "body_text": raw.decode("utf-8", "replace"), "answered": None}
        self.events.append(ev)
        if not valid:
            ev["answered"] = "400 (wrong path or stage)"
            send(400, b'{"error": "gcl stand-in: unexpected path or stage"}')
            return
        release = self._release
        if mode in VERDICTS:
            resp = proto.verdicts[mode](body, self.modify_text)
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
            with self._lock:
                self.stalled += 1
            try:
                release.wait(300)  # never answer while the scenario runs
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
        elif mode == "unknown_verdict":
            resp = _mangle_verdict(proto.verdicts["block"](body, self.modify_text))
            ev["answered"] = resp
            content(json.dumps(resp))
        elif mode == "verdict_type":
            resp = _type_confuse(proto.verdicts["block"](body, self.modify_text))
            ev["answered"] = resp
            content(json.dumps(resp))
        elif mode in proto.extra_faults:
            ev["answered"] = proto.extra_faults[mode]
            send(200, json.dumps(proto.extra_faults[mode], ensure_ascii=False).encode())
        else:
            ev["answered"] = "500 (unknown gcl mode)"
            send(500, b'{"error": "unknown gcl mode"}')

    def handler_factory(self, listener: str):
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                outer.serve(self, listener, self.rfile.read(n))

        return H


def _type_confuse(resp: dict) -> dict:
    """The block verdict with the right meaning in the wrong type: booleans as strings
    ("true"/"false"), verdict keywords in lower case. What a scanner written in another
    language, or a hand-rolled JSON template, sends. A parser that tests truthiness reads
    the string "false" as true."""
    out = {}
    for key, val in resp.items():
        if isinstance(val, bool):
            out[key] = "true" if val else "false"
        elif isinstance(val, str) and key in ("action", "verdict", "decision", "result") and val.isupper():
            out[key] = val.lower()
        else:
            out[key] = val
    return out


def _mangle_verdict(resp: dict) -> dict:
    """A block verdict with its verdict field set to a value the protocol does not
    define — what a scanner upgrade or a typo produces. A robust parser must not read
    an unknown verdict as allow."""
    out = dict(resp)
    for key in ("action", "verdict", "decision", "result"):
        if key in out:
            out[key] = "DENY_UNKNOWN"
            return out
    for key, val in out.items():
        if isinstance(val, bool):
            out[key] = "unknown"
            return out
    return out
