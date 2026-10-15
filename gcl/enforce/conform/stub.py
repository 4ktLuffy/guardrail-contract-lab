"""A loopback OpenAI-compatible model endpoint for conformance runs (stdlib `http.server`).

It answers an agent's `/v1/chat/completions` from gcl's `ScriptedModelEndpoint` (benign setup turns
from the `ConversationScript`, then ONE deterministic tool call for the governed operation on the turn
the run's marker first appears). It is a test fixture: it binds 127.0.0.1 on an ephemeral port, makes
no outbound connection, and holds no reference to any observer or fixture directory, so it can neither
cause nor hide the effect under test. Same requests give the same replies.

`on_request` is a fault-injection hook (called with the 1-based request count before the reply is
sent); production runs leave it None.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..breach.driver import ScriptedModelEndpoint


class LoopbackModelStub:
    def __init__(self, endpoint: ScriptedModelEndpoint, on_request: Callable[[int], None] | None = None):
        self.endpoint = endpoint
        self.on_request = on_request
        self.paths: list[str] = []
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._count = 0

    @property
    def base_url(self) -> str:
        if self._server is None:
            raise RuntimeError("stub is not started")
        return f"http://127.0.0.1:{self._server.server_port}/v1"

    def __enter__(self) -> LoopbackModelStub:
        stub = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                try:
                    body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                    stub.paths.append(self.path)
                    stub._count += 1
                    if stub.on_request is not None:
                        stub.on_request(stub._count)
                    message = stub.endpoint(body)
                except Exception as e:  # a malformed request is a failed run, never a quiet success
                    b = json.dumps({"error": {"message": f"{type(e).__name__}: {e}"}}).encode()
                    self.send_response(500)
                else:
                    called = bool(message.get("tool_calls"))
                    b = json.dumps({"id": "gcl-stub", "object": "chat.completion", "created": 0, "model": "gcl-stub",
                                    "choices": [{"index": 0, "message": message,
                                                 "finish_reason": "tool_calls" if called else "stop"}],
                                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}).encode()
                    self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
