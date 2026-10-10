"""Stand-in scanners that answer correctly or fail in a chosen way.

Used by `gcl probe`. The system under test is pointed at one of these instead of its
real scanner (through an environment variable it already reads), so the drill
needs no change to the system and no network beyond localhost.

HTTP mode: a localhost server. Command mode: `python -m gcl.faults <mode>` reads the
request on stdin and answers (or misbehaves) on stdout.
"""

from __future__ import annotations

import json
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# mode -> what the stand-in scanner does
MODES = {
    "flag": "answers 'malicious' (control: the system must block)",
    "clean": "answers 'clean' (control: the system must allow)",
    "timeout": "accepts the request and never answers",
    "error": "fails: HTTP 500 / exit status 1",
    "malformed": "answers with bytes that are not JSON",
    "empty": "answers with an empty body",
    "wrong_schema": "answers valid JSON without the verdict field",
    "refused": "nothing is listening (connection refused) / command not found",
}


class FaultServer:
    """A one-mode localhost scanner. In 'timeout' mode it holds the connection until the
    scenario ends and never answers — a late "clean" reply would turn a patient,
    fail-closed system into a false violation."""

    def __init__(self, mode: str, clean: dict, flag: dict):
        self.mode, self.clean, self.flag = mode, clean, flag
        self.requests = 0
        self._srv = None
        self.port = None
        self._stop = threading.Event()

    def __enter__(self):
        if self.mode == "refused":
            # Reserve a free port, then close it: connecting to it is refused.
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
            s.close()
            return self
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # keep test output clean
                pass

            def _answer(self, code: int, body: bytes, ctype="application/json"):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                outer.requests += 1
                n = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(n)
                m = outer.mode
                if m == "timeout":
                    outer._stop.wait()  # until the scenario ends; then drop the connection
                    return
                elif m == "error":
                    self._answer(500, b'{"error": "internal"}')
                elif m == "malformed":
                    self._answer(200, b"<html>upstream error</html>", "text/html")
                elif m == "empty":
                    self._answer(200, b"")
                elif m == "wrong_schema":
                    self._answer(200, b'{"status": "ok"}')
                elif m == "flag":
                    self._answer(200, json.dumps(outer.flag).encode())
                else:
                    self._answer(200, json.dumps(outer.clean).encode())

            do_GET = do_POST

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self._srv.daemon_threads = True
        self.port = self._srv.server_address[1]
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/scan"

    def __exit__(self, *exc):
        self._stop.set()
        if self._srv:
            self._srv.shutdown()
            self._srv.server_close()


def command_main(argv: list[str]) -> int:
    """`python -m gcl.faults <mode> [clean_json] [flag_json]` — command mode."""
    mode = argv[0]
    clean = json.loads(argv[1]) if len(argv) > 1 else {"flagged": False}
    flag = json.loads(argv[2]) if len(argv) > 2 else {"flagged": True}
    sys.stdin.read()
    if mode == "timeout":
        # Never answer. The system's own timeout decides; failing that, the probe
        # harness kills the whole process group at the end of the scenario.
        while True:
            time.sleep(3600)
    if mode == "error":
        print("scanner crashed", file=sys.stderr)
        return 1
    if mode == "malformed":
        print("Traceback (most recent call last): ...")
        return 0
    if mode == "empty":
        return 0
    if mode == "wrong_schema":
        print('{"status": "ok"}')
        return 0
    print(json.dumps(flag if mode == "flag" else clean))
    return 0


if __name__ == "__main__":
    raise SystemExit(command_main(sys.argv[1:]))
