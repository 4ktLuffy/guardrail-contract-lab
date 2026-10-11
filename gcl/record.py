"""`gcl record`: capture real vendor replies, so stand-ins stop being guesses.

A recording proxy sits between an integration and the real guard vendor. The integration
is pointed at the proxy instead of the vendor (the same setting gcl uses for its
stand-in); every request is forwarded unchanged and the vendor's answer is returned
unchanged, and both are appended to a JSON-lines file. Then `to-spec` turns one recorded
allow and one recorded block answer into the `recorded` block of a vendor spec, with the
request shape they were captured for, so `gcl enforce` serves real answers and labels its
results "recorded" instead of "guessed".

What is never written to the file: request headers (credentials travel there), and any
JSON field whose name looks like a secret (key, token, secret, password, authorization)
— its value is replaced by "[redacted]" in both requests and responses.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

SECRET = re.compile(r"(api[_-]?key|token|secret|password|authorization|credential|bearer)", re.I)
HOP = {"host", "content-length", "connection", "keep-alive", "transfer-encoding", "accept-encoding",
       "proxy-authorization", "te", "trailer", "upgrade"}


def redact(obj):
    """Replace the value of every secret-looking field, at any depth."""
    if isinstance(obj, dict):
        return {k: ("[redacted]" if SECRET.search(str(k)) else redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def _decode(raw: bytes):
    text = raw.decode("utf-8", "replace")
    try:
        return json.loads(text)
    except ValueError:
        return text


def request_shape(body) -> dict:
    """What a recorded reply depends on that gcl can check: the message count."""
    if isinstance(body, dict) and isinstance(body.get("messages"), list):
        return {"messages": len(body["messages"])}
    return {}


class RecordingProxy:
    """Forward every request to `upstream` and record the exchange in `out`."""

    def __init__(self, upstream: str, out: Path, host: str = "127.0.0.1", port: int = 0, timeout_s: float = 60.0):
        u = urlsplit(upstream)
        if u.scheme not in ("http", "https") or not u.netloc:
            raise ValueError(f"upstream must be an http(s) URL, got {upstream!r}")
        self.upstream, self.out, self.timeout_s = upstream.rstrip("/"), Path(out), timeout_s
        self._lock = threading.Lock()
        self.count = 0
        self.srv = ThreadingHTTPServer((host, port), self._handler())
        self.srv.daemon_threads = True

    @property
    def url(self) -> str:
        h, p = self.srv.server_address[:2]
        return f"http://{h}:{p}"

    def __enter__(self):
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.srv.shutdown()
        self.srv.server_close()

    def _write(self, rec: dict) -> None:
        with self._lock:
            self.count += 1
            rec["n"] = self.count
            with self.out.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def _handler(self):
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _forward(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
                req = urllib.request.Request(outer.upstream + self.path, data=raw if raw else None,
                                             headers=headers, method=self.command)
                try:
                    with urllib.request.urlopen(req, timeout=outer.timeout_s) as r:
                        status, body, ctype = r.status, r.read(), r.headers.get("Content-Type", "")
                except urllib.error.HTTPError as e:
                    status, body, ctype = e.code, e.read(), e.headers.get("Content-Type", "")
                except (urllib.error.URLError, OSError) as e:
                    outer._write({"t": _now(), "method": self.command, "path": self.path,
                                  "request": redact(_decode(raw)), "error": str(e)})
                    self.send_response(502)
                    self.end_headers()
                    return
                req_body = _decode(raw)
                outer._write({"t": _now(), "method": self.command, "path": self.path,
                              "request": redact(req_body), "request_shape": request_shape(req_body),
                              "status": status, "response": redact(_decode(body))})
                self.send_response(status)
                if ctype:
                    self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_POST = do_GET = do_PUT = _forward

        return H


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def to_spec(records: list[dict], spec: dict, allow: int, block: int, upstream_note: str = "") -> dict:
    """Put recorded allow and block replies (by record number) into a copy of `spec`.
    Both must be successful JSON answers to requests of the same shape: a reply whose
    content depends on the request is only valid for requests like the one it answered."""
    by_n = {r.get("n"): r for r in records}
    picked = {}
    for name, n in (("allow", allow), ("block", block)):
        r = by_n.get(n)
        if r is None:
            raise ValueError(f"no record number {n}")
        if r.get("error") or not isinstance(r.get("response"), dict) or not 200 <= int(r.get("status") or 0) < 300:
            raise ValueError(f"record {n} is not a successful JSON answer; it cannot stand for {name}")
        if "[redacted]" in json.dumps(r["response"]):
            raise ValueError(f"record {n}'s answer had secret-looking fields redacted; it would not be the real reply")
        picked[name] = r
    shapes = {json.dumps(r.get("request_shape") or {}, sort_keys=True) for r in picked.values()}
    if len(shapes) != 1 or not picked["block"].get("request_shape"):
        raise ValueError("the allow and block records must answer requests of the same, known shape "
                         f"(got {[r.get('request_shape') for r in picked.values()]})")
    if picked["allow"]["response"] == picked["block"]["response"]:
        raise ValueError("the allow and block answers are identical: one of them is not what you think")
    out = json.loads(json.dumps(spec))
    out["recorded"] = {"allow": picked["allow"]["response"], "block": picked["block"]["response"],
                       "request_shape": picked["block"]["request_shape"],
                       "source": f"gcl record, records {allow} (allow) and {block} (block), captured "
                                 f"{picked['block'].get('t', '?')}{' from ' + upstream_note if upstream_note else ''}"}
    return out
