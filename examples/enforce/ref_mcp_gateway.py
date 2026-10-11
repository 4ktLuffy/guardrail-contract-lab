"""A tiny reference MCP gateway with a guardrail, for `gcl enforce` (standard library only).

A streamable-HTTP MCP proxy: POST /mcp is forwarded to --upstream (Mcp-Session-Id and the
client's Accept carried through; a JSON or SSE reply comes back in the same form, event by
event). Its guard speaks the scanner protocol of LiteLLM's generic guardrail API: before a
message goes upstream it POSTs {"texts": [...], "input_type": "request"}, before a message
goes back to the client {"texts": [...], "input_type": "response"}; the scanner answers
{"action": "NONE" | "BLOCKED" | "GUARDRAIL_INTERVENED", "texts": [...]}. A block becomes a
JSON-RPC error (-32001, "blocked by policy", HTTP 403) for the client's request; upstream is not
called for a blocked request.

Its documented contract: fail closed, as ref_gateway.py. `--policy strict` keeps it and
guards every message: every string in requests, responses, notifications, server requests
inside SSE streams, the client's answers to them, tools/list, resources/read, prompts/get
and error messages, in both directions. It rejects JSON-RPC batches, refuses a tools/call
for a tool missing from the last tools/list it forwarded in that session (a session
with no tools/list has nothing to compare against), re-scans every
tools/list, and treats any scanner failure as a block. A blocked SSE event ends the stream
with an error for the original request.
`--policy naive` guards what most gateways guard: tools/call arguments.note going in and
result.content[0].text coming back; everything else is forwarded untouched, and scanner
errors and unknown verdicts mean "allow".

    python ref_mcp_gateway.py --scanner URL [--scanner-output URL] --upstream URL --port N --policy strict|naive
"""
import argparse
import itertools
import json
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ref_gateway import check  # same directory: the fail-closed verdict handling is shared

TOOLS: dict = {}  # session id -> tool names in the last tools/list forwarded


def string_slots(node, out: list) -> list:
    """(container, key) of every string value in a JSON tree, except the JSON-RPC envelope."""
    for k, v in list(node.items() if isinstance(node, dict) else enumerate(node) if isinstance(node, list) else ()):
        if k in ("jsonrpc", "method"):
            continue
        if isinstance(v, str):
            out.append((node, k))
        else:
            string_slots(v, out)
    return out


def note_slots(msg: dict) -> list:
    """Naive: only the two places every MCP gateway guards."""
    slots = []
    args = (msg.get("params") or {}).get("arguments") if msg.get("method") == "tools/call" else None
    if isinstance(args, dict) and isinstance(args.get("note"), str):
        slots.append((args, "note"))
    content = msg["result"].get("content") if isinstance(msg.get("result"), dict) else None
    first = content[0] if isinstance(content, list) and content else None
    if isinstance(first, dict) and isinstance(first.get("text"), str):
        slots.append((first, "text"))
    return slots


def scan(args, msg: dict, stage: str, req_method: str | None = None) -> bool:
    """True if the message may pass; scanner rewrites are applied in place. Strict leaves
    the handshake alone (initialize and its notification carry no model-facing text) except
    the server's `instructions`, which go straight into the model's context."""
    method = msg.get("method") or (req_method if "method" not in msg else None)
    if args.policy == "naive":
        slots = note_slots(msg)
    elif method == "initialize":
        res = msg.get("result")
        slots = [(res, "instructions")] if isinstance(res, dict) and isinstance(res.get("instructions"), str) else []
    elif method == "notifications/initialized":
        slots = []
    else:
        slots = string_slots(msg, [])
    if not slots:
        return True
    decision, texts = check(args, [c[k] for c, k in slots], stage)
    if decision == "block":
        return False
    for (c, k), t in zip(slots, texts, strict=True):
        c[k] = t
    return True


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scanner", required=True)
    ap.add_argument("--scanner-output", default="", help="scanner URL for replies (default: --scanner)")
    ap.add_argument("--upstream", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--policy", choices=["strict", "naive"], required=True)
    args = ap.parse_args()
    strict = args.policy == "strict"

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code: int, body: bytes, ctype: str = "application/json", sid: str | None = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            if sid:
                self.send_header("Mcp-Session-Id", sid)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _error(self, rid, message: str = "blocked by policy", code: int = -32001, status: int = 403) -> None:
            err = {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}
            self._send(status, json.dumps(err).encode())

        def do_GET(self):
            if self.path.rstrip("/") == "/health":
                self._send(200, b'{"status": "ok"}')
            else:
                self._error(None, "no server-initiated stream here", -32000, 405)

        def _down(self, msg, method, sid) -> bool:
            """Guard one upstream message on its way to the client."""
            if not isinstance(msg, dict):
                return not strict
            if not scan(args, msg, "response", method):
                return False
            tools = msg["result"].get("tools") if isinstance(msg.get("result"), dict) else None
            if strict and method == "tools/list" and isinstance(tools, list):
                TOOLS[sid] = {t.get("name") for t in tools if isinstance(t, dict)}
            return True

        def do_POST(self):
            if self.path.split("?")[0].rstrip("/") != "/mcp":
                self._error(None, "not found", -32000, 404)
                return
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            sid = self.headers.get("Mcp-Session-Id")
            try:
                msg = json.loads(raw)
            except ValueError:
                msg = None
            if strict and not isinstance(msg, dict):  # unparseable, or a batch
                self._error(None, "blocked by policy: batches are not accepted", -32600, 400)
                return
            method = rid = None
            if isinstance(msg, dict):
                method = msg.get("method")
                rid = msg.get("id") if method else None  # a client's answer to a server request has no reply
                if not scan(args, msg, "request"):
                    self._error(rid)
                    return
                tool = (msg.get("params") or {}).get("name")
                if strict and method == "tools/call" and sid in TOOLS and tool not in TOOLS[sid]:
                    self._error(rid, "blocked by policy: tool not in tools/list")
                    return
                raw = json.dumps(msg, ensure_ascii=False).encode()
            headers = {"Content-Type": "application/json",
                       "Accept": self.headers.get("Accept", "application/json, text/event-stream")}
            for h in ("Mcp-Session-Id", "MCP-Protocol-Version"):
                if self.headers.get(h):
                    headers[h] = self.headers[h]
            try:
                try:
                    up = urllib.request.urlopen(urllib.request.Request(args.upstream, raw, headers), timeout=15)
                except urllib.error.HTTPError as e:
                    up = e
            except OSError:
                self._error(rid, "upstream unavailable", -32000, 502)
                return
            with up:
                status = getattr(up, "status", None) or up.code
                ctype, up_sid = up.headers.get("Content-Type", ""), up.headers.get("Mcp-Session-Id")
                if "text/event-stream" in ctype:
                    self._stream(up, status, ctype, up_sid, method, sid, rid)
                    return
                body = up.read()
                if body.strip():
                    try:
                        reply = json.loads(body)
                    except ValueError:
                        reply = None
                        if strict:
                            self._error(rid)
                            return
                    if reply is not None:
                        if not self._down(reply, method, sid):
                            self._error(rid)
                            return
                        body = json.dumps(reply, ensure_ascii=False).encode()
                self._send(status, body, ctype or "application/json", up_sid)

        def _stream(self, up, status, ctype, up_sid, method, sid, rid) -> None:
            """Relay an SSE reply event by event, guarding each event's JSON-RPC message."""
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-cache")
            if up_sid:
                self.send_header("Mcp-Session-Id", up_sid)
            self.end_headers()
            lines: list[bytes] = []
            for line in itertools.chain(up, [b""]):  # the trailing blank line flushes an unterminated last event
                line = line.rstrip(b"\r\n")
                if line:
                    lines.append(line)
                    continue
                data = b"\n".join(x[5:].lstrip(b" ") for x in lines if x.startswith(b"data:"))
                if data:
                    try:
                        msg = json.loads(data)
                    except ValueError:
                        msg = None
                    if (msg is None and strict) or (msg is not None and not self._down(msg, method, sid)):
                        err = {"jsonrpc": "2.0", "id": rid, "error": {"code": -32001, "message": "blocked by policy"}}
                        self.wfile.write(b"event: message\ndata: " + json.dumps(err).encode() + b"\n\n")
                        return
                    if msg is not None:
                        lines = [x for x in lines if not x.startswith(b"data:")]
                        lines.append(b"data: " + json.dumps(msg, ensure_ascii=False).encode())
                if lines:
                    self.wfile.write(b"\n".join(lines) + b"\n\n")
                    self.wfile.flush()
                lines = []

    ThreadingHTTPServer(("127.0.0.1", args.port), H).serve_forever()


if __name__ == "__main__":
    main()
