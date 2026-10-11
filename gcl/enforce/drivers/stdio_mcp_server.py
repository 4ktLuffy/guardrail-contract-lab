"""A minimal MCP server over stdio (newline-delimited JSON-RPC), standard library only.

    python stdio_mcp_server.py --mock URL

A bridge to gcl's mock MCP server at URL/mcp: every message on stdin (requests,
notifications, and the client's answers to server requests) is POSTed there with
`X-GCL-Transport: stdio`, and every JSON-RPC message in the reply (a JSON body, a batch
array, or each event of an SSE stream) is written as its own stdout line. The mock records
what it received (the provider boundary) and places the scenario's payload in the MCP
surface under test; nothing is decided here. The client's answer to a server request
(m12) is POSTed from the reader thread while the SSE stream is still open.
"""
import json
import queue
import sys
import threading
import urllib.error
import urllib.request

_OUT = threading.Lock()


def _emit(obj) -> None:
    with _OUT:
        sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
        sys.stdout.flush()


def _post(mock: str, msg) -> None:
    """POST one message (or batch) and write whatever JSON-RPC the reply carries."""
    req = urllib.request.Request(mock + "/mcp", data=json.dumps(msg, ensure_ascii=False).encode(), headers={
        "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
        "X-GCL-Transport": "stdio"})
    try:
        r = urllib.request.urlopen(req, timeout=15)
    except urllib.error.HTTPError as e:
        r = e
    except Exception as e:  # the client must get an answer, not a hung pipe
        mid = msg.get("id") if isinstance(msg, dict) else None
        if mid is not None:
            _emit({"jsonrpc": "2.0", "id": mid, "error": {"code": -32603, "message": f"bridge: {e}"}})
        return
    with r:
        if "text/event-stream" in (r.headers.get("Content-Type") or ""):
            data: list[str] = []
            for raw in r:
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if line.startswith("data:"):
                    data.append(line[5:].removeprefix(" "))
                elif not line and data:
                    _emit_text("\n".join(data))
                    data = []
            if data:
                _emit_text("\n".join(data))
        else:
            body = r.read().decode("utf-8", "replace")
            if body.strip():
                _emit_text(body)


def _emit_text(text: str) -> None:
    try:
        obj = json.loads(text)
    except ValueError:
        return
    for m in obj if isinstance(obj, list) else [obj]:
        _emit(m)


def main() -> None:
    mock = sys.argv[sys.argv.index("--mock") + 1].rstrip("/")
    work: queue.Queue = queue.Queue()

    def reader() -> None:
        for line in sys.stdin:
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if isinstance(msg, dict) and msg.get("method") is None and msg.get("id") is not None:
                # An answer to a server request: the request's stream is still open on
                # the worker thread, so this must not queue behind it.
                threading.Thread(target=_post, args=(mock, msg), daemon=True).start()
            else:
                work.put(msg)
        work.put(None)

    threading.Thread(target=reader, daemon=True).start()
    while (msg := work.get()) is not None:
        _post(mock, msg)


if __name__ == "__main__":
    main()
