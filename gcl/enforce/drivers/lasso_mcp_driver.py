"""Driver for Lasso mcp-gateway (stdio MCP proxy) with its `lasso` guardrail plugin.

    python lasso_mcp_driver.py --port N --config FILE --python PY

For each request it opens an MCP stdio session to the gateway (started through
lasso_gateway_launch.py with `-p lasso`), calls the proxied tool `gcl_gcl_probe` with the
request text, and returns the tool result's text as the answer. An MCP error or a result
flagged isError is reported as 400 with its text; a failed session as 500.
"""
import argparse
import asyncio
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def call(args, text: str) -> tuple[int, dict]:
    launch = str(Path(__file__).with_name("lasso_gateway_launch.py"))
    params = StdioServerParameters(command=args.python, args=[launch, "--mcp-json-path", args.config, "-p", "lasso"],
                                   env=dict(os.environ))
    async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
        await s.initialize()
        res = await s.call_tool("gcl_gcl_probe", {"note": text})
        content = "".join(getattr(c, "text", "") or "" for c in res.content or [])
        return (400 if res.isError else 200), {"choices": [{"index": 0, "message": {"role": "assistant",
                                                                                   "content": content}}],
                                               "library_return": {"is_error": res.isError}}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--python", required=True)
    args = ap.parse_args()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, code: int, obj: dict) -> None:
            b = json.dumps(obj, ensure_ascii=False, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            self._json(200, {"status": "ok"})

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            text = (body.get("messages") or [{}])[-1].get("content", "")
            try:
                code, obj = asyncio.run(call(args, text))
            except BaseException as e:  # report whatever the session raised
                self._json(500, {"error": {"type": type(e).__name__, "message": str(e), "detail": repr(e)}})
                return
            self._json(code, obj)

    ThreadingHTTPServer(("127.0.0.1", args.port), H).serve_forever()


if __name__ == "__main__":
    main()
