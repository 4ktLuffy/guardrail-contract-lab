"""A tiny reference LLM gateway with a guardrail, for `gcl enforce` (standard library only).

It speaks the same scanner protocol as LiteLLM's generic guardrail API: before the model
call it POSTs {"texts": [...], "input_type": "request"} to the scanner, after it
{"texts": [...], "input_type": "response"}; the scanner answers {"action": "NONE" |
"BLOCKED" | "GUARDRAIL_INTERVENED", "texts": [...]}.

Its documented contract: fail closed — any scanner error, timeout, unparseable or
unrecognised verdict stops the request. `--policy strict` keeps that promise.
`--policy naive` breaks it the way real integrations do: errors and unknown verdicts
are treated as "allow". Use it to see `gcl enforce` catch the difference.

    python ref_gateway.py --scanner URL [--scanner-output URL] --model URL --port N \
        --policy strict|naive
"""
import argparse
import json
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def post(url: str, body: dict, timeout: float) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body, ensure_ascii=False).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def check(args, texts: list[str], stage: str):
    """Return ("allow" | "block", texts). Strict: anything unexpected blocks."""
    url = args.scanner_output if stage == "response" and args.scanner_output else args.scanner
    try:
        verdict = post(url, {"texts": texts, "input_type": stage}, timeout=3)
    except Exception:
        return ("allow", texts) if args.policy == "naive" else ("block", texts)
    action = verdict.get("action") if isinstance(verdict, dict) else None
    if action == "BLOCKED":
        return "block", texts
    if action == "GUARDRAIL_INTERVENED":
        new = verdict.get("texts")
        # A rewrite must replace every text, one for one, with a string; anything else
        # would forward some original text unscanned.
        if isinstance(new, list) and len(new) == len(texts) and all(isinstance(t, str) for t in new):
            return "allow", new
        return ("allow", texts) if args.policy == "naive" else ("block", texts)
    if action == "NONE" or args.policy == "naive":
        return "allow", texts
    return "block", texts


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scanner", required=True)
    ap.add_argument("--scanner-output", default="", help="scanner URL for replies (default: --scanner)")
    ap.add_argument("--model", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--policy", choices=["strict", "naive"], required=True)
    args = ap.parse_args()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, code: int, obj: dict) -> None:
            b = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            self._json(200, {"status": "ok"})

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            messages = body.get("messages", [])
            texts = [m.get("content", "") for m in messages]
            decision, texts = check(args, texts, "request")
            if decision == "block":
                self._json(400, {"error": {"message": "blocked by guardrail"}})
                return
            for m, t in zip(messages, texts, strict=True):
                m["content"] = t
            try:
                reply = post(args.model, {"model": body.get("model", "m"), "messages": messages}, timeout=10)
            except urllib.error.URLError:
                self._json(502, {"error": {"message": "model unavailable"}})
                return
            content = reply["choices"][0]["message"]["content"]
            decision, out = check(args, [content], "response")
            if decision == "block":
                self._json(400, {"error": {"message": "blocked by guardrail"}})
                return
            reply["choices"][0]["message"]["content"] = out[0]
            self._json(200, reply)

    ThreadingHTTPServer(("127.0.0.1", args.port), H).serve_forever()


if __name__ == "__main__":
    main()
