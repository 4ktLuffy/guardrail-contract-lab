"""Driver for openai-guardrails (`pip install openai-guardrails`, import `guardrails`).

    python openai_guardrails_driver.py --port N --base-url URL --config FILE
        [--raise-guardrail-errors] [--timeout S]

Uses `GuardrailsOpenAI` exactly as its README shows: the guardrail LLM shares the
client's base_url, and `GuardrailTripwireTriggered` is how a block surfaces.
"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from guardrails import GuardrailsOpenAI, GuardrailTripwireTriggered


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--model", default="gcl-mock")
    ap.add_argument("--raise-guardrail-errors", action="store_true")
    ap.add_argument("--timeout", type=float, default=None)
    args = ap.parse_args()
    kwargs = {"timeout": args.timeout} if args.timeout else {}
    client = GuardrailsOpenAI(config=Path(args.config), raise_guardrail_errors=args.raise_guardrail_errors,
                              base_url=args.base_url, api_key="sk-gcl", **kwargs)

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
            try:
                r = client.chat.completions.create(model=args.model, messages=body.get("messages", []))
            except GuardrailTripwireTriggered as e:
                self._json(400, {"error": {"type": "guardrail_tripwire", "message": str(e),
                                           "detail": repr(getattr(e, "guardrail_result", None))}})
                return
            except Exception as e:  # anything else the library raised
                self._json(500, {"error": {"type": type(e).__name__, "message": str(e), "detail": repr(e)},
                                 "library_return": {"exception_attrs": {k: repr(v) for k, v in vars(e).items()}}})
                return
            # Everything the caller could read, not just the first choice.
            full = r.llm_response.model_dump() if hasattr(r, "llm_response") else repr(r)
            self._json(200, {"choices": [{"index": 0, "message": {
                "role": "assistant", "content": r.choices[0].message.content}}], "library_return": full})

    ThreadingHTTPServer(("127.0.0.1", args.port), H).serve_forever()


if __name__ == "__main__":
    main()
