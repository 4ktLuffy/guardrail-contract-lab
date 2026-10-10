"""Driver for Guardrails AI (`pip install guardrails-ai`).

    python guardrails_ai_driver.py --port N --model-base URL --input-guard URL
        --output-guard URL [--style python|rail]

The validator is gcl's strictest one (POST the text to the scanner; PassResult only on an
explicit allow, FailResult on a block, raise on anything else). What is under test is the
framework: style "python" attaches it with `Guard().use(...)` (default on_fail), on the
messages and on the output; style "rail" declares the same validator in a RAIL spec
without an on-fail attribute, as the RAIL docs' examples do. `ValidationError` (or any
exception) is how a block surfaces; a validated output is returned as the answer.
"""
import argparse
import json
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict

from guardrails import Guard
from guardrails.validator_base import FailResult, PassResult, Validator, register_validator


def _post(url: str, obj: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(obj, ensure_ascii=False).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=8) as r:
        return json.loads(r.read())


URLS: dict = {}


@register_validator(name="gcl/strict-check", data_type="string")
class GclCheck(Validator):
    def __init__(self, stage: str = "response", **kwargs):
        super().__init__(stage=stage, **kwargs)
        self.stage = stage

    def validate(self, value: Any, metadata: Dict) -> Any:
        v = _post(URLS[self.stage], {"texts": [str(value)], "input_type": self.stage})
        action = v.get("action") if isinstance(v, dict) else None
        if action == "NONE":
            return PassResult()
        if action == "BLOCKED":
            return FailResult(error_message=str(v.get("blocked_reason") or "blocked"))
        raise RuntimeError(f"unrecognised scanner verdict: {v!r}")


RAIL = """<rail version="0.1">
<output type="string" validators="gcl/strict-check: response" />
</rail>"""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--model-base", required=True)
    ap.add_argument("--input-guard", required=True)
    ap.add_argument("--output-guard", required=True)
    ap.add_argument("--style", default="python")
    args = ap.parse_args()
    URLS.update(request=args.input_guard, response=args.output_guard)
    if args.style == "rail":
        guard = Guard.for_rail_string(RAIL)
    else:
        guard = Guard().use(GclCheck(stage="request"), on="messages").use(GclCheck(stage="response"))

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
                out = guard(model="openai/gcl-mock", messages=body.get("messages", []),
                            api_base=args.model_base, api_key="sk-gcl")
            except Exception as e:
                code = 400 if type(e).__name__ == "ValidationError" else 500
                self._json(code, {"error": {"type": type(e).__name__, "message": str(e), "detail": repr(e)},
                                 "library_return": {"exception_attrs": {k: repr(v) for k, v in vars(e).items()}}})
                return
            # Exactly what the docs tell an application to use; the driver does not judge it.
            self._json(200, {"choices": [{"index": 0, "message": {"role": "assistant",
                                                                  "content": out.validated_output}}],
                             "library_return": {"raw_llm_output": out.raw_llm_output,
                                                "validation_passed": out.validation_passed}})

    ThreadingHTTPServer(("127.0.0.1", args.port), H).serve_forever()


if __name__ == "__main__":
    main()
