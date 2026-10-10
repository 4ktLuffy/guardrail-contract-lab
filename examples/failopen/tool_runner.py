"""A toy agent tool runner with a guardrail in front of every tool call.

Written for the `gcl probe` demo. It reads one tool call as JSON on stdin, asks a
scanner (HTTP, URL in $SCANNER_URL) whether the call is safe, and runs the tool only
if the scanner says so. "Running the tool" here just writes a receipt file
($GCL_RECEIPT): that is the observable side effect the drill watches for.

    python tool_runner.py --policy open     # the common bug: errors mean "allow"
    python tool_runner.py --policy closed   # the fix: errors mean "block"
"""
import argparse
import json
import os
import sys
import urllib.request


def ask_scanner(text: str, timeout: float = 2.0) -> dict:
    req = urllib.request.Request(os.environ["SCANNER_URL"], method="POST",
                                 data=json.dumps({"text": text}).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def allowed_fail_open(text: str) -> bool:
    try:
        verdict = ask_scanner(text)
    except Exception:
        # "Don't break the user's workflow if the scanner is down" -- the fail-open bug.
        return True
    return not verdict.get("flagged", False)  # missing field reads as "clean"


def allowed_fail_closed(text: str) -> bool:
    try:
        verdict = ask_scanner(text)
    except Exception as e:
        print(f"blocked: scanner unavailable ({type(e).__name__})", file=sys.stderr)
        return False
    flagged = verdict.get("flagged") if isinstance(verdict, dict) else None
    if not isinstance(flagged, bool):
        print("blocked: scanner gave no verdict", file=sys.stderr)
        return False
    return not flagged


def run_tool(call: dict) -> None:
    with open(os.environ["GCL_RECEIPT"], "w") as f:
        json.dump(call, f)
    print(f"ran tool {call.get('tool')}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", choices=["open", "closed"], required=True)
    policy = ap.parse_args().policy
    call = json.loads(sys.stdin.read())
    text = json.dumps(call.get("args", {}), ensure_ascii=False)
    ok = (allowed_fail_open if policy == "open" else allowed_fail_closed)(text)
    if not ok:
        print("blocked by guardrail")
        return 0
    run_tool(call)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
