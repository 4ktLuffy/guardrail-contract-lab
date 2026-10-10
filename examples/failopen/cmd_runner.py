"""Like tool_runner.py, but the scanner is a subprocess ($SCANNER_CMD), the way many
local guardrails are wired. Used to exercise `gcl probe` in command mode.

    python cmd_runner.py --policy open|closed
"""
import argparse
import json
import os
import shlex
import subprocess
import sys


def scan(text: str) -> dict:
    proc = subprocess.run(shlex.split(os.environ["SCANNER_CMD"]), input=json.dumps({"text": text}),
                          capture_output=True, text=True, timeout=2, check=True)
    return json.loads(proc.stdout)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", choices=["open", "closed"], required=True)
    policy = ap.parse_args().policy
    call = json.loads(sys.stdin.read())
    try:
        verdict = scan(json.dumps(call.get("args", {})))
        flagged = verdict.get("flagged")
    except Exception as e:  # catch-all on purpose: this is the demo of the bug
        if policy == "open":
            flagged = False
        else:
            print(f"blocked: scanner failed ({type(e).__name__})", file=sys.stderr)
            return 0
    if policy == "closed" and not isinstance(flagged, bool):
        print("blocked: no verdict", file=sys.stderr)
        return 0
    if flagged:
        print("blocked by guardrail")
        return 0
    with open(os.environ["GCL_RECEIPT"], "w") as f:
        json.dump(call, f)
    print("ran tool")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
