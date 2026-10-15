"""Conformance driver for pydantic-ai's per-tool `requires_approval` setting (`gcl conform`).

    python pydantic_ai_conform_driver.py --base URL --fixture-dir DIR --requires-approval true|false --prompt TEXT
    python pydantic_ai_conform_driver.py --version

Runs in the pydantic-ai venv (stdlib + pydantic_ai only; it imports nothing from gcl). Builds an
Agent whose model client points at a loopback OpenAI-compatible stub, registers two tools, runs ONE
agent turn, and prints one JSON line.

  write_marker(text)    the GOVERNED operation: `requires_approval` is set from the command line.
                        When it runs it writes DIR/marker.txt.
  record_allowed(text)  a permitted operation, never governed: writes DIR/allowed.txt. It is how the
                        harness shows its observer can see a normal tool run.

The JSON line (`output_kind`, `deferred_tools`) is corroboration only. Whether the governed
operation took effect is judged by the file on disk, read by gcl, never by this output.
"""
import argparse
import json
import os
import sys


def _flag(v: str) -> bool:
    if v not in ("true", "false"):
        raise argparse.ArgumentTypeError("expected true or false")
    return v == "true"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", action="store_true")
    ap.add_argument("--base")
    ap.add_argument("--fixture-dir")
    ap.add_argument("--requires-approval", type=_flag)
    ap.add_argument("--prompt", default="")
    args = ap.parse_args()
    if args.version:
        from importlib.metadata import version
        print(json.dumps({"pydantic_ai": version("pydantic-ai-slim")}))
        return
    if not (args.base and args.fixture_dir and args.requires_approval is not None):
        ap.error("--base, --fixture-dir and --requires-approval are required")

    from pydantic_ai import Agent, DeferredToolRequests
    from pydantic_ai.models.openai import OpenAIChatModel
    from pydantic_ai.providers.openai import OpenAIProvider

    model = OpenAIChatModel("gcl-stub", provider=OpenAIProvider(base_url=args.base, api_key="sk-gcl-stub"))
    agent = Agent(model, output_type=[str, DeferredToolRequests])

    @agent.tool_plain(requires_approval=args.requires_approval)
    def write_marker(text: str) -> str:
        with open(os.path.join(args.fixture_dir, "marker.txt"), "w", encoding="utf-8") as f:
            f.write(text)
        return "written"

    @agent.tool_plain
    def record_allowed(text: str) -> str:
        with open(os.path.join(args.fixture_dir, "allowed.txt"), "w", encoding="utf-8") as f:
            f.write(text)
        return "recorded"

    result = agent.run_sync(args.prompt)
    out = result.output
    deferred = [c.tool_name for c in (out.approvals if isinstance(out, DeferredToolRequests) else [])]
    print(json.dumps({"output_kind": type(out).__name__, "deferred_tools": deferred}))


if __name__ == "__main__":
    sys.exit(main())
