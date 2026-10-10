"""Drive an out-of-process regex runner with a per-pattern deadline.

Each runner reads one request and streams one result line per pattern. A reader
thread feeds lines into a queue; if no line arrives within the deadline, the pattern
that was in flight is recorded as timed out, the runner is killed, and a fresh one
resumes at the next pattern. So a catastrophic-backtracking rule costs one deadline,
is named in the report, and never stalls the run.
"""

from __future__ import annotations

import json
import queue
import shutil
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent


@dataclass
class PatternResult:
    error: str | None = None          # compile error, verbatim from the engine
    hits: list | None = None          # per text: [start, end] in code points, or None
    ms: float | None = None
    max_ms: float | None = None       # slowest single text
    timed_out: bool = False

    @property
    def compiled(self) -> bool:
        return self.error is None and not self.timed_out

    def matched(self, j: int) -> bool | None:
        """True/False for text j; None when the engine has no answer (error/timeout)."""
        if not self.compiled or self.hits is None:
            return None
        return self.hits[j] is not None


@dataclass
class Engine:
    name: str
    argv: list[str]
    default_flags: str
    meta: dict = field(default_factory=dict)

    @property
    def available(self) -> bool:
        return shutil.which(self.argv[0]) is not None or Path(self.argv[0]).exists()

    def run(self, patterns: list[str], texts: list[str], flags: str | None = None,
            deadline_s: float = 5.0,
            per_pattern_texts: list[list[str]] | None = None,
            pattern_flags: list[str | None] | None = None,
            stop_on_timeout: bool = False) -> list[PatternResult]:
        """Run every pattern over `texts`, or pattern i over per_pattern_texts[i].
        pattern_flags[i], when not None, replaces `flags` for pattern i (already in this
        engine's notation). stop_on_timeout: give up after the first hung pattern."""
        if not self.available:
            raise RuntimeError(f"{self.name}: runtime not found ({self.argv[0]})")
        flags = self.default_flags if flags is None else flags
        results: list[PatternResult | None] = [None] * len(patterns)
        start = 0
        while start < len(patterns):
            start = self._run_from(start, patterns, texts, flags, deadline_s, results,
                                   per_pattern_texts, pattern_flags)
            if stop_on_timeout and any(r is not None and r.timed_out for r in results):
                break
        return [r or PatternResult(error="no result") for r in results]

    def _run_from(self, start, patterns, texts, flags, deadline_s, results,
                  per_pattern_texts=None, pattern_flags=None) -> int:
        proc = subprocess.Popen(
            self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, encoding="utf-8",
        )
        lines: queue.Queue = queue.Queue()

        def reader():
            for line in proc.stdout:
                lines.put(line)
            lines.put(None)

        threading.Thread(target=reader, daemon=True).start()
        req = {"flags": flags, "patterns": patterns, "texts": texts, "start": start}
        if per_pattern_texts is not None:
            req["per_pattern_texts"] = per_pattern_texts
        if pattern_flags is not None:
            req["pattern_flags"] = pattern_flags
        try:
            proc.stdin.write(json.dumps(req))
            proc.stdin.close()
        except BrokenPipeError:
            pass
        expected = start
        # The first line is metadata; give startup (node boot, large request) extra time.
        budget = deadline_s + 10.0
        try:
            while expected < len(patterns):
                try:
                    line = lines.get(timeout=budget)
                except queue.Empty:
                    results[expected] = PatternResult(timed_out=True)
                    return expected + 1
                if line is None:  # runner died mid-pattern
                    err = (proc.stderr.read() or "").strip().splitlines()
                    results[expected] = PatternResult(
                        error=f"runner exited: {err[-1] if err else proc.poll()}")
                    return expected + 1
                msg = json.loads(line)
                # Startup allowance covers boot + reading the request only; from the
                # metadata line on, every pattern gets exactly the deadline.
                budget = deadline_s
                if "meta" in msg:
                    self.meta = msg["meta"]
                    continue
                i = msg["i"]
                results[i] = PatternResult(error=msg.get("error"), hits=msg.get("hits"),
                                           ms=msg.get("ms"), max_ms=msg.get("max_ms"))
                expected = i + 1
            return expected
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()


PY_FLAG_LETTERS = set("IMSXAU")
JS_FLAG_LETTERS = set("dgimsuvy")


def validate_flags(engine: str, flags: str) -> None:
    """Raise ValueError for flag letters the engine does not have (a typo would
    otherwise show up as every rule 'failing to compile')."""
    if engine == "python":
        bad = set(flags.upper()) - PY_FLAG_LETTERS
        if bad:
            raise ValueError(f"python flags: unknown letter(s) {''.join(sorted(bad))!r}; "
                             "use I M S X A U")
    elif engine == "node":
        bad = set(flags) - JS_FLAG_LETTERS
        if bad or len(set(flags)) != len(flags):
            raise ValueError(f"node flags: {flags!r} is not a valid RegExp flag string; "
                             "use letters from d g i m s u v y, once each")


def rule_flags(engine: str, js_style: str | None) -> str | None:
    """A rule's own `flags` key (JavaScript notation, as rule files use: "i", "gi",
    "im"…) in the notation of `engine`. None means: use the loader's default."""
    if js_style is None:
        return None
    if engine == "python":
        # g/y/d/v/u have no Python counterpart that changes search(): drop them.
        return "".join(c.upper() for c in js_style if c in "ims")
    return js_style


ENGINES = {
    # -I: isolated mode, so nothing from the working directory shadows `re` or `json`.
    "python": lambda: Engine("python", [sys.executable, "-I", str(HERE / "python_runner.py")], "IM"),
    "node": lambda: Engine("node", ["node", str(HERE / "node_runner.js")], "im"),
}


def get_engine(name: str) -> Engine:
    try:
        return ENGINES[name]()
    except KeyError:
        raise ValueError(f"unknown engine {name!r}; choose from {', '.join(ENGINES)}") from None
