// Out-of-process JavaScript RegExp runner. Same protocol as python_runner.py: one
// JSON request on stdin, one JSON line per pattern on stdout. Match offsets are
// converted from UTF-16 code units to code points so they compare with Python's.
"use strict";
const chunks = [];
process.stdin.on("data", (c) => chunks.push(c));
process.stdin.on("end", () => {
  const req = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  const flags = req.flags === undefined ? "im" : req.flags;
  // fs.writeSync, not process.stdout.write: on macOS a pipe write is asynchronous, so a
  // later hanging regex would hold earlier results in Node's buffer and the parent would
  // blame the wrong rule. A synchronous write puts each result on the wire before the
  // next pattern runs.
  const fs = require("fs");
  const write = (o) => fs.writeSync(1, JSON.stringify(o) + "\n");
  write({ meta: { engine: "node-regexp", version: process.version, flags } });
  const cp = (s, unitIndex) => Array.from(s.slice(0, unitIndex)).length;
  const { patterns, texts } = req;
  for (let i = req.start || 0; i < patterns.length; i++) {
    const t0 = process.hrtime.bigint();
    let rx;
    try {
      const pf = req.pattern_flags && req.pattern_flags[i] != null ? req.pattern_flags[i] : flags;
      rx = new RegExp(patterns[i], pf);
    } catch (e) {
      write({ i, error: `${e.name}: ${e.message}` });
      continue;
    }
    const mine = req.per_pattern_texts ? req.per_pattern_texts[i] : texts;
    let worst = 0n;
    const hits = mine.map((t) => {
      rx.lastIndex = 0; // a user-supplied g/y flag would otherwise carry state across texts
      const t1 = process.hrtime.bigint();
      const m = rx.exec(t);
      const d = process.hrtime.bigint() - t1;
      if (d > worst) worst = d;
      if (!m) return null;
      const s = cp(t, m.index);
      return [s, s + Array.from(m[0]).length];
    });
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    write({ i, error: null, hits, ms: Math.round(ms * 1000) / 1000,
            max_ms: Math.round(Number(worst) / 1e3) / 1000 });
  }
});
