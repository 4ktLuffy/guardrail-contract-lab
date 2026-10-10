"""Out-of-process Python `re` runner. Protocol: one JSON request on stdin, then one
JSON line per pattern on stdout (so the parent can tell which pattern hung)."""
import json
import re
import sys
import time

FLAG_BITS = {"I": re.IGNORECASE, "M": re.MULTILINE, "S": re.DOTALL, "X": re.VERBOSE,
             "A": re.ASCII, "U": re.UNICODE}


def main():
    req = json.loads(sys.stdin.read())
    def bits(spec):
        b = 0
        for ch in spec.upper():
            b |= FLAG_BITS[ch]
        return b

    flags = bits(req.get("flags", "IM"))
    per_flags = req.get("pattern_flags")
    out = sys.stdout
    out.write(json.dumps({"meta": {"engine": "python-re", "version": sys.version.split()[0],
                                    "flags": req.get("flags", "IM")}}) + "\n")
    out.flush()
    texts = req["texts"]
    pats = req["patterns"]
    for i in range(req.get("start", 0), len(pats)):
        t0 = time.perf_counter()
        try:
            f = flags if not per_flags or per_flags[i] is None else bits(per_flags[i])
            rx = re.compile(pats[i], f)
        except (re.error, ValueError, OverflowError, RecursionError, KeyError) as e:
            out.write(json.dumps({"i": i, "error": f"{type(e).__name__}: {e}"}) + "\n")
            out.flush()
            continue
        hits, worst = [], 0.0
        for t in (req["per_pattern_texts"][i] if "per_pattern_texts" in req else texts):
            t1 = time.perf_counter()
            m = rx.search(t)
            worst = max(worst, time.perf_counter() - t1)
            hits.append([m.start(), m.end()] if m else None)
        out.write(json.dumps({"i": i, "error": None, "hits": hits,
                              "ms": round((time.perf_counter() - t0) * 1000, 3),
                              "max_ms": round(worst * 1000, 3)}) + "\n")
        out.flush()


main()
