"""`gcl conform`: Agent Control Conformance. Does a configured setting take effect?

When a real agent framework is configured with a governed setting (for example a per-tool "require
approval before it runs" setting, or a read-only data mode), does the agent honor that setting on the
operation it governs? This is ordinary configuration conformance testing: configure the component,
exercise the governed operation through a deterministic stub model on loopback (a test fixture, not a
live model), and judge ON against OFF from an INDEPENDENT observer (a file the tool writes), never
from the agent's own text.

It is a new binding on the existing paired-trial machinery in `gcl.enforce.breach` (`run_paired_trial`
and its gates: manifest, k00l liveness, allowed action, reachability, OFF calibration, completion,
verdict, stability). Nothing there is re-implemented. See `pydantic_ai_conform.py` for the first
target and what a verdict does and does not mean.
"""
