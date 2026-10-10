"""`gcl enforce`: does a real guardrail integration enforce what its scanner decides?

`probe` asks the question for a system you wrap yourself. `enforce` asks it for real
integrations (LiteLLM proxy guardrails, NeMo Guardrails rails), driving their own code
paths end to end: a scripted stand-in scanner gives each verdict or fault, and two
independent observers record what actually happened — a mock model server (did the
request reach the model?) and the client (what came back?). The adapters only translate
protocols; they never interpret a verdict themselves, so a pass can't be manufactured by
the harness.

Two separate questions are answered for every scenario:

  * policy — does the behaviour meet a strict fail-closed policy (blocked, faulty or
    unparseable verdicts must stop the request)?
  * documented — does it match what the integration itself documents for this
    configuration? A policy violation that the integration documents (a fail-open
    option you enabled) is reported as configuration, not as a bug.
"""
