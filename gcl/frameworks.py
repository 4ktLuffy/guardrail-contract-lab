"""Which framework provisions a gcl result is evidence for, and how strongly.

This is gcl's reading of the text, kept as plain data so a reader can disagree with one
line instead of a black box. It is NOT a conformity assessment and NOT legal advice. The
rules this file follows:

  * A provision may be named only if it is in VERIFIED below: read on a primary page (or in
    the primary document) on 2026-10-12, with the URL it was read at. Nothing is added from
    memory. A test fails if a mapping row points anywhere else.
  * Every mapping row carries a one-line reason in plain English (WHY the result is evidence
    for that provision) and a strength:
        direct      the provision (or action) asks for the property this check measures,
                    or, for a risk list (OWASP), the observed outcome IS the listed risk
        supporting  the result is relevant context for the provision but does not by itself
                    show it is met (the usual case: gcl tests a guardrail integration, not
                    a whole AI system)
  * A provision gcl considered and left out is listed in NOT_MAPPED with the reason, so the
    omission is visible.
  * ISO/IEC 42001 Annex A was not readable (paid standard; iso.org blocked the fetch), so it is
    not mapped at all (ISO_42001).
  * The OWASP MCP Top 10 is in Beta: its ids are provisional.

OWASP ids come from gcl.standards, not from a second table: the ids a family can emit are
computed from standards.risks / SURFACE_RISKS / CONFIG_RISKS, so this file cannot drift
from what a report actually tags.

Sources: research sheet of 2026-10-12 (primary pages, URLs below). Two NIST AI 600-1 actions
(MS-2.6-006, MS-2.7-004) and AI Act Art 15(4) were additionally checked against the downloaded
primary texts of that research.
"""

from __future__ import annotations

from . import standards as S

SOURCES_READ = "2026-10-12"

_AIA_URL = "https://publications.europa.eu/resource/cellar/dc8116a1-3fe6-11ef-865a-01aa75ed71a1"
_OMNIBUS_URL = "https://publications.europa.eu/resource/cellar/b459c07f-86fb-11f1-bf5e-01aa75ed71a1"
_RMF_URL = "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf"
_N600_URL = "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf"
_LLM_URL = "https://genai.owasp.org/llm-top-10/"
_ASI_URL = "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
_MCP_URL = "https://owasp.org/www-project-mcp-top-10/"

DISCLAIMER = (
    "This is technical test evidence from a tool run. It is not a conformity assessment, not a statement "
    "that any law or standard is met, and not legal advice. The mapping from gcl results to provisions is "
    "gcl's own reading of the texts listed here; a lawyer or assessor may read them differently. gcl tests a "
    "guardrail integration against stand-ins, not a deployed AI system."
)

# --------------------------------------------------------------------------- verified provisions
# id -> framework, short title (as printed in the source), what it asks (paraphrase), url.
VERIFIED: dict[str, dict] = {}


def _v(pid, framework, title, asks, url, note=""):
    VERIFIED[pid] = {
        "framework": framework,
        "title": title,
        "asks": asks,
        "url": url,
        **({"note": note} if note else {}),
    }


_EU = "EU AI Act"
_v(
    "AIA:Art9(6)",
    _EU,
    "Article 9(6), Risk management system",
    "high-risk AI systems are tested to identify the most "
    "appropriate, targeted risk management measures, and the testing shows they perform consistently and comply",
    _AIA_URL,
)
_v(
    "AIA:Art9(7)",
    _EU,
    "Article 9(7), Risk management system",
    "testing procedures may include testing in real-world conditions under Article 60",
    _AIA_URL,
)
_v(
    "AIA:Art9(8)",
    _EU,
    "Article 9(8), Risk management system",
    "testing happens during development and in any event "
    "before placing on the market, against prior defined metrics and probabilistic thresholds",
    _AIA_URL,
)
_v(
    "AIA:Art10",
    _EU,
    "Article 10, Data and data governance",
    "quality criteria and governance for training, validation "
    "and testing data sets of the AI system (paras 1 and 6 amended by the Digital Omnibus, para 5 deleted)",
    _AIA_URL,
)
_v(
    "AIA:Art12(1)",
    _EU,
    "Article 12(1), Record-keeping",
    "high-risk AI systems technically allow automatic recording of events (logs) over the lifetime of the system",
    _AIA_URL,
)
_v(
    "AIA:Art13",
    _EU,
    "Article 13, Transparency and provision of information to deployers",
    "instructions and information that let deployers interpret and use the system's output",
    _AIA_URL,
)
_v(
    "AIA:Art15(1)",
    _EU,
    "Article 15(1), Accuracy, robustness and cybersecurity",
    "appropriate accuracy, robustness and cybersecurity, performed consistently throughout the lifecycle",
    _AIA_URL,
)
_v(
    "AIA:Art15(4)",
    _EU,
    "Article 15(4), Accuracy, robustness and cybersecurity",
    "systems are as resilient as possible "
    "regarding errors, faults or inconsistencies in the system or its environment; fail-safe plans are one means",
    _AIA_URL,
)
_v(
    "AIA:Art15(5)",
    _EU,
    "Article 15(5), Accuracy, robustness and cybersecurity",
    "resilience against unauthorised third "
    "parties exploiting vulnerabilities; technical solutions include measures to prevent, detect, respond to, resolve "
    "and "
    "control attacks such as data poisoning, model poisoning and adversarial examples or model evasion",
    _AIA_URL,
)
_v(
    "AIA:Art17",
    _EU,
    "Article 17, Quality management system",
    "documented quality management system (para 2 replaced by the Digital Omnibus)",
    _AIA_URL,
)
_v(
    "AIA:Art26(5)",
    _EU,
    "Article 26(5), Obligations of deployers",
    "deployers monitor operation on the basis of the instructions for use",
    _AIA_URL,
)
_v(
    "AIA:Art55(1)(a)",
    _EU,
    "Article 55(1)(a), Obligations of providers of general-purpose AI models with systemic risk",
    "providers of GPAI models with systemic risk perform model evaluation including conducting and documenting "
    "adversarial "
    "testing of the model to identify and mitigate systemic risks",
    _AIA_URL,
    "applies to providers of general-purpose AI models with systemic risk only",
)
_v(
    "AIA:Art72(2)",
    _EU,
    "Article 72(2), Post-market monitoring",
    "the post-market monitoring system actively and "
    "systematically collects, documents and analyses data on performance throughout the lifetime",
    _AIA_URL,
)
_v(
    "AIA:AnnexIV-2(g)",
    _EU,
    "Annex IV point 2(g), Technical documentation",
    "validation and testing procedures used, "
    "including test logs and all test reports dated and signed by the responsible persons",
    _AIA_URL,
)
_v(
    "AIA:AnnexIV-2(h)",
    _EU,
    "Annex IV point 2(h), Technical documentation",
    "cybersecurity measures put in place",
    _AIA_URL,
)

_RMF = "NIST AI RMF 1.0 (AI 100-1)"
_v(
    "RMF:MEASURE 2.4",
    _RMF,
    "MEASURE 2.4",
    "functionality and behavior of the system and its components are monitored when in production",
    _RMF_URL,
)
_v(
    "RMF:MEASURE 2.5",
    _RMF,
    "MEASURE 2.5",
    "the system to be deployed is demonstrated valid and reliable; limits of "
    "generalizability beyond the development conditions are documented",
    _RMF_URL,
)
_v(
    "RMF:MEASURE 2.6",
    _RMF,
    "MEASURE 2.6",
    "the system is evaluated regularly for safety risks, is demonstrated safe and "
    "can fail safely; safety metrics reflect reliability, robustness and response times for failures",
    _RMF_URL,
)
_v(
    "RMF:MEASURE 2.7",
    _RMF,
    "MEASURE 2.7",
    "security and resilience, as identified in MAP, are evaluated and documented",
    _RMF_URL,
)
_v("RMF:MEASURE 2.10", _RMF, "MEASURE 2.10", "privacy risk of the system is examined and documented", _RMF_URL)
_v("RMF:MEASURE 2.11", _RMF, "MEASURE 2.11", "fairness and bias are evaluated and documented", _RMF_URL)
_v(
    "RMF:MEASURE 2.13",
    _RMF,
    "MEASURE 2.13",
    "effectiveness of the TEVV metrics and processes is evaluated and documented",
    _RMF_URL,
)
_v(
    "RMF:MANAGE 4.1",
    _RMF,
    "MANAGE 4.1",
    "post-deployment monitoring plans are implemented, including incident response, recovery and change management",
    _RMF_URL,
)

_N6 = "NIST AI 600-1 (Generative AI Profile)"
_v(
    "N600:MS-2.6-005",
    _N6,
    "MS-2.6-005",
    "verify the architecture can monitor outputs and performance and handle, recover "
    "from and repair errors when security anomalies are detected",
    _N600_URL,
    "checked against the downloaded text",
)
_v(
    "N600:MS-2.6-006",
    _N6,
    "MS-2.6-006",
    "verify systems properly handle queries that may give rise to inappropriate, malicious or illegal usage",
    _N600_URL,
    "checked against the downloaded text",
)
_v(
    "N600:MS-2.7-001",
    _N6,
    "MS-2.7-001",
    "apply established security measures to assess likelihood and magnitude of vulnerabilities and threats",
    _N600_URL,
)
_v(
    "N600:MS-2.7-004",
    _N6,
    "MS-2.7-004",
    "identify metrics that reflect the effectiveness of security measures (including bypass)",
    _N600_URL,
)
_v(
    "N600:MS-2.7-007",
    _N6,
    "MS-2.7-007",
    "perform AI red-teaming to assess resilience against GAI attacks such as prompt "
    "injection, and other abuse and ML attacks",
    _N600_URL,
)
_v(
    "N600:MS-2.7-008",
    _N6,
    "MS-2.7-008",
    "verify fine-tuning does not compromise safety and security controls",
    _N600_URL,
)
_v(
    "N600:MS-2.7-009",
    _N6,
    "MS-2.7-009",
    "regularly assess and verify that security measures remain effective and have not been compromised",
    _N600_URL,
)

for _id, _t in {
    "LLM01:2025": "Prompt Injection",
    "LLM02:2025": "Sensitive Information Disclosure",
    "LLM03:2025": "Supply Chain",
    "LLM04:2025": "Data and Model Poisoning",
    "LLM05:2025": "Improper Output Handling",
    "LLM06:2025": "Excessive Agency",
    "LLM07:2025": "System Prompt Leakage",
    "LLM08:2025": "Vector and Embedding Weaknesses",
    "LLM09:2025": "Misinformation",
    "LLM10:2025": "Unbounded Consumption",
}.items():
    _v(_id, "OWASP Top 10 for LLM Applications 2025", _t, "risk list entry", _LLM_URL)
for _id, _t in {
    "ASI01:2026": "Agent Goal Hijack",
    "ASI02:2026": "Tool Misuse and Exploitation",
    "ASI03:2026": "Identity and Privilege Abuse",
    "ASI04:2026": "Agentic Supply Chain Vulnerabilities",
    "ASI05:2026": "Unexpected Code Execution",
    "ASI06:2026": "Memory & Context Poisoning",
    "ASI07:2026": "Insecure Inter-Agent Communication",
    "ASI08:2026": "Cascading Failures",
    "ASI09:2026": "Human-Agent Trust Exploitation",
    "ASI10:2026": "Rogue Agents",
}.items():
    _v(_id, "OWASP Top 10 for Agentic Applications 2026", _t, "risk list entry", _ASI_URL)
for _id, _t in {
    "MCP01:2025": "Token Mismanagement & Secret Exposure",
    "MCP02:2025": "Privilege Escalation via Scope Creep",
    "MCP03:2025": "Tool Poisoning",
    "MCP04:2025": "Software Supply Chain Attacks & Dependency Tampering",
    "MCP05:2025": "Command Injection & Execution",
    # The project page prints this title; gcl.standards keeps the repository file's older title for the same id.
    "MCP06:2025": "Prompt Injection via Contextual Payloads",
    "MCP07:2025": "Insufficient Authentication & Authorization",
    "MCP08:2025": "Lack of Audit and Telemetry",
    "MCP09:2025": "Shadow MCP Servers",
    "MCP10:2025": "Context Injection & Over-Sharing",
}.items():
    _v(
        _id,
        "OWASP MCP Top 10 (Beta, provisional ids)",
        _t,
        "risk list entry",
        _MCP_URL,
        "the project is in Phase 3, Beta Release and Pilot Testing: ids and titles may change",
    )

# Titles standards.py keeps that differ from the primary page (same id): checked by a test, shown in the pack.
TITLE_ALIASES = {"MCP06:2025": "Intent Flow Subversion"}

ISO_42001 = {
    "framework": "ISO/IEC 42001:2023",
    "status": "not mapped: control text not read (paid standard)",
    "detail": "iso.org returned HTTP 403 to every fetch on 2026-10-12 and the Annex A control list was not read from "
    "any "
    "primary source. No control id is cited, from memory or otherwise. Nothing in this pack is evidence for "
    "ISO/IEC 42001.",
}

PROVISIONAL_PREFIX = "MCP"  # OWASP MCP Top 10 ids are provisional (Beta)


def is_provisional(pid: str) -> bool:
    return pid.startswith(PROVISIONAL_PREFIX)


# --------------------------------------------------------------------------- check families
# The columns of the coverage matrix: what kind of check produced a result.
FAMILIES: dict[str, dict] = {
    "verdict_controls": {
        "label": "Allow / block / modify controls",
        "what": "ordinary `gcl enforce` scenarios in which the scanner says allow, block, modify or "
        "block-and-retry, input and output side",
    },
    "fail_closed": {
        "label": "Fail-closed faults",
        "what": "`gcl enforce` scenarios in which the scanner times out, errors, answers malformed, empty, "
        "wrong-schema, unknown or refused, or the policy is missing: does the request still stop",
    },
    "attack_corpus": {
        "label": "Attack corpus (--attacks)",
        "what": "`gcl enforce` scenarios sending the attack cases of the corpus, with a healthy guard and "
        "under each fault",
    },
    "stream_history": {
        "label": "Streaming and history",
        "what": "`--extra stream,history`: the attack text arrives in a streamed reply or earlier in the conversation",
    },
    "mcp_surfaces": {
        "label": "MCP surfaces",
        "what": "`--extra mcp`: tool results, errors, metadata, instructions, resources, prompts, sampling, "
        "batches and unlisted tools through an MCP gateway",
    },
    "config_applied": {
        "label": "Configuration applied",
        "what": "`--extra config`: load failures, live edits and policy scope; is the configured policy the "
        "one that runs",
    },
    "coverage_recall": {
        "label": "Detector coverage (recall)",
        "what": "`gcl coverage`: per-language recall and false positives of the detector",
    },
    "scanner_probe": {
        "label": "Scanner-failure probe",
        "what": "`gcl probe`: when the scanner fails, does the protected action still run",
    },
    "latency_race": {
        "label": "Latency and races",
        "what": "`--judge-latency`: does a result change with how long the guard takes",
    },
}

# --------------------------------------------------------------------------- the mapping
# (family, provision, strength, why). Plain English, one line each.
D, SUP = "direct", "supporting"
_ROWS: list[tuple[str, str, str, str]] = [
    # verdict controls
    (
        "verdict_controls",
        "AIA:Art9(6)",
        SUP,
        (
            "Each scenario checks that one risk-control measure (the guard) allows, blocks or rewrites "
            "what it should, observed at the model and the caller; it tests the guardrail integration, not the whole "
            "system."
        ),
    ),
    (
        "verdict_controls",
        "AIA:Art15(5)",
        SUP,
        (
            "A block that is not enforced lets a manipulative input reach the model; a hold shows "
            "the guard stops the inputs gcl sent, and only those."
        ),
    ),
    (
        "verdict_controls",
        "RMF:MEASURE 2.7",
        SUP,
        (
            "Shows whether the guard's decisions are carried out end to end, one part of "
            "evaluating and documenting security and resilience."
        ),
    ),
    # fail closed
    (
        "fail_closed",
        "AIA:Art9(6)",
        SUP,
        (
            "Injects faults into the guard and records the outcome; testing of a risk-control measure "
            "under the conditions where it is most likely to break."
        ),
    ),
    (
        "fail_closed",
        "AIA:Art15(4)",
        D,
        (
            "Art 15(4) asks for resilience against errors and faults and names fail-safe plans; this "
            "injects exactly such faults into the guard and checks the request is stopped rather than passed."
        ),
    ),
    (
        "fail_closed",
        "AIA:Art15(5)",
        SUP,
        (
            "If an outsider can make the guard fail and the request then passes, the guard is bypassed; "
            "a hold shows this particular route is closed."
        ),
    ),
    (
        "fail_closed",
        "RMF:MEASURE 2.6",
        SUP,
        (
            "MEASURE 2.6 includes that the system can fail safely; a held fault scenario shows the "
            "guard fails to a stop, not to a pass."
        ),
    ),
    (
        "fail_closed",
        "RMF:MEASURE 2.7",
        D,
        "Resilience of a security control is evaluated and the outcome documented per fault with a witness.",
    ),
    # attack corpus
    (
        "attack_corpus",
        "AIA:Art9(6)",
        SUP,
        "Runs defined attack inputs against the guard before release and records what reached the model.",
    ),
    (
        "attack_corpus",
        "AIA:Art15(5)",
        D,
        (
            "The provision names measures to prevent and control inputs designed to make a model "
            "err; the corpus sends such inputs and checks the guard's measure actually stops them."
        ),
    ),
    (
        "attack_corpus",
        "AIA:Art55(1)(a)",
        SUP,
        (
            "Adversarial testing is required of GPAI model providers with systemic risk only, and of "
            "the model; gcl tests a guardrail in front of a model, so this is context for such a provider at most."
        ),
    ),
    (
        "attack_corpus",
        "RMF:MEASURE 2.7",
        D,
        "Evaluates the security of the guard against attack inputs and documents the outcome per attack.",
    ),
    (
        "attack_corpus",
        "N600:MS-2.7-007",
        SUP,
        (
            "The action asks for red-teaming including prompt injection; a fixed corpus run by a "
            "tool is a scripted test, not human adversarial red-teaming."
        ),
    ),
    (
        "attack_corpus",
        "N600:MS-2.7-004",
        SUP,
        "Counts of attacks that bypassed the guard are a metric of how effective the security measure is.",
    ),
    (
        "attack_corpus",
        "N600:MS-2.6-006",
        D,
        (
            "The action asks to verify the system handles queries that may be malicious; each "
            "attack case checks that one is stopped."
        ),
    ),
    # stream and history
    (
        "stream_history",
        "AIA:Art9(6)",
        SUP,
        (
            "Tests the guard in two places an implementation can miss, a streamed reply and an "
            "earlier turn of the conversation."
        ),
    ),
    (
        "stream_history",
        "AIA:Art15(5)",
        SUP,
        (
            "An attack text placed where the guard does not look is a way around it; a hold shows "
            "these two placements are covered."
        ),
    ),
    ("stream_history", "RMF:MEASURE 2.7", SUP, "Extends the security evaluation to streaming and multi-turn input."),
    # mcp
    ("mcp_surfaces", "AIA:Art9(6)", SUP, "Tests the guard on each way text enters or leaves an MCP gateway."),
    (
        "mcp_surfaces",
        "AIA:Art15(5)",
        D,
        (
            "Attack text hidden in tool results, metadata, resources and the like is an input designed "
            "to make the model err; each surface checks the control stops it."
        ),
    ),
    (
        "mcp_surfaces",
        "AIA:Art55(1)(a)",
        SUP,
        (
            "Context only, and only for a GPAI-with-systemic-risk provider: injection through tool "
            "channels is a kind of adversarial input, but the object tested is the gateway, not the model."
        ),
    ),
    (
        "mcp_surfaces",
        "RMF:MEASURE 2.7",
        D,
        "Evaluates security of the tool channel and documents the outcome per surface.",
    ),
    (
        "mcp_surfaces",
        "N600:MS-2.7-007",
        SUP,
        "Prompt injection through tool channels is named by the action; again scripted payloads, not a human red team.",
    ),
    # config
    (
        "config_applied",
        "AIA:Art9(6)",
        SUP,
        (
            "Tests that the configured protection is the one that runs, a precondition for any other "
            "test of that protection."
        ),
    ),
    (
        "config_applied",
        "AIA:Art15(4)",
        SUP,
        (
            "A policy that fails to load or an edit that is ignored is a fault inside the system; a "
            "hold shows it fails to a stop and edits take effect."
        ),
    ),
    (
        "config_applied",
        "AIA:Art15(5)",
        SUP,
        "A protection that is silently not applied lets attacks through; a hold shows it applied.",
    ),
    (
        "config_applied",
        "RMF:MEASURE 2.6",
        SUP,
        "A broken policy file is a failure; the load-failure checks show whether it fails safely.",
    ),
    (
        "config_applied",
        "RMF:MEASURE 2.7",
        SUP,
        "Resilience of the security configuration (reload, scope) is evaluated and documented.",
    ),
    # coverage
    (
        "coverage_recall",
        "AIA:Art9(8)",
        SUP,
        (
            "Produces metrics (recall with an interval, false positives, per language) that testing "
            "against prior defined thresholds could use; gcl records no threshold unless you set one outside the "
            "report."
        ),
    ),
    (
        "coverage_recall",
        "RMF:MEASURE 2.5",
        SUP,
        (
            "Per-language recall shows where the detector generalises and where it does not, which "
            "is the limits-of-generalizability documentation MEASURE 2.5 mentions."
        ),
    ),
    (
        "coverage_recall",
        "N600:MS-2.7-004",
        SUP,
        "Recall is a metric of how effective the detector, a security measure, is.",
    ),
    # probe
    ("scanner_probe", "AIA:Art9(6)", SUP, "Tests the protected action under scanner failure."),
    (
        "scanner_probe",
        "AIA:Art15(4)",
        D,
        (
            "Injects scanner faults and checks the protected action does not run: the fault resilience the "
            "provision asks for."
        ),
    ),
    ("scanner_probe", "RMF:MEASURE 2.6", SUP, "A held probe shows the action fails safe when its scanner fails."),
    (
        "scanner_probe",
        "RMF:MEASURE 2.7",
        D,
        "Evaluates resilience of the security control to its own failure and records the outcome.",
    ),
    # latency
    (
        "latency_race",
        "AIA:Art9(6)",
        SUP,
        "Repeats the whole contract at several guard latencies to find timing-dependent results.",
    ),
    (
        "latency_race",
        "AIA:Art15(4)",
        SUP,
        "A result that depends on how slow the guard is, is an inconsistency under load.",
    ),
    (
        "latency_race",
        "RMF:MEASURE 2.6",
        SUP,
        (
            "MEASURE 2.6 mentions reliability, robustness and response times; this shows whether "
            "outcomes stay the same when the guard is slow."
        ),
    ),
    ("latency_race", "RMF:MEASURE 2.7", SUP, "Race conditions between check and model call are a resilience weakness."),
]

# OWASP ids a family can emit, computed from standards.py (see module docstring).
_AGENT = S.AGENT_INTEGRATIONS[0]
_MCP = S.MCP_INTEGRATIONS[0]
_OBS = S.LEAKS


def _verdict_ids(modes, stages=("input", "output")) -> list[str]:
    out: list[str] = []
    for integ in ("x", _AGENT, _MCP):
        for st in stages:
            for mode in modes:
                for obs in _OBS:
                    out += S.risks(integ, st, mode, obs, "violated")
    return list(dict.fromkeys(out))


def owasp_ids(family: str) -> list[str]:
    """The OWASP ids a violated result in this family can carry (gcl.standards decides)."""
    v = _verdict_ids(S.VERDICTS)
    f = _verdict_ids(S.FAULT_MODES)
    if family == "verdict_controls":
        return v
    if family == "fail_closed":
        return f
    if family in ("attack_corpus", "latency_race"):
        return list(dict.fromkeys(v + f))
    if family == "stream_history":
        return list(
            dict.fromkeys(_verdict_ids(("block", "error"), ("output",)) + _verdict_ids(("history_block",), ("input",)))
        )
    if family == "mcp_surfaces":
        return list(dict.fromkeys(i for ids in S.SURFACE_RISKS.values() for i in ids))
    if family == "config_applied":
        return list(dict.fromkeys(i for ids in S.CONFIG_RISKS.values() for i in ids))
    return []


def _owasp_rows() -> list[tuple[str, str, str, str]]:
    rows = []
    for fam in FAMILIES:
        for pid in owasp_ids(fam):
            t = S.TITLES.get(pid, VERIFIED[pid]["title"])
            rows.append(
                (
                    fam,
                    pid,
                    D,
                    f"gcl tags a violated {FAMILIES[fam]['label'].lower()} result with {pid} ({t}) when the "
                    "outcome is what that risk describes; a hold means that leak did not happen in these tests."
                    + (" MCP ids are provisional (Beta)." if is_provisional(pid) else ""),
                )
            )
    return rows


MAPPING: list[dict] = [dict(family=f, provision=p, strength=s, why=w) for f, p, s, w in _ROWS + _owasp_rows()]

# Provisions about the pack itself or about repeat runs: not matrix cells (no held/violated verdict exists for them).
DOCUMENTATION = [
    {
        "provision": "AIA:AnnexIV-2(g)",
        "strength": SUP,
        "why": "Annex IV asks for test logs and test reports dated and signed by the responsible persons. This pack's "
        "manifest and "
        "receipts are dated, hashed test records. They are not signed by a responsible person; the optional HMAC "
        "proves "
        "integrity to whoever holds the key, not identity.",
    },
    {
        "provision": "AIA:Art72(2)",
        "strength": SUP,
        "why": "Post-market monitoring collects and analyses performance data over the lifetime. Repeat runs of the "
        "same integration "
        "(for example after each upgrade) are one such data source; see the repeat-run table.",
    },
    {
        "provision": "N600:MS-2.7-009",
        "strength": SUP,
        "why": "The action asks to regularly assess and verify that security measures stay effective; repeat runs "
        "compared over time "
        "are that, if you keep making them.",
    },
    {
        "provision": "RMF:MEASURE 2.6",
        "strength": SUP,
        "why": "MEASURE 2.6 says evaluated regularly; the repeat-run table shows whether the inputs contain more than "
        "one run.",
    },
]

NOT_MAPPED = [
    (
        "AIA:Art9(7)",
        (
            "Asks for testing in real-world conditions as an option; gcl is an offline test against stand-ins, which "
            "is "
            "the opposite."
        ),
    ),
    (
        "AIA:Art10",
        (
            "About training, validation and testing data sets of the AI system itself (and amended by the Digital "
            "Omnibus); gcl's cases "
            "test a guardrail and are not the system's data sets."
        ),
    ),
    (
        "AIA:Art12(1)",
        (
            "Asks that the high-risk system itself can record events over its lifetime. gcl's run records are records "
            "of "
            "a test, "
            "not the system's logs, so they are not evidence for this article."
        ),
    ),
    ("AIA:Art13", "Transparency and instructions for deployers; gcl measures nothing about what is communicated."),
    (
        "AIA:Art15(1)",
        (
            "Lifecycle-wide accuracy, robustness and cybersecurity in general; too broad to attach one tool run to "
            "(the "
            "specific paragraphs 4 and 5 are mapped)."
        ),
    ),
    (
        "AIA:Art17",
        (
            "Quality management system; the Digital Omnibus replaced paragraph 2 and it was not read for testing "
            "procedures."
        ),
    ),
    ("AIA:Art26(5)", "Deployers' monitoring in operation; gcl runs offline and does not monitor a deployment."),
    (
        "AIA:AnnexIV-2(h)",
        (
            "Asks for a description of cybersecurity measures put in place; a test result is not that description (it "
            "may "
            "be "
            "attached to one)."
        ),
    ),
    ("RMF:MEASURE 2.4", "Monitoring in production; gcl is not a production monitor."),
    (
        "RMF:MANAGE 4.1",
        "Post-deployment monitoring, incident response and recovery plans; not something a test run implements.",
    ),
    ("RMF:MEASURE 2.10", "Privacy risk of the system; gcl does not assess privacy risk."),
    (
        "RMF:MEASURE 2.11",
        (
            "Fairness and bias; per-language recall is a detector measurement and is not a fairness evaluation (and "
            "the "
            "AI Act text read contains no per-language requirement)."
        ),
    ),
    (
        "RMF:MEASURE 2.13",
        (
            "Asks the organisation to evaluate its own TEVV process; gcl's controls and receipts check the tester, but "
            "that "
            "evaluation is a judgement outside the pack."
        ),
    ),
    (
        "N600:MS-2.6-005",
        "Asks to verify recovery and repair after anomalies; gcl tests fail-closed behaviour, not recovery.",
    ),
    (
        "N600:MS-2.7-001",
        (
            "Asks to assess likelihood and magnitude of threats; gcl states whether a leak happened in a test, not how "
            "likely or "
            "how large it is in operation."
        ),
    ),
    ("N600:MS-2.7-008", "Fine-tuning safety checks; not tested by gcl."),
]


def not_mapped_owasp() -> list[dict]:
    """OWASP ids that no gcl check produces: listed so the gap is visible, not hidden."""
    used = {m["provision"] for m in MAPPING}
    return [
        {
            "provision": pid,
            "title": v["title"],
            "why": "no gcl check produces this id" + (" (provisional, Beta list)" if is_provisional(pid) else ""),
        }
        for pid, v in VERIFIED.items()
        if v["framework"].startswith("OWASP") and pid not in used
    ]


# --------------------------------------------------------------------------- dates
DATES = {
    "read_on": SOURCES_READ,
    "note": "Application dates of Regulation (EU) 2024/1689 as published and as changed by Regulation (EU) 2026/1744 "
    "(Digital "
    "Omnibus on AI). Read from the Publications Office copies of the Official Journal texts; the Omnibus recitals "
    "restate "
    "the general date of 2 August 2026. This is the text as read, not a verified current consolidation.",
    "items": [
        {"what": "General date of application (Art 113)", "date": "2 August 2026", "source": _AIA_URL},
        {"what": "Chapters I and II (Art 113(a), as published)", "date": "2 February 2025", "source": _AIA_URL},
        {
            "what": "Chapters I and II after the Omnibus: Art 5(1) first subparagraph points (ba), (bb) and Art "
            "5(1a), (1b) instead",
            "date": "2 December 2026",
            "source": _OMNIBUS_URL,
        },
        {
            "what": "Chapter III Section 4, Chapter V, Chapter VII, Chapter XII and Art 78, except Art 101 (Art "
            "113(b))",
            "date": "2 August 2025",
            "source": _AIA_URL,
        },
        {
            "what": "Art 6(1) and corresponding obligations (Art 113(c), as published)",
            "date": "2 August 2027",
            "source": _AIA_URL,
        },
        {
            "what": "Omnibus: Chapter III Sections 1, 2, 3 (except Art 6(5)), Annex III high-risk systems (Art 6(2))",
            "date": "2 December 2027",
            "source": _OMNIBUS_URL,
        },
        {
            "what": "Omnibus: Chapter III Sections 1, 2, 3 (except Art 6(5)), Annex I systems (Art 6(1))",
            "date": "2 August 2028",
            "source": _OMNIBUS_URL,
        },
        {"what": "Omnibus: Articles 102 to 110 (new Art 113(d))", "date": "27 July 2026", "source": _OMNIBUS_URL},
        {
            "what": "Omnibus: generative-AI systems placed on the market before 2 August 2026 comply with Art 50(2) "
            "(new Art 111(4))",
            "date": "by 2 December 2026",
            "source": _OMNIBUS_URL,
        },
        {
            "what": "Omnibus: high-risk systems of public authorities (Art 111(2))",
            "date": "by 2 August 2030",
            "source": _OMNIBUS_URL,
        },
        {
            "what": "Omnibus: Commission guidance on the post-market monitoring plan (Art 72(3), replaced)",
            "date": "by 2 September 2027",
            "source": _OMNIBUS_URL,
        },
    ],
    "omnibus_scope": "A text search of the Omnibus found amendment headers for Arts 2, 3, 4, 5, 10, 25, 27, 47, 57, "
    "60, 75, 77, 97, "
    "99, 111 and 113, plus replacements of Art 17(2) and Art 72(3) found in its amending text, and no header for "
    "Arts 9, 12, 13, 15, 26 or 55. That is a search, not a line-by-line legal review.",
    "not_read": [
        (
            "Corrigendum to Regulation (EU) 2026/1744 dated 2026-09-29 (Publications Office record, Cellar "
            "1d32c7c2-bb9e-11f1-81de-01aa75ed71a1): NOT READ."
        ),
        (
            "Corrigenda to Regulation (EU) 2024/1689 dated 2025-10-09, 2025-12-19, 2026-03-27 and 2026-05-04, and the "
            "consolidated version "
            "dated 2026-07-27: NOT READ."
        ),
        "EUR-Lex itself was not reachable (HTTP 202, empty body); the Publications Office copies were read instead.",
    ],
    "standards": "No harmonised standard was found cited in the Official Journal. The Commission's standardisation "
    "page (read "
    "2026-10-12) says CEN and CENELEC develop them in JTC 21 under standardisation request C(2025)3871, and that "
    "prEN 18286 (quality management) entered public enquiry on 30 October 2025; it does not say any has been cited. "
    "So no presumption of conformity from a harmonised standard can be claimed here.",
    "standards_source": "https://digital-strategy.ec.europa.eu/en/policies/ai-act-standardisation",
}

FRAMEWORKS = [
    {
        "id": "eu_ai_act",
        "name": "EU AI Act, Regulation (EU) 2024/1689 as amended by Regulation (EU) 2026/1744",
        "status": "mapped (technical reading); corrigendum of 2026-09-29 not read",
        "url": _AIA_URL,
    },
    {
        "id": "nist_ai_rmf",
        "name": "NIST AI RMF 1.0 (NIST AI 100-1), 26 January 2023",
        "status": "mapped",
        "url": _RMF_URL,
    },
    {
        "id": "nist_ai_600_1",
        "name": "NIST AI 600-1 Generative AI Profile, July 2024",
        "status": "mapped",
        "url": _N600_URL,
    },
    {
        "id": "owasp_llm",
        "name": "OWASP Top 10 for LLM Applications 2025",
        "status": "mapped (ids from gcl.standards)",
        "url": _LLM_URL,
    },
    {
        "id": "owasp_agentic",
        "name": "OWASP Top 10 for Agentic Applications 2026 (December 2025)",
        "status": "mapped (ids from gcl.standards)",
        "url": _ASI_URL,
    },
    {
        "id": "owasp_mcp",
        "name": "OWASP MCP Top 10 (2025)",
        "status": "mapped, ids PROVISIONAL (Beta, Phase 3)",
        "url": _MCP_URL,
    },
    {"id": "iso_42001", "name": ISO_42001["framework"], "status": ISO_42001["status"], "url": None},
]


def framework_of(pid: str) -> str:
    return VERIFIED[pid]["framework"]
