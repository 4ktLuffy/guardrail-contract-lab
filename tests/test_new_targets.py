"""The Coralogix (Aporia) LangChain adapter's guard protocol and the LlamaFirewall judge."""

import json

from gcl.enforce.adapters import ADAPTERS, CORALOGIX_VALIDATE, LLAMAFIREWALL_PII
from gcl.enforce.servers import _path_ok


def test_coralogix_protocol_stages_by_validation_target_on_one_url():
    p = CORALOGIX_VALIDATE
    assert p.stage_of({"validation_target": "prompt"}) == "input"
    assert p.stage_of({"validation_target": "response"}) == "output"
    assert p.stage_of({}) is None and p.single_listener
    assert _path_ok(p, "/gcl-project/validate") and not _path_ok(p, "/gcl-project/other")
    assert p.verdicts["block"]({}, "")["action"] == "block"
    assert p.verdicts["modify"]({}, "x") == {"action": "modify", "revised_response": "x"}
    assert p.scanned({"validation_target": "response", "response": "R"}) == "R"
    assert "hello" in p.scanned({"validation_target": "prompt", "messages": [{"content": "hello"}]})
    assert p.provenance == "client_code"           # the vendor API, rebuilt from the client's schema


def test_llamafirewall_judge_is_the_libraries_own_schema():
    p = LLAMAFIREWALL_PII
    assert p.shared_endpoint and p.provenance == "integration"
    assert json.loads(json.dumps(p.verdicts["block"]({}, ""))) == {"detected_pii_types": ["EMAIL"]}
    assert ADAPTERS["llamafirewall"].capabilities == {"input"}
    assert {"stream", "history"} <= ADAPTERS["coralogix-langchain"].capabilities
