import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
EX = ROOT / "examples"

needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


@pytest.fixture
def tmp_rules(tmp_path):
    """Write a YAML rule file from a dict of {id: pattern} (one category)."""
    def make(rules: dict, lang: dict | None = None, name="rules.yaml"):
        lines = ["rules:"]
        for rid, pat in rules.items():
            lines.append(f"  - id: {rid}")
            lines.append("    pattern: '" + pat.replace("'", "''") + "'")
            if lang and rid in lang:
                lines.append(f"    lang: {lang[rid]}")
        p = tmp_path / name
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return p
    return make
