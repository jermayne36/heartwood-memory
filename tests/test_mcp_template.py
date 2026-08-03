"""Checked-in MCP starter-template regressions."""
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_root_mcp_template_matches_documented_read_only_default():
    template = json.loads((ROOT / ".mcp.json").read_text(encoding="utf-8"))
    example = json.loads((ROOT / ".mcp.json.example").read_text(encoding="utf-8"))

    assert template == example
    server = template["mcpServers"]["heartwood-memory"]
    assert server["command"] == "uvx"
    assert server["args"] == ["heartwood-memory"]
    assert server["env"] == {
        "HEARTWOOD_DB_PATH": ".heartwood/heartwood.db",
        "HEARTWOOD_TENANT": "tenant:ops",
        "HEARTWOOD_MCP_ALLOWED_TOOLS": "recall,explain_recall,health",
    }
    assert "/absolute/path/to" not in json.dumps(template)
