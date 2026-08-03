"""Checked-in MCP starter-template regressions."""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


ROOT = Path(__file__).resolve().parents[1]


def test_root_mcp_template_matches_documented_read_only_default():
    template = json.loads((ROOT / ".mcp.json").read_text(encoding="utf-8"))
    example = json.loads((ROOT / ".mcp.json.example").read_text(encoding="utf-8"))

    assert template == example
    server = template["mcpServers"]["heartwood-memory"]
    assert server["command"] == "uvx"
    assert server["args"] == ["heartwood-memory"]
    assert server["env"] == {
        "HEARTWOOD_DB_PATH": "heartwood.db",
        "HEARTWOOD_TENANT": "tenant:ops",
        "HEARTWOOD_MCP_ALLOWED_TOOLS": "recall,explain_recall,health",
    }
    assert "/absolute/path/to" not in json.dumps(template)


def test_root_mcp_template_starts_in_an_uninitialized_workspace(tmp_path):
    template = json.loads((ROOT / ".mcp.json").read_text(encoding="utf-8"))
    server = template["mcpServers"]["heartwood-memory"]

    async def start_and_list_tools() -> list[str]:
        clean_env = {
            key: os.environ[key]
            for key in ("HOME", "PATH", "TMPDIR", "SYSTEMROOT")
            if key in os.environ
        }
        clean_env.update(server["env"])
        clean_env.update(
            {
                "HF_HOME": str(tmp_path / "hf-cache"),
                "HF_HUB_OFFLINE": "1",
                "PYTHONPATH": str(ROOT),
                "TRANSFORMERS_OFFLINE": "1",
            }
        )
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "heartwood.adapters.mcp_server"],
            env=clean_env,
            cwd=tmp_path,
        )
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                return sorted(tool.name for tool in tools.tools)

    assert not (tmp_path / "heartwood.db").exists()
    assert asyncio.run(start_and_list_tools()) == ["explain_recall", "health", "recall"]
    assert (tmp_path / "heartwood.db").is_file()
