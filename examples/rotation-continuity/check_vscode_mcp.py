#!/usr/bin/env python3
"""Exercise the workspace VS Code MCP command against a demo store."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db-path", type=Path, required=True)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


async def run_check(args: argparse.Namespace) -> dict[str, Any]:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    env = os.environ.copy()
    env.update(
        {
            "PYTHONPATH": str(ROOT),
            "HEARTWOOD_DB_PATH": str(args.db_path.expanduser().resolve()),
            "HEARTWOOD_TENANT": "tenant:rotation-continuity-demo",
            "HEARTWOOD_MCP_ALLOWED_TOOLS": "recall,explain_recall,health",
        }
    )
    params = StdioServerParameters(
        command=str(Path(args.python).expanduser().resolve()),
        args=[str(ROOT / "examples" / "rotation-continuity" / "mcp_server.py")],
        env=env,
    )
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            initialized = await session.initialize()
            listed = await session.list_tools()
            tools = sorted(tool.name for tool in listed.tools)
            health = await session.call_tool("health", {})
            health_payload = _tool_payload(health)
            recall = await session.call_tool(
                "recall",
                {
                    "cue": "Project Juniper release decision security approval region",
                    "principal_id": "agent:rotation-continuity-demo",
                    "roles": ["release-manager"],
                    "clearance": "confidential",
                    "subject": "project:juniper",
                    "k": 5,
                },
            )
            recall_payload = _tool_payload(recall)

    expected_tools = ["explain_recall", "health", "recall"]
    result_ids = sorted(row["id"] for row in recall_payload["results"])
    expected_ids = [
        "mem:rotation-demo:juniper-region",
        "mem:rotation-demo:juniper-release-policy",
    ]
    receipt = {
        "status": "PASS",
        "transport": "stdio",
        "command": str(Path(args.python).expanduser().resolve()),
        "args": [str(ROOT / "examples" / "rotation-continuity" / "mcp_server.py")],
        "server_name": initialized.serverInfo.name,
        "server_version": initialized.serverInfo.version,
        "tools": tools,
        "expected_tools": expected_tools,
        "fail_closed_read_only_allowlist": tools == expected_tools,
        "health_ok": health_payload.get("ok") is True,
        "recall_result_ids": result_ids,
        "expected_result_ids": expected_ids,
        "recall_matches_demo_store": result_ids == expected_ids,
        "db_path": str(args.db_path.expanduser().resolve()),
    }
    if not all(
        (
            receipt["fail_closed_read_only_allowlist"],
            receipt["health_ok"],
            receipt["recall_matches_demo_store"],
        )
    ):
        raise AssertionError(json.dumps(receipt, indent=2))
    return receipt


def _tool_payload(result: Any) -> dict[str, Any]:
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        return structured
    for block in getattr(result, "content", ()):
        text = getattr(block, "text", None)
        if text:
            payload = json.loads(text)
            if isinstance(payload, dict):
                return payload
    raise AssertionError("MCP tool did not return a JSON object")


def main() -> int:
    args = parse_args()
    receipt = asyncio.run(run_check(args))
    rendered = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
