#!/usr/bin/env python3
"""Exercise the workspace VS Code MCP command against a demo store."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import runpy
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
MCP_SERVER_ENV_KEYS = (
    "HEARTWOOD_DB_PATH",
    "HEARTWOOD_MCP_ALLOWED_TOOLS",
    "HEARTWOOD_TENANT",
    "PYTHONPATH",
)
PLATFORM_RUNTIME_ENV_KEYS = (
    "LC_CTYPE",
    "__CF_USER_TEXT_ENCODING",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db-path", type=Path, required=True)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


async def run_check(args: argparse.Namespace) -> dict[str, Any]:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    configured_env = {
        "PYTHONPATH": str(ROOT),
        "HEARTWOOD_DB_PATH": str(args.db_path.expanduser().resolve()),
        "HEARTWOOD_TENANT": "tenant:rotation-continuity-demo",
        "HEARTWOOD_MCP_ALLOWED_TOOLS": "recall,explain_recall,health",
    }
    with tempfile.TemporaryDirectory(prefix="heartwood-mcp-env-receipt-") as temp_dir:
        environment_receipt = Path(temp_dir) / "effective-environment.json"
        params = StdioServerParameters(
            command=str(Path(args.python).expanduser().resolve()),
            args=[
                str(Path(__file__).resolve()),
                "--launch-server",
                str(environment_receipt),
            ],
            env=configured_env,
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
        environment_probe = json.loads(
            environment_receipt.read_text(encoding="utf-8")
        )
        effective_environment_keys = environment_probe[
            "effective_server_environment_keys"
        ]

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
        "configured_environment_keys": sorted(configured_env),
        "exec_input_environment_keys": sorted(configured_env),
        "post_start_environment_keys_before_sanitize": environment_probe[
            "post_start_environment_keys_before_sanitize"
        ],
        "platform_runtime_environment_keys_removed": environment_probe[
            "platform_runtime_environment_keys_removed"
        ],
        "effective_server_environment_keys": effective_environment_keys,
        "unexpected_post_start_environment_keys": environment_probe[
            "unexpected_post_start_environment_keys"
        ],
        "environment_reset": "post_start_sanitize_before_server_init",
        "effective_environment_matches_allowlist": (
            effective_environment_keys == sorted(MCP_SERVER_ENV_KEYS)
        ),
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
            receipt["effective_environment_matches_allowlist"],
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


def _launch_server(environment_receipt: Path) -> int:
    effective_env = {key: os.environ[key] for key in MCP_SERVER_ENV_KEYS}
    launcher = Path(__file__).resolve()
    os.execve(
        sys.executable,
        [
            sys.executable,
            str(launcher),
            "--serve-and-probe",
            str(environment_receipt),
        ],
        effective_env,
    )
    raise AssertionError("os.execve returned unexpectedly")


def _serve_and_probe(environment_receipt: Path) -> int:
    before_sanitize = sorted(os.environ)
    removed = sorted(
        key for key in PLATFORM_RUNTIME_ENV_KEYS if os.environ.pop(key, None) is not None
    )
    effective = sorted(os.environ)
    unexpected = sorted(set(effective) - set(MCP_SERVER_ENV_KEYS))
    environment_receipt.write_text(
        json.dumps(
            {
                "post_start_environment_keys_before_sanitize": before_sanitize,
                "platform_runtime_environment_keys_removed": removed,
                "effective_server_environment_keys": effective,
                "unexpected_post_start_environment_keys": unexpected,
            }
        ),
        encoding="utf-8",
    )
    if effective != sorted(MCP_SERVER_ENV_KEYS):
        raise AssertionError(
            "effective MCP server environment does not match the reviewed allowlist"
        )
    server = ROOT / "examples" / "rotation-continuity" / "mcp_server.py"
    runpy.run_path(str(server), run_name="__main__")
    return 0


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--launch-server":
        return _launch_server(Path(sys.argv[2]).expanduser().resolve())
    if len(sys.argv) == 3 and sys.argv[1] == "--serve-and-probe":
        return _serve_and_probe(Path(sys.argv[2]).expanduser().resolve())
    args = parse_args()
    receipt = asyncio.run(run_check(args))
    rendered = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
