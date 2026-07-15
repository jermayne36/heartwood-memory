"""Adapters that expose Heartwood through standard agent interfaces.

- memory_tool: Anthropic Memory Tool (memory_20250818) backend.
- mcp_server: an MCP server exposing Heartwood verbs, trust controls, and
  memory-tool file ops.

The pitch: agent frameworks store memory; Heartwood stores it *with lineage, policy,
and erasure*. These adapters make Heartwood a drop-in governed backend.
"""
from .hermes import HeartwoodHermesMemoryProvider
from .memory_tool import MemoryToolBackend
from .mcp_server import MCPMemoryAPI, allowed_tools_from_env, build_server
from .openclaw import HeartwoodOpenClawMemoryRuntime
from . import mcp_server


def route_tool_use(backend: "MemoryToolBackend", tool_use) -> dict:
    """Turn an Anthropic `memory` tool_use block into a tool_result dict.

    Works with either an SDK content block (``.input`` / ``.id``) or a plain dict.
    """
    inp = tool_use["input"] if isinstance(tool_use, dict) else tool_use.input
    tid = tool_use["id"] if isinstance(tool_use, dict) else tool_use.id
    return {"type": "tool_result", "tool_use_id": tid, "content": backend.handle(dict(inp))}


__all__ = [
    "HeartwoodHermesMemoryProvider",
    "HeartwoodOpenClawMemoryRuntime",
    "MCPMemoryAPI",
    "MemoryToolBackend",
    "allowed_tools_from_env",
    "build_server",
    "mcp_server",
    "route_tool_use",
]
