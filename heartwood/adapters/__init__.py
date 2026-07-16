"""Adapters that expose Heartwood through standard agent interfaces.

- memory_tool: Anthropic Memory Tool (memory_20250818) backend.
- mcp_server: an MCP server exposing Heartwood verbs, trust controls, and
  memory-tool file ops.

The pitch: agent frameworks store memory; Heartwood stores it *with lineage, policy,
and erasure*. These adapters make Heartwood a drop-in governed backend.
"""
from importlib import import_module

from .hermes import HeartwoodHermesMemoryProvider
from .memory_tool import MemoryToolBackend
from .openclaw import HeartwoodOpenClawMemoryRuntime


_MCP_EXPORTS = {"MCPMemoryAPI", "allowed_tools_from_env", "build_server", "mcp_server"}


def __getattr__(name: str):
    """Load MCP exports lazily so ``python -m ...mcp_server`` stays warning-free."""
    if name not in _MCP_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = import_module(f"{__name__}.mcp_server")
    return module if name == "mcp_server" else getattr(module, name)


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
