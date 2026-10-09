"""MCP clients cannot choose the tenant or principal a tool call runs as.

Every hostile call below would read or erase a synthetic canary if the server
accepted the identity argument. The assertions check the canary first, so a
regression fails by showing the leaked text.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.fastmcp.exceptions import ToolError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Heartwood  # noqa: E402
from heartwood.adapters.mcp_server import build_server  # noqa: E402
from heartwood.envelope import Policy  # noqa: E402
from heartwood.importers.markdown import dev_models  # noqa: E402
from heartwood.policy import Principal  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TENANT = "tenant:acme"
OTHER_TENANT = "tenant:globex"
CUE = "launch codename canary"
ALL_TOOLS = "remember,recall,explain_recall,forget,evaluate_egress,assess_faithfulness,memory,health"
# Literal copy, so this file imports on a build that predates the binding.
IDENTITY_ARGUMENTS = {"tenant", "principal_id", "roles", "attrs", "clearance", "created_by", "actor"}

BASELINE = "PUBLIC-BASELINE"
GLOBEX = "GLOBEX-CANARY"
FINANCE = "FINANCE-CANARY"
RESTRICTED = "RESTRICTED-CANARY"
ATTR = "ATTR-CANARY"
PRIVATE = "PRIVATE-CANARY"
ACME_CANARIES = (FINANCE, RESTRICTED, ATTR, PRIVATE)


@pytest.fixture()
def store(tmp_path):
    embedder, reranker = dev_models()
    db = Heartwood(path=tmp_path / "heartwood.db", tenant=TENANT, embedder=embedder, reranker=reranker)
    other = db.with_tenant(OTHER_TENANT)
    try:
        other.remember(f"{GLOBEX} {CUE} for Globex only.", subject="globex:launch", created_by="agent:globex")
    finally:
        other.close()
    seeds = (
        (BASELINE, "agent:writer", Policy()),
        (FINANCE, "agent:writer", Policy(roles=("finance",))),
        (RESTRICTED, "agent:writer", Policy(classification="restricted")),
        (ATTR, "agent:writer", Policy(attrs=(("region", "eu"),))),
        (PRIVATE, "agent:alice", Policy(visibility="private")),
    )
    for marker, author, policy in seeds:
        db.remember(f"{marker} {CUE} for Acme.", subject="acme:launch", created_by=author, policy=policy)
    try:
        yield db
    finally:
        db.close()


def _call(server, name, arguments):
    output = asyncio.run(server.call_tool(name, arguments))
    if isinstance(output, dict):
        return output
    if isinstance(output, tuple):
        return output[1]
    text = output[0].text
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _attempt(server, name, arguments):
    try:
        return _call(server, name, arguments)
    except ToolError as exc:
        return exc


def _contents(response) -> str:
    return " ".join(row["content"] for row in response["results"])


def _globex_contents(db) -> str:
    other = db.with_tenant(OTHER_TENANT)
    try:
        out = other.recall(CUE, principal=Principal("agent:audit", OTHER_TENANT), k=8)
        return " ".join(row["content"] for row in out["results"])
    finally:
        other.close()


@pytest.mark.parametrize(
    ("hostile", "canary"),
    [
        ({"tenant": OTHER_TENANT}, GLOBEX),
        ({"roles": ["finance"]}, FINANCE),
        ({"clearance": "restricted"}, RESTRICTED),
        ({"attrs": {"region": "eu"}}, ATTR),
        ({"principal_id": "agent:alice"}, PRIVATE),
    ],
    ids=["tenant", "roles", "clearance", "attrs", "principal_id"],
)
def test_recall_rejects_client_identity_and_leaks_no_canary(store, hostile, canary):
    """@positive-control(mcp-principal-arguments)"""
    server, _db, _backend = build_server(store)

    control = _call(server, "recall", {"cue": CUE, "k": 8})
    assert BASELINE in _contents(control)
    assert canary not in json.dumps(control)

    outcome = _attempt(server, "recall", {"cue": CUE, "k": 8, **hostile})
    assert canary not in json.dumps(outcome, default=str)
    assert isinstance(outcome, ToolError), outcome
    (name,) = hostile
    assert f"recall: {name} cannot be set by an MCP client" in str(outcome)


def test_mutating_tools_cannot_cross_tenant_or_claim_identity(store, monkeypatch):
    """@positive-control(mcp-principal-arguments)"""
    monkeypatch.setenv("HEARTWOOD_MCP_ALLOWED_TOOLS", ALL_TOOLS)
    server, _db, _backend = build_server(store)

    erase = _attempt(server, "forget", {"subject": "globex:launch", "tenant": OTHER_TENANT})
    assert GLOBEX in _globex_contents(store)
    assert isinstance(erase, ToolError), erase

    write = _attempt(server, "remember", {"content": f"POISON {CUE}", "subject": "globex:launch",
                                          "tenant": OTHER_TENANT})
    assert "POISON" not in _globex_contents(store)
    assert isinstance(write, ToolError), write

    for name, arguments in (
        ("remember", {"content": f"{CUE} note", "subject": "acme:note", "created_by": "human:owner"}),
        ("remember", {"content": f"{CUE} note", "subject": "acme:note", "roles": ["finance"]}),
        ("forget", {"subject": "acme:launch", "actor": "human:owner"}),
        ("memory", {"command": "view", "path": "/memories", "tenant": OTHER_TENANT}),
        ("explain_recall", {"recall_id": "recall_x", "tenant": OTHER_TENANT}),
        ("evaluate_egress", {"request": {}, "tenant": OTHER_TENANT}),
        ("assess_faithfulness", {"candidate": {}, "tenant": OTHER_TENANT}),
    ):
        outcome = _attempt(server, name, arguments)
        assert isinstance(outcome, ToolError), (name, outcome)
        assert "cannot be set by an MCP client" in str(outcome)
    assert BASELINE in _contents(_call(server, "recall", {"cue": CUE, "k": 8}))


def test_unknown_tool_arguments_are_rejected_not_ignored(store):
    server, _db, _backend = build_server(store)
    outcome = _attempt(server, "recall", {"cue": CUE, "topc": 200})
    assert isinstance(outcome, ToolError), outcome
    assert "recall: unknown arguments: topc" in str(outcome)


def test_tool_schemas_carry_no_identity_arguments(store, monkeypatch):
    monkeypatch.setenv("HEARTWOOD_MCP_ALLOWED_TOOLS", ALL_TOOLS)
    server, _db, _backend = build_server(store)
    tools = asyncio.run(server.list_tools())
    assert sorted(tool.name for tool in tools) == sorted(ALL_TOOLS.split(","))
    for tool in tools:
        assert not IDENTITY_ARGUMENTS & set(tool.inputSchema.get("properties", {})), tool.name
        assert tool.inputSchema["additionalProperties"] is False, tool.name


def test_configured_principal_is_the_only_source_of_access(store, monkeypatch):
    finance = Principal("agent:finance-bot", TENANT, roles=("finance",))
    server, _db, _backend = build_server(store, principal=finance)
    seen = _contents(_call(server, "recall", {"cue": CUE, "k": 8}))
    assert FINANCE in seen and BASELINE in seen
    assert not any(marker in seen for marker in (RESTRICTED, ATTR, PRIVATE, GLOBEX))

    monkeypatch.setenv("HEARTWOOD_MCP_PRINCIPAL_ID", "agent:alice")
    monkeypatch.setenv("HEARTWOOD_MCP_ROLES", "finance,support")
    monkeypatch.setenv("HEARTWOOD_MCP_ATTRS", "region=eu")
    monkeypatch.setenv("HEARTWOOD_MCP_CLEARANCE", "restricted")
    server, _db, _backend = build_server(store)
    seen = _contents(_call(server, "recall", {"cue": CUE, "k": 8}))
    assert all(marker in seen for marker in ACME_CANARIES)
    assert GLOBEX not in seen


def test_misconfigured_principal_fails_closed_at_startup(store, monkeypatch):
    with pytest.raises(ValueError, match="does not match the store tenant"):
        build_server(store, principal=Principal("agent:x", OTHER_TENANT))
    # An unprefixed tenant could never match a recall principal; refuse to start.
    embedder, reranker = dev_models()
    bare = Heartwood(path=":memory:", tenant="acme", embedder=embedder, reranker=reranker)
    try:
        with pytest.raises(ValueError, match="Set HEARTWOOD_TENANT=tenant:acme"):
            build_server(bare)
    finally:
        bare.close()
    monkeypatch.setenv("HEARTWOOD_MCP_CLEARANCE", "top-secret")
    with pytest.raises(ValueError, match="Unknown MCP principal clearance 'top-secret'"):
        build_server(store)
    monkeypatch.setenv("HEARTWOOD_MCP_CLEARANCE", "internal")
    monkeypatch.setenv("HEARTWOOD_MCP_ATTRS", "region")
    with pytest.raises(ValueError, match="attribute must be key=value"):
        build_server(store)


def test_stdio_client_gets_an_error_for_a_client_chosen_tenant(tmp_path):
    """The rejection holds over the real MCP transport, not only in-process."""

    async def session_receipts():
        env = {key: os.environ[key] for key in ("HOME", "PATH", "TMPDIR", "SYSTEMROOT") if key in os.environ}
        env.update({
            "HEARTWOOD_DB_PATH": str(tmp_path / "heartwood.db"),
            "HEARTWOOD_TENANT": TENANT,
            "HF_HOME": str(tmp_path / "hf-cache"),
            "HF_HUB_OFFLINE": "1",
            "PYTHONPATH": str(ROOT),
            "TRANSFORMERS_OFFLINE": "1",
        })
        parameters = StdioServerParameters(
            command=sys.executable, args=["-m", "heartwood.adapters.mcp_server"], env=env, cwd=tmp_path,
        )
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                schema = next(t for t in (await session.list_tools()).tools if t.name == "recall").inputSchema
                assert "tenant" not in schema["properties"]
                assert schema["additionalProperties"] is False
                result = await session.call_tool("recall", {"cue": CUE, "tenant": OTHER_TENANT})
                return result.isError, " ".join(getattr(block, "text", "") for block in result.content)

    is_error, text = asyncio.run(session_receipts())
    assert is_error is True
    assert "recall: tenant cannot be set by an MCP client" in text
