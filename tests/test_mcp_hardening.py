"""Phase 1 B4 MCP hardening tests."""
import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp.exceptions import ToolError  # noqa: E402

from heartwood import Heartwood, __version__  # noqa: E402
from heartwood.adapters.mcp_server import (  # noqa: E402
    MCPMemoryAPI,
    _mutating_exposure_warning,
    allowed_tools_from_env,
    build_server,
)
from heartwood.importers.markdown import dev_models  # noqa: E402
from heartwood.policy import Principal  # noqa: E402


def _api(path: Path) -> MCPMemoryAPI:
    embedder, reranker = dev_models()
    return MCPMemoryAPI(
        Heartwood(
            path=path,
            tenant="tenant:ops",
            embedder=embedder,
            reranker=reranker,
        )
    )


def _tool(server, name: str, arguments: dict):
    output = asyncio.run(server.call_tool(name, arguments))
    if isinstance(output, dict):
        return output
    if isinstance(output, tuple):
        return output[1]
    return json.loads(output[0].text)


def test_mcp_governed_tenant_recall_and_no_denied_side_channel():
    with tempfile.TemporaryDirectory() as temp_dir:
        from test_receipts import _db
        db, _, _, _ = _db(Path(temp_dir), tenant="tenant:northwind-retail")
        api = MCPMemoryAPI(db)
        try:
            # The operator seeds through the trusted Python facade.
            saved = api.remember(
                "Northwind Retail auth changes require finance approval before shipping.",
                subject="northwind-retail:auth",
                tenant="northwind-retail",
                created_by="agent:reviewer",
                classification="confidential",
                roles=["finance"],
                source_uri="doc://northwind-retail/auth-approval",
            )
            assert saved["ok"] is True
            assert saved["tenant"] == "tenant:northwind-retail"
            assert saved["classification"] == "confidential"

            # MCP clients recall through tools as the server's configured principal.
            ops, _, _ = build_server(
                db, principal=Principal("agent:ops", db.tenant, clearance="confidential")
            )
            no_role = _tool(ops, "recall", {"cue": "auth changes finance approval"})
            assert no_role["ok"] is True
            assert no_role["result_count"] == 0
            assert no_role["receipt"]["schema"] == "heartwood.recall-receipt.v2"
            assert "denied" not in json.dumps(no_role).lower()

            # A client cannot claim the finance role the server was not given.
            try:
                claimed = _tool(ops, "recall", {"cue": "auth changes finance approval", "roles": ["finance"]})
            except ToolError as exc:
                assert "roles cannot be set by an MCP client" in str(exc)
            else:
                raise AssertionError(f"client-chosen roles were accepted: {claimed}")

            finance_server, _, _ = build_server(
                db,
                principal=Principal(
                    "agent:finance", db.tenant, roles=("finance",), clearance="confidential"
                ),
            )
            finance = _tool(finance_server, "recall", {"cue": "auth changes finance approval"})
            assert finance["result_count"] == 1
            result = finance["results"][0]
            assert result["id"] == saved["id"]
            assert result["classification"] == "confidential"
            assert list(result["source_ids"]) == ["doc://northwind-retail/auth-approval"]
            assert result["provenance_valid"] is True
            assert result["content_hash_match"] is True

            explain = _tool(finance_server, "explain_recall", {"recall_id": finance["recall_id"]})
            assert "denied" not in json.dumps(explain).lower()

            receipt = api.forget(
                "northwind-retail:auth",
                tenant="northwind-retail",
                actor="agent:mcp",
                reason="test erasure",
            )
            assert receipt["purged"] == 1
            after = _tool(finance_server, "recall", {"cue": "auth changes finance approval"})
            assert after["results"] == []
        finally:
            api.close()


def test_mcp_memory_tool_surface_still_confined():
    with tempfile.TemporaryDirectory() as temp_dir:
        api = _api(Path(temp_dir) / "heartwood.db")
        try:
            assert api.memory("view", path="/etc/passwd").startswith("Error")
            created = api.memory(
                "create",
                tenant="ops",
                path="/memories/runbook.md",
                file_text="Runbook: preserve provenance before recall cutover.",
            )
            assert created == "File created successfully at: /memories/runbook.md"
            listing = api.memory("view", tenant="ops", path="/memories")
            assert "/memories/runbook.md" in listing
            health = api.health()
            assert health["ok"] is True
            assert "tenant:ops" in health["tenants"]
        finally:
            api.close()


def test_r2_mcp_allowed_tools_env_recall_only():
    assert allowed_tools_from_env("recall,health") == {"recall", "health"}
    # ASA A4 fix: empty/unset is treated as "unspecified" and fails CLOSED to the
    # read-only subset (previously returned None == full fail-open surface).
    assert allowed_tools_from_env("") == {"recall", "explain_recall", "health"}
    try:
        allowed_tools_from_env("recall,remember_all")
        raise AssertionError("unknown allowlist entries should fail closed")
    except ValueError as exc:
        assert "remember_all" in str(exc)


def test_a4_mcp_allowlist_fail_closed_default():
    """ASA A4: an unset/empty allowlist must NOT expose destructive verbs."""
    saved = os.environ.pop("HEARTWOOD_MCP_ALLOWED_TOOLS", None)
    try:
        default = allowed_tools_from_env()  # resolves with env genuinely unset
    finally:
        if saved is not None:
            os.environ["HEARTWOOD_MCP_ALLOWED_TOOLS"] = saved

    # Criterion 1: forget, remember, and the /memories mutation verb are absent.
    assert "forget" not in default
    assert "remember" not in default
    assert "memory" not in default
    # Criterion 2: the read-only subset IS available by default.
    assert default == {"recall", "explain_recall", "health"}

    # Criterion 3: destructive verbs require explicit opt-in — naming forget
    # exposes it; not naming it does not. (the gate)
    assert "forget" not in allowed_tools_from_env("recall,explain_recall,health")
    assert "forget" in allowed_tools_from_env("recall,explain_recall,forget,health")

    # Criterion 4: an explicit allowlist is honored verbatim (deployments unchanged).
    assert allowed_tools_from_env("recall,forget") == {"recall", "forget"}

    # Fail-loud defense-in-depth: the safe default warns nothing; an explicit
    # destructive opt-in surfaces an irreversible-erasure warning to stderr.
    assert _mutating_exposure_warning(default) is None
    warn = _mutating_exposure_warning(allowed_tools_from_env("recall,forget"))
    assert warn is not None and "forget" in warn and "irreversible" in warn


def test_mcp_forget_rejects_unknown_mode():
    with tempfile.TemporaryDirectory() as temp_dir:
        api = _api(Path(temp_dir) / "heartwood.db")
        try:
            api.remember(
                "Delete this MCP customer preference only when mode is supported.",
                subject="customer:mcp-erase",
                created_by="agent:test",
            )
            receipt = api.forget("customer:mcp-erase", mode="soft", actor="agent:mcp", reason="DSAR")
            assert receipt["ok"] is False
            assert "unsupported forget mode" in receipt["error"]
            assert receipt["mode"] == "soft"

            after = api.recall(
                "MCP customer preference",
                principal_id="agent:test",
                subject="customer:mcp-erase",
            )
            assert after["result_count"] >= 1
        finally:
            api.close()


def test_mcp_initialize_reports_heartwood_version():
    mcp, db, _backend = build_server()
    try:
        assert mcp._mcp_server.version == __version__
    finally:
        db.close()


def main():
    test_mcp_governed_tenant_recall_and_no_denied_side_channel()
    test_mcp_memory_tool_surface_still_confined()
    test_r2_mcp_allowed_tools_env_recall_only()
    test_a4_mcp_allowlist_fail_closed_default()
    test_mcp_forget_rejects_unknown_mode()
    test_mcp_initialize_reports_heartwood_version()
    print("MCP HARDENING TESTS PASSED")


if __name__ == "__main__":
    main()
