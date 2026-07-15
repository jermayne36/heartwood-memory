"""Phase 1 B4 MCP hardening tests."""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Heartwood  # noqa: E402
from heartwood.adapters.mcp_server import (  # noqa: E402
    MCPMemoryAPI,
    _mutating_exposure_warning,
    allowed_tools_from_env,
)
from heartwood.importers.markdown import dev_models  # noqa: E402


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


def test_mcp_governed_tenant_recall_and_no_denied_side_channel():
    with tempfile.TemporaryDirectory() as temp_dir:
        api = _api(Path(temp_dir) / "heartwood.db")
        try:
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

            no_role = api.recall(
                "auth changes finance approval",
                tenant="northwind-retail",
                principal_id="agent:ops",
                clearance="confidential",
            )
            assert no_role["ok"] is True
            assert no_role["result_count"] == 0
            assert "denied" not in json.dumps(no_role).lower()

            finance = api.recall(
                "auth changes finance approval",
                tenant="northwind-retail",
                principal_id="agent:finance",
                roles=["finance"],
                clearance="confidential",
            )
            assert finance["result_count"] == 1
            result = finance["results"][0]
            assert result["id"] == saved["id"]
            assert result["classification"] == "confidential"
            assert result["source_ids"] == ("doc://northwind-retail/auth-approval",)
            assert result["provenance_valid"] is True
            assert result["content_hash_match"] is True

            explain = api.explain_recall(finance["recall_id"], tenant="northwind-retail")
            assert "denied" not in json.dumps(explain).lower()

            receipt = api.forget(
                "northwind-retail:auth",
                tenant="northwind-retail",
                actor="agent:mcp",
                reason="test erasure",
            )
            assert receipt["purged"] == 1
            after = api.recall(
                "auth changes finance approval",
                tenant="northwind-retail",
                principal_id="agent:finance",
                roles=["finance"],
                clearance="confidential",
            )
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


def main():
    test_mcp_governed_tenant_recall_and_no_denied_side_channel()
    test_mcp_memory_tool_surface_still_confined()
    test_r2_mcp_allowed_tools_env_recall_only()
    test_a4_mcp_allowlist_fail_closed_default()
    test_mcp_forget_rejects_unknown_mode()
    print("MCP HARDENING TESTS PASSED")


if __name__ == "__main__":
    main()
