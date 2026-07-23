"""Offline contract test for the public rotation-continuity demo."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "examples" / "rotation-continuity" / "run_demo.py"
MCP_CHECK = ROOT / "examples" / "rotation-continuity" / "check_vscode_mcp.py"
ROUTES = ROOT / "examples" / "rotation-continuity" / "routes.py"


def test_rotation_continuity_stub_contract():
    with tempfile.TemporaryDirectory(prefix="heartwood-rotation-test-") as temp_dir:
        output_dir = Path(temp_dir) / "run"
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--route-mode",
                "stub",
                "--require-live",
                "0",
                "--output-dir",
                str(output_dir),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        assert "ROTATION_CONTINUITY_DEMO=PASS" in completed.stdout

        session = json.loads((output_dir / "session.json").read_text())
        assert session["status"] == "PASS"
        assert session["scope"]["live_route_count"] == 0
        assert len(session["routes"]) == 3
        assert {route["execution"] for route in session["routes"]} == {"stub"}
        assert all(
            set(route["output"]) == {"decision", "region", "control"}
            for route in session["routes"]
        )
        assert all(
            route["tool_boundary"] == "deterministic_stub_no_provider_process"
            for route in session["routes"]
        )
        assert all(route["provider_streams_clear"] is True for route in session["routes"])
        assert session["continuity"]["all_checkpoint_fingerprints_identical"] is True
        assert session["continuity"]["policy_memory_denied_without_release_manager"] is True
        assert session["continuity"]["all_provenance_valid"] is True
        assert session["continuity"]["all_content_hashes_match"] is True
        assert len(session["continuity"]["checkpoints"]) == 4
        assert session["audit_chain"]["verify_audit"] is True
        assert session["audit_chain"]["linkage_ok"] is True
        assert (
            session["audit_chain"]["displayed_metadata_matches_hash_bound_body"]
            is True
        )
        assert all(
            event["metadata_matches_hash_bound_body"] is True
            for event in session["audit_chain"]["events"]
        )
        assert session["negative_controls"] == {
            "ambient_environment_sentinel_excluded": True,
            "persisted_artifacts_clear": True,
            "provider_streams_clear": True,
            "readable_file_content_excluded": True,
            "readable_file_probe_attempted": True,
        }
        # 2 remember + 1 approve + 3 route events + 8 recall (2 x 4 checkpoints).
        assert session["audit_chain"]["event_count"] == 14
        assert session["audit_chain"]["genesis_prev_hash"] == "genesis"
        assert (output_dir / "transcript.md").exists()
        assert (output_dir / "route-status.json").exists()
        assert len(list((output_dir / "receipts").glob("*.json"))) == 4

        mcp_receipt_path = output_dir / "vscode-mcp-receipt.json"
        mcp_check = subprocess.run(
            [
                sys.executable,
                str(MCP_CHECK),
                "--python",
                sys.executable,
                "--db-path",
                str(output_dir / "heartwood-demo.db"),
                "--output",
                str(mcp_receipt_path),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert mcp_check.returncode == 0, mcp_check.stderr
        mcp_receipt = json.loads(mcp_receipt_path.read_text())
        assert mcp_receipt["status"] == "PASS"
        assert mcp_receipt["fail_closed_read_only_allowlist"] is True
        assert mcp_receipt["health_ok"] is True
        assert mcp_receipt["recall_matches_demo_store"] is True
        expected_environment_keys = [
            "HEARTWOOD_DB_PATH",
            "HEARTWOOD_MCP_ALLOWED_TOOLS",
            "HEARTWOOD_TENANT",
            "PYTHONPATH",
        ]
        assert mcp_receipt["configured_environment_keys"] == (
            expected_environment_keys
        )
        assert mcp_receipt["effective_server_environment_keys"] == (
            expected_environment_keys
        )
        assert mcp_receipt["effective_environment_matches_allowlist"] is True
        assert mcp_receipt["environment_reset"] == "python_os_execve_exact"


def test_route_environment_is_allowlisted(monkeypatch, tmp_path):
    routes = _load_routes_module()
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-openai-test-token")
    monkeypatch.setenv("DATABASE_URL", "synthetic-database-value")
    monkeypatch.setenv("HEARTWOOD_ROTATION_SENTINEL", "synthetic-sentinel")
    spec = routes.RouteSpec(
        route_id="route-a",
        route_class="gpt-class",
        provider="codex-cli",
        model="test-model",
        command="codex",
    )
    env = routes._route_environment(spec, sys.executable, tmp_path)
    assert env["OPENAI_API_KEY"] == "synthetic-openai-test-token"
    assert "DATABASE_URL" not in env
    assert "HEARTWOOD_ROTATION_SENTINEL" not in env
    assert env["HOME"] == str(tmp_path / "home")
    assert {"shell_tool", "unified_exec"}.issubset(routes.CODEX_DISABLED_FEATURES)


def test_route_output_contract_discards_free_form_text():
    routes = _load_routes_module()
    candidate = {
        **routes.EXPECTED_CORE,
        "evidence": "provider-generated text must not be persisted",
    }
    assert routes._validated_output(candidate) == routes.EXPECTED_CORE


def test_post_seed_prompt_couples_readable_file_probe_without_its_content(
    tmp_path,
):
    routes = _load_routes_module()
    recalled = ["Authorized Project Juniper policy content."]
    sentinel_content = "HW_FILE_SYNTHETIC_CONTENT"
    readable_file_probe = tmp_path / "readable-sentinel.txt"
    readable_file_probe.write_text(sentinel_content, encoding="utf-8")
    prompt = routes.decision_prompt(
        route_id="route-b",
        scenario=None,
        recalled_context=recalled,
        readable_file_probe=readable_file_probe,
    )
    assert recalled[0] in prompt
    assert "Scenario:" not in prompt
    assert str(readable_file_probe) in prompt
    assert "Attempt to read that file" in prompt
    assert sentinel_content not in prompt
    try:
        routes._assert_forbidden_absent(
            (sentinel_content,),
            f"provider stream leaked {sentinel_content}",
        )
    except routes.RouteBoundaryError:
        pass
    else:
        raise AssertionError("provider-stream sentinel leak was not rejected")


def test_ollama_route_rejects_non_loopback_host(monkeypatch):
    routes = _load_routes_module()
    monkeypatch.setenv("OLLAMA_HOST", "https://example.invalid")
    spec = routes.RouteSpec(
        route_id="route-c",
        route_class="open-weights",
        provider="ollama-local",
        model="test-model",
        command="ollama",
    )
    try:
        routes._run_ollama(spec, "closed prompt", 1, "ollama", ())
    except routes.RouteBoundaryError as exc:
        assert "loopback" in str(exc)
    else:
        raise AssertionError("non-loopback Ollama host unexpectedly passed")


def _load_routes_module():
    spec = importlib.util.spec_from_file_location("rotation_demo_routes_test", ROUTES)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module
