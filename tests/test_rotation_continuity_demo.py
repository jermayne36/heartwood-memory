"""Offline contract test for the public rotation-continuity demo."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "examples" / "rotation-continuity" / "run_demo.py"
MCP_CHECK = ROOT / "examples" / "rotation-continuity" / "check_vscode_mcp.py"


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
        assert session["continuity"]["all_checkpoint_fingerprints_identical"] is True
        assert session["continuity"]["policy_memory_denied_without_release_manager"] is True
        assert session["continuity"]["all_provenance_valid"] is True
        assert session["continuity"]["all_content_hashes_match"] is True
        assert len(session["continuity"]["checkpoints"]) == 4
        assert session["audit_chain"]["verify_audit"] is True
        assert session["audit_chain"]["linkage_ok"] is True
        # 2 remember + 1 approve + 3 route events + 8 recall (2 x 4 checkpoints).
        assert session["audit_chain"]["event_count"] == 14
        assert session["audit_chain"]["genesis_prev_hash"] == "genesis"
        assert (output_dir / "transcript.md").exists()
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
