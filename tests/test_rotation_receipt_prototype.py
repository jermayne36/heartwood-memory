"""Security and end-to-end tests for the stub-only rotation receipt prototype."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "examples" / "rotation-receipt-prototype" / "run_prototype.py"
FIXTURE = (
    ROOT
    / "examples"
    / "rotation-receipt-prototype"
    / "fixtures"
    / "toy-eval-suite.json"
)
MODULE_NAME = "heartwood_rotation_receipt_prototype"
SPEC = importlib.util.spec_from_file_location(MODULE_NAME, SCRIPT)
assert SPEC is not None and SPEC.loader is not None
prototype = importlib.util.module_from_spec(SPEC)
sys.modules[MODULE_NAME] = prototype
SPEC.loader.exec_module(prototype)

from heartwood.continuity import Continuity, SignedRotationReceipt  # noqa: E402


def _negative_control(temp_dir: Path):
    sentinel_file = temp_dir / "readable-sentinel.txt"
    sentinel_value = "FILE_NEGATIVE_CONTROL_7f2d9e4c0a1b"
    sentinel_file.write_text(sentinel_value, encoding="utf-8")
    return prototype.NegativeControl(
        environment_value="ENV_NEGATIVE_CONTROL_6c1a8f3e2d9b",
        file_path=sentinel_file,
        file_value=sentinel_value,
    )


def _run(temp_dir: Path):
    output_dir = temp_dir / "output"
    negative_control = _negative_control(temp_dir)
    artifacts = prototype.run_prototype(
        output_dir,
        negative_control=negative_control,
    )
    return artifacts, negative_control


def test_prototype_end_to_end_receipt_is_signed_and_audit_bound():
    with tempfile.TemporaryDirectory(prefix="heartwood-bet3-prototype-") as raw:
        artifacts, _negative = _run(Path(raw))
        receipt_dict = json.loads(artifacts.rotation_receipt_path.read_text())
        baseline_dict = json.loads(artifacts.baseline_receipt_path.read_text())
        receipt = SignedRotationReceipt.from_dict(receipt_dict)

        assert receipt.draft.evidence_mode.value == "prototype"
        assert receipt.draft.prior_baseline.receipt_id == baseline_dict["receipt_id"]
        assert (
            receipt.draft.prior_baseline.receipt_hash == baseline_dict["receipt_hash"]
        )

        reopened = prototype._new_heartwood(artifacts.database_path)
        try:
            verification = Continuity(reopened).verify_rotation_receipt(receipt)
        finally:
            reopened.close()
        assert verification["ok"] is True
        assert verification["signature_valid"] is True
        assert verification["audit_event_valid"] is True
        assert verification["audit_chain_valid"] is True


def test_sentinel_environment_and_file_negative_controls_pass():
    with tempfile.TemporaryDirectory(prefix="heartwood-bet3-sentinel-") as raw:
        temp_dir = Path(raw)
        previous = os.environ.get(prototype.PROTOTYPE_ENV_SENTINEL)
        artifacts, negative = _run(temp_dir)
        assert os.environ.get(prototype.PROTOTYPE_ENV_SENTINEL) == previous

        summary = json.loads(artifacts.run_summary_path.read_text())
        assert summary["negative_controls"] == {
            "environment_sentinel_absent": True,
            "file_probe_path_absent": True,
            "file_sentinel_absent": True,
        }
        artifact_bytes = b"".join(
            path.read_bytes()
            for path in artifacts.output_dir.iterdir()
            if path.is_file()
        )
        for forbidden in negative.forbidden_values:
            assert forbidden.encode("utf-8") not in artifact_bytes


def test_timeout_and_fallback_emit_only_sanitized_categories():
    with tempfile.TemporaryDirectory(prefix="heartwood-bet3-timeout-") as raw:
        artifacts, _negative = _run(Path(raw))
        receipt = json.loads(artifacts.rotation_receipt_path.read_text())
        timeout_case = next(
            case
            for case in receipt["cases"]
            if case["case_id"] == "case_bet3timeout0001"
        )
        assert timeout_case["after"] == "failed"
        assert timeout_case["after_error_category"] == "timeout"
        assert timeout_case["fallback"] == {
            "attempted": True,
            "error_category": None,
            "fallback_exercised": True,
            "result": "pass",
            "target_route_id": prototype.FROM_ROUTE_ID,
            "trigger": "on_error",
        }
        assert "prototype stub timeout" not in json.dumps(receipt)


def test_arbitrary_route_strings_are_not_persisted():
    suite = prototype.load_toy_suite()
    sentinel = "ARBITRARY_MODEL_TEXT_MUST_NOT_PERSIST"

    class UnexpectedStringRoute:
        def __call__(self, prompt, tools=None, schema=None):
            return {
                "outcome": "pass",
                "score": 1.0,
                "raw_output": sentinel,
            }

    from_route = prototype.StubModelRoute(
        {case.prompt_id: case.from_stub for case in suite.cases}
    )
    cases = prototype.execute_suite(
        suite,
        from_route,
        UnexpectedStringRoute(),
    )
    rendered = json.dumps(cases, sort_keys=True)
    assert sentinel not in rendered
    assert {case["after_error_category"] for case in cases} == {"invalid_response"}
    assert {case["after"] for case in cases} == {"failed"}


def test_fixture_and_response_schemas_fail_closed():
    raw = json.loads(FIXTURE.read_text())
    unknown = copy.deepcopy(raw)
    unknown["cases"][0]["prompt"] = "not allowed"
    with pytest.raises(
        prototype.PrototypeValidationError,
        match="toy_case",
    ):
        prototype.ToyEvalSuite.from_dict(unknown)

    out_of_bounds = copy.deepcopy(raw)
    out_of_bounds["cases"][0]["from_stub"]["score"] = 1.01
    with pytest.raises(
        prototype.PrototypeValidationError,
        match="stub_score",
    ):
        prototype.ToyEvalSuite.from_dict(out_of_bounds)


def test_receipt_excludes_prompt_ids_and_forbidden_rich_fields():
    with tempfile.TemporaryDirectory(prefix="heartwood-bet3-closed-") as raw:
        artifacts, _negative = _run(Path(raw))
        receipt_text = artifacts.rotation_receipt_path.read_text()
        receipt = json.loads(receipt_text)
        suite = prototype.load_toy_suite()
        for case in suite.cases:
            assert case.prompt_id not in receipt_text

        forbidden_keys = {
            "prompt",
            "prompt_id",
            "memory",
            "model_output",
            "evidence",
            "raw_error",
            "environment",
            "command",
            "credential",
            "callable",
            "stdout",
            "stderr",
        }

        def assert_closed(value):
            if isinstance(value, dict):
                assert not (set(value) & forbidden_keys)
                for nested in value.values():
                    assert_closed(nested)
            elif isinstance(value, list):
                for nested in value:
                    assert_closed(nested)
            else:
                assert isinstance(value, (str, int, float, bool)) or value is None

        assert_closed(receipt)
        assert SignedRotationReceipt.from_dict(receipt).draft.evidence_mode.value == (
            "prototype"
        )


def test_stub_only_summary_and_visible_prototype_label():
    with tempfile.TemporaryDirectory(prefix="heartwood-bet3-label-") as raw:
        artifacts, _negative = _run(Path(raw))
        summary = json.loads(artifacts.run_summary_path.read_text())
        report = artifacts.report_path.read_text()
        assert summary["evidence_mode"] == "prototype"
        assert summary["live_routes"] == 0
        assert summary["stub_routes"] == 2
        assert summary["child_processes"] == 0
        assert summary["model_generated_tools"] == "none"
        assert "PROTOTYPE ONLY" in report
        assert "evidence_mode=prototype" in report
        assert "live_routes=0" in report
        assert "stub_routes=2" in report
        assert "production-catalog evidence" in report


def test_output_directory_reuse_fails_closed():
    with tempfile.TemporaryDirectory(prefix="heartwood-bet3-output-") as raw:
        temp_dir = Path(raw)
        output_dir = temp_dir / "output"
        output_dir.mkdir()
        (output_dir / "existing.txt").write_text("occupied", encoding="utf-8")
        with pytest.raises(
            prototype.PrototypeValidationError,
            match="output_directory_not_empty",
        ):
            prototype.run_prototype(
                output_dir,
                negative_control=_negative_control(temp_dir),
            )


def test_runner_has_no_provider_network_or_subprocess_imports():
    source = SCRIPT.read_text(encoding="utf-8")
    forbidden_imports = (
        "import subprocess",
        "from subprocess",
        "import urllib",
        "from urllib",
        "import requests",
        "from requests",
        "import openai",
        "from openai",
        "import anthropic",
        "from anthropic",
        "import boto3",
        "from boto3",
        "import litellm",
        "from litellm",
    )
    assert all(token not in source for token in forbidden_imports)
