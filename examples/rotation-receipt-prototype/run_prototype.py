#!/usr/bin/env python3
"""PROTOTYPE ONLY: build a signed measured diff from deterministic stub routes."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import secrets
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

import numpy as np


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
DEFAULT_SUITE_PATH = HERE / "fixtures" / "toy-eval-suite.json"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from heartwood import Heartwood, Principal  # noqa: E402
from heartwood.continuity import (  # noqa: E402
    CONTRACT_SCHEMA_VERSION,
    CONTINUITY_ADMIN_ROLE,
    RECEIPT_SCHEMA_VERSION,
    CapabilityContract,
    Continuity,
    ErrorCategory,
    Outcome,
    RotationReceiptDraft,
    SignedRotationReceipt,
    content_hash,
    sanitize_error_category,
)


TENANT = "tenant:bet3-prototype"
ADMIN_ID = "agent:bet3-prototype"
FROM_ROUTE_ID = "route_bet3from000001"
TO_ROUTE_ID = "route_bet3to0000001"
BASELINE_RECEIPT_ID = "rot_bet3baseline001"
ROTATION_RECEIPT_ID = "rot_bet3prototype01"
BASELINE_RUN_ID = "run_bet3baseline0001"
ROTATION_RUN_ID = "run_bet3prototype001"
PROTOTYPE_ENV_SENTINEL = "HEARTWOOD_ROTATION_RECEIPT_PROTOTYPE_SENTINEL"

RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "outcome": {
            "type": "string",
            "enum": [outcome.value for outcome in Outcome],
        },
        "score": {
            "type": "number",
            "minimum": 0.0,
            "maximum": 1.0,
        },
    },
    "required": ["outcome", "score"],
    "additionalProperties": False,
}


class PrototypeValidationError(ValueError):
    """A toy-suite or prototype-boundary value failed closed validation."""

    def __init__(self, category: str):
        self.category = category
        super().__init__(f"invalid rotation receipt prototype: {category}")


class StubBehavior(str, Enum):
    RETURN = "return"
    TIMEOUT = "timeout"


class ModelRoute(Protocol):
    """Customer-supplied route boundary; this prototype ships stubs only."""

    def __call__(
        self,
        prompt: str,
        tools: Sequence[str] | None = None,
        schema: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class StubPlan:
    behavior: StubBehavior
    outcome: Outcome
    score: float

    def __post_init__(self) -> None:
        if not isinstance(self.behavior, StubBehavior):
            raise PrototypeValidationError("stub_behavior")
        if not isinstance(self.outcome, Outcome):
            raise PrototypeValidationError("stub_outcome")
        if (
            isinstance(self.score, bool)
            or not isinstance(self.score, (int, float))
            or not math.isfinite(float(self.score))
            or not 0.0 <= float(self.score) <= 1.0
        ):
            raise PrototypeValidationError("stub_score")
        if self.behavior is StubBehavior.TIMEOUT and (
            self.outcome is not Outcome.FAILED or float(self.score) != 0.0
        ):
            raise PrototypeValidationError("timeout_plan")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> StubPlan:
        data = _exact_mapping(
            value,
            {"behavior", "outcome", "score"},
            "stub_plan",
        )
        try:
            behavior = StubBehavior(data["behavior"])
            outcome = Outcome(data["outcome"])
        except (TypeError, ValueError) as exc:
            raise PrototypeValidationError("stub_enum") from exc
        return cls(
            behavior=behavior,
            outcome=outcome,
            score=data["score"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "behavior": self.behavior.value,
            "outcome": self.outcome.value,
            "score": float(self.score),
        }


@dataclass(frozen=True)
class ToyCase:
    case_id: str
    prompt_id: str
    from_stub: StubPlan
    to_stub: StubPlan

    def __post_init__(self) -> None:
        _opaque_id(self.case_id, "case_", "case_id")
        _opaque_id(self.prompt_id, "prompt_", "prompt_id")
        if not isinstance(self.from_stub, StubPlan):
            raise PrototypeValidationError("from_stub")
        if not isinstance(self.to_stub, StubPlan):
            raise PrototypeValidationError("to_stub")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ToyCase:
        data = _exact_mapping(
            value,
            {"case_id", "prompt_id", "from_stub", "to_stub"},
            "toy_case",
        )
        return cls(
            case_id=data["case_id"],
            prompt_id=data["prompt_id"],
            from_stub=StubPlan.from_dict(data["from_stub"]),
            to_stub=StubPlan.from_dict(data["to_stub"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "prompt_id": self.prompt_id,
            "from_stub": self.from_stub.to_dict(),
            "to_stub": self.to_stub.to_dict(),
        }


@dataclass(frozen=True)
class ToyEvalSuite:
    schema_version: str
    eval_suite_id: str
    cases: tuple[ToyCase, ...]

    def __post_init__(self) -> None:
        if self.schema_version != "1":
            raise PrototypeValidationError("suite_schema_version")
        _opaque_id(self.eval_suite_id, "suite_", "eval_suite_id")
        if not isinstance(self.cases, tuple) or not 1 <= len(self.cases) <= 100:
            raise PrototypeValidationError("cases")
        if any(not isinstance(case, ToyCase) for case in self.cases):
            raise PrototypeValidationError("cases")
        case_ids = [case.case_id for case in self.cases]
        prompt_ids = [case.prompt_id for case in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise PrototypeValidationError("duplicate_case_id")
        if len(prompt_ids) != len(set(prompt_ids)):
            raise PrototypeValidationError("duplicate_prompt_id")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ToyEvalSuite:
        data = _exact_mapping(
            value,
            {"schema_version", "eval_suite_id", "cases"},
            "toy_eval_suite",
        )
        if not isinstance(data["cases"], list):
            raise PrototypeValidationError("cases")
        return cls(
            schema_version=data["schema_version"],
            eval_suite_id=data["eval_suite_id"],
            cases=tuple(ToyCase.from_dict(case) for case in data["cases"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "eval_suite_id": self.eval_suite_id,
            "cases": [case.to_dict() for case in self.cases],
        }


@dataclass(frozen=True)
class RouteObservation:
    outcome: Outcome
    score: float
    error_category: ErrorCategory | None

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, Outcome):
            raise PrototypeValidationError("observation_outcome")
        if (
            isinstance(self.score, bool)
            or not isinstance(self.score, (int, float))
            or not math.isfinite(float(self.score))
            or not 0.0 <= float(self.score) <= 1.0
        ):
            raise PrototypeValidationError("observation_score")
        if self.outcome is Outcome.FAILED:
            if not isinstance(self.error_category, ErrorCategory):
                raise PrototypeValidationError("observation_error_category")
        elif self.error_category is not None:
            raise PrototypeValidationError("observation_error_category")


@dataclass(frozen=True)
class NegativeControl:
    environment_value: str
    file_path: Path
    file_value: str

    def __post_init__(self) -> None:
        if not self.environment_value or not self.file_value:
            raise PrototypeValidationError("negative_control_value")
        if not self.file_path.is_file() or not os.access(self.file_path, os.R_OK):
            raise PrototypeValidationError("negative_control_file")

    @property
    def forbidden_values(self) -> tuple[str, ...]:
        return (
            self.environment_value,
            self.file_value,
            str(self.file_path),
        )


@dataclass(frozen=True)
class PrototypeArtifacts:
    output_dir: Path
    database_path: Path
    baseline_receipt_path: Path
    rotation_receipt_path: Path
    run_summary_path: Path
    report_path: Path


class StubModelRoute:
    """Deterministic canned route with no provider, network, process, or tool use."""

    route_mode = "stub"

    def __init__(self, plans: Mapping[str, StubPlan]):
        self._plans = dict(plans)

    def __call__(
        self,
        prompt: str,
        tools: Sequence[str] | None = None,
        schema: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        if tools not in (None, (), []):
            raise PermissionError("prototype route tools disabled")
        if schema != RESPONSE_SCHEMA:
            raise ValueError("prototype response schema required")
        prompt_id = prompt.splitlines()[0]
        plan = self._plans.get(prompt_id)
        if plan is None:
            raise ValueError("unknown prototype prompt")
        if plan.behavior is StubBehavior.TIMEOUT:
            raise TimeoutError("prototype stub timeout")
        return {
            "outcome": plan.outcome.value,
            "score": float(plan.score),
        }


def load_toy_suite(path: Path = DEFAULT_SUITE_PATH) -> ToyEvalSuite:
    """Load and close-validate the fixture before any route runs."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PrototypeValidationError("suite_file") from exc
    return ToyEvalSuite.from_dict(raw)


def execute_suite(
    suite: ToyEvalSuite,
    from_route: ModelRoute,
    to_route: ModelRoute,
    *,
    file_probe: Path | None = None,
) -> tuple[dict[str, Any], ...]:
    """Execute a measured diff and return only closed receipt-case values."""
    measured_cases: list[dict[str, Any]] = []
    for case in suite.cases:
        prompt = case.prompt_id
        if file_probe is not None:
            prompt += f"\nfile_probe={file_probe}"
        before = _invoke_route(from_route, prompt)
        after = _invoke_route(to_route, prompt)
        fallback = {
            "attempted": False,
            "fallback_exercised": False,
        }
        if after.outcome in {Outcome.DEGRADED, Outcome.FAILED}:
            fallback_result = _invoke_route(from_route, prompt)
            fallback = {
                "attempted": True,
                "fallback_exercised": True,
                "trigger": (
                    "on_degraded" if after.outcome is Outcome.DEGRADED else "on_error"
                ),
                "target_route_id": FROM_ROUTE_ID,
                "result": fallback_result.outcome.value,
                "error_category": (
                    fallback_result.error_category.value
                    if fallback_result.error_category is not None
                    else None
                ),
            }
        measured_cases.append(
            {
                "case_id": case.case_id,
                "before": before.outcome.value,
                "after": after.outcome.value,
                "delta": round(float(after.score) - float(before.score), 6),
                "before_error_category": (
                    before.error_category.value
                    if before.error_category is not None
                    else None
                ),
                "after_error_category": (
                    after.error_category.value
                    if after.error_category is not None
                    else None
                ),
                "fallback": fallback,
            }
        )
    return tuple(measured_cases)


def run_prototype(
    output_dir: Path,
    *,
    suite_path: Path = DEFAULT_SUITE_PATH,
    negative_control: NegativeControl,
) -> PrototypeArtifacts:
    """Produce real signed receipts while enforcing a stub-only claim boundary."""
    suite = load_toy_suite(suite_path)
    from_route = StubModelRoute(
        {case.prompt_id: case.from_stub for case in suite.cases}
    )
    to_route = StubModelRoute({case.prompt_id: case.to_stub for case in suite.cases})
    if (
        not isinstance(from_route, StubModelRoute)
        or not isinstance(to_route, StubModelRoute)
        or from_route.route_mode != "stub"
        or to_route.route_mode != "stub"
    ):
        raise PrototypeValidationError("stub_routes_required")

    _prepare_output_dir(output_dir)
    database_path = output_dir / "heartwood-prototype.db"
    baseline_receipt_path = output_dir / "baseline-receipt.json"
    rotation_receipt_path = output_dir / "rotation-receipt.json"
    run_summary_path = output_dir / "run-summary.json"
    report_path = output_dir / "prototype-report.md"

    previous_environment_value = os.environ.get(PROTOTYPE_ENV_SENTINEL)
    os.environ[PROTOTYPE_ENV_SENTINEL] = negative_control.environment_value
    db: Heartwood | None = None
    try:
        db = _new_heartwood(database_path)
        principal = _admin()
        continuity = Continuity(db)
        from_contract, to_contract = _contracts()
        stored_from = continuity.store_capability_contract(
            from_contract,
            principal=principal,
        )
        stored_to = continuity.store_capability_contract(
            to_contract,
            principal=principal,
        )
        from_contract = continuity.get_capability_contract(
            stored_from.memory_id,
            principal=principal,
        )
        to_contract = continuity.get_capability_contract(
            stored_to.memory_id,
            principal=principal,
        )
        measured_cases = execute_suite(
            suite,
            from_route,
            to_route,
            file_probe=negative_control.file_path,
        )

        baseline = continuity.issue_rotation_receipt(
            _draft(
                suite,
                measured_cases,
                from_contract,
                to_contract,
                receipt_id=BASELINE_RECEIPT_ID,
                run_id=BASELINE_RUN_ID,
                prior_baseline={"is_genesis": True},
            ),
            principal=principal,
        )
        baseline_verification = continuity.verify_rotation_receipt(baseline)
        if not baseline_verification["ok"]:
            raise RuntimeError("prototype baseline receipt verification failed")

        receipt = continuity.issue_rotation_receipt(
            _draft(
                suite,
                measured_cases,
                from_contract,
                to_contract,
                receipt_id=ROTATION_RECEIPT_ID,
                run_id=ROTATION_RUN_ID,
                prior_baseline={
                    "receipt_id": baseline.draft.receipt_id,
                    "receipt_hash": baseline.receipt_hash,
                    "audit_seq": baseline.audit_seq,
                },
            ),
            principal=principal,
        )
        receipt_verification = continuity.verify_rotation_receipt(receipt)
        if not receipt_verification["ok"]:
            raise RuntimeError("prototype rotation receipt verification failed")

        audit_rows = list(db.store.iter_audit())
        baseline_rendered = baseline.render()
        receipt_rendered = receipt.render()
        audit_rendered = json.dumps(audit_rows, sort_keys=True)
    finally:
        if db is not None:
            db.close()
        if previous_environment_value is None:
            os.environ.pop(PROTOTYPE_ENV_SENTINEL, None)
        else:
            os.environ[PROTOTYPE_ENV_SENTINEL] = previous_environment_value

    if not _values_absent(
        negative_control.forbidden_values,
        baseline_rendered,
        receipt_rendered,
        audit_rendered,
        database_path.read_bytes(),
    ):
        raise RuntimeError("prototype negative control leaked")

    summary = {
        "artifact_type": "rotation_receipt_prototype",
        "claim_scope": "stub_routes_only",
        "evidence_mode": "prototype",
        "live_routes": 0,
        "stub_routes": 2,
        "child_processes": 0,
        "model_generated_tools": "none",
        "provider_sdks": "none",
        "case_count": len(measured_cases),
        "baseline_verification": baseline_verification,
        "rotation_verification": receipt_verification,
        "negative_controls": {
            "environment_sentinel_absent": True,
            "file_sentinel_absent": True,
            "file_probe_path_absent": True,
        },
    }
    summary_rendered = json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n"
    report_rendered = _render_report(
        summary,
        receipt,
        receipt_rendered,
    )
    if not _values_absent(
        negative_control.forbidden_values,
        summary_rendered,
        report_rendered,
    ):
        raise RuntimeError("prototype rendered output leaked a negative control")

    baseline_receipt_path.write_text(baseline_rendered, encoding="utf-8")
    rotation_receipt_path.write_text(receipt_rendered, encoding="utf-8")
    run_summary_path.write_text(summary_rendered, encoding="utf-8")
    report_path.write_text(report_rendered, encoding="utf-8")
    return PrototypeArtifacts(
        output_dir=output_dir,
        database_path=database_path,
        baseline_receipt_path=baseline_receipt_path,
        rotation_receipt_path=rotation_receipt_path,
        run_summary_path=run_summary_path,
        report_path=report_path,
    )


def _invoke_route(route: ModelRoute, prompt: str) -> RouteObservation:
    try:
        response = route(prompt, tools=(), schema=RESPONSE_SCHEMA)
        data = _exact_mapping(
            response,
            {"outcome", "score"},
            "route_response",
        )
        try:
            outcome = Outcome(data["outcome"])
        except (TypeError, ValueError) as exc:
            raise PrototypeValidationError("route_outcome") from exc
        score = data["score"]
        error_category = (
            ErrorCategory.ASSERTION_FAILED if outcome is Outcome.FAILED else None
        )
        return RouteObservation(
            outcome=outcome,
            score=score,
            error_category=error_category,
        )
    except Exception as exc:
        return RouteObservation(
            outcome=Outcome.FAILED,
            score=0.0,
            error_category=sanitize_error_category(exc),
        )


def _draft(
    suite: ToyEvalSuite,
    measured_cases: tuple[dict[str, Any], ...],
    from_contract: CapabilityContract,
    to_contract: CapabilityContract,
    *,
    receipt_id: str,
    run_id: str,
    prior_baseline: Mapping[str, Any],
) -> RotationReceiptDraft:
    summary = {outcome.value: 0 for outcome in Outcome}
    for case in measured_cases:
        summary[case["after"]] += 1
    return RotationReceiptDraft.from_dict(
        {
            "schema_version": RECEIPT_SCHEMA_VERSION,
            "receipt_id": receipt_id,
            "evidence_mode": "prototype",
            "from_route": from_contract.route_id,
            "to_route": to_contract.route_id,
            "from_contract": {
                "route_id": from_contract.route_id,
                "schema_version": from_contract.schema_version,
                "contract_hash": from_contract.contract_hash,
            },
            "to_contract": {
                "route_id": to_contract.route_id,
                "schema_version": to_contract.schema_version,
                "contract_hash": to_contract.contract_hash,
            },
            "eval_suite": {
                "eval_suite_id": suite.eval_suite_id,
                "schema_version": suite.schema_version,
                "eval_suite_hash": content_hash(suite.to_dict()),
            },
            "run_id": run_id,
            "prior_baseline": dict(prior_baseline),
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "cases": list(measured_cases),
            "summary": {
                "passed": summary["pass"],
                "degraded": summary["degraded"],
                "failed": summary["failed"],
            },
        }
    )


def _contracts() -> tuple[CapabilityContract, CapabilityContract]:
    shared = {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "provider": "prototype.stub",
        "tool_use": False,
        "structured_output": {
            "json_mode": True,
            "json_schema": True,
            "grammar": False,
        },
        "context_window_tokens": 4096,
        "latency_class": "interactive",
        "price_class": "economy",
        "residency": "synthetic",
    }
    from_contract = CapabilityContract.from_dict(
        {
            **shared,
            "route_id": FROM_ROUTE_ID,
            "model": "stub/from-v1",
            "fallback": {
                "on_error": {
                    "target_route_id": TO_ROUTE_ID,
                    "policy": "fail_closed",
                },
                "on_degraded": {
                    "target_route_id": TO_ROUTE_ID,
                    "policy": "degrade",
                },
            },
        }
    )
    to_contract = CapabilityContract.from_dict(
        {
            **shared,
            "route_id": TO_ROUTE_ID,
            "model": "stub/to-v1",
            "fallback": {
                "on_error": {
                    "target_route_id": FROM_ROUTE_ID,
                    "policy": "degrade",
                },
                "on_degraded": {
                    "target_route_id": FROM_ROUTE_ID,
                    "policy": "degrade",
                },
            },
        }
    )
    return from_contract, to_contract


def _new_heartwood(path: Path) -> Heartwood:
    return Heartwood(
        path=path,
        tenant=TENANT,
        embedder=(_deterministic_embed, "prototype-hash-embedder"),
        reranker=(_deterministic_rerank, "prototype-token-reranker"),
    )


def _deterministic_embed(texts: list[str]) -> np.ndarray:
    vectors = np.zeros((len(texts), 16), dtype=np.float32)
    for row, text in enumerate(texts):
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        for column in range(16):
            vectors[row, column] = digest[column] / 255.0
    return vectors


def _deterministic_rerank(query: str, texts: list[str]) -> np.ndarray:
    query_tokens = set(query.lower().split())
    return np.asarray(
        [float(len(query_tokens & set(text.lower().split()))) for text in texts],
        dtype=np.float32,
    )


def _admin() -> Principal:
    return Principal(
        id=ADMIN_ID,
        tenant=TENANT,
        roles=(CONTINUITY_ADMIN_ROLE,),
        clearance="confidential",
    )


def _render_report(
    summary: Mapping[str, Any],
    receipt: SignedRotationReceipt,
    receipt_rendered: str,
) -> str:
    verification = summary["rotation_verification"]
    return (
        "# PROTOTYPE ONLY — rotation receipt measured diff\n\n"
        "This is prototype evidence from a toy eval suite and deterministic "
        "stub routes. It is not production-catalog evidence.\n\n"
        f"- evidence_mode={receipt.draft.evidence_mode.value}\n"
        f"- live_routes={summary['live_routes']}\n"
        f"- stub_routes={summary['stub_routes']}\n"
        f"- signature_valid={str(verification['signature_valid']).lower()}\n"
        f"- audit_event_valid={str(verification['audit_event_valid']).lower()}\n"
        f"- audit_chain_valid={str(verification['audit_chain_valid']).lower()}\n"
        f"- receipt_hash={receipt.receipt_hash}\n\n"
        "## PROTOTYPE signed receipt (machine-readable)\n\n"
        "```json\n"
        f"{receipt_rendered.rstrip()}\n"
        "```\n"
    )


def _prepare_output_dir(path: Path) -> None:
    if path.exists() and (not path.is_dir() or path.is_symlink()):
        raise PrototypeValidationError("output_directory_invalid")
    if path.exists() and any(path.iterdir()):
        raise PrototypeValidationError("output_directory_not_empty")
    path.mkdir(parents=True, exist_ok=True)


def _exact_mapping(
    value: Mapping[str, Any],
    keys: set[str],
    category: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise PrototypeValidationError(category)
    return value


def _opaque_id(value: Any, prefix: str, category: str) -> str:
    if not isinstance(value, str) or not value.startswith(prefix):
        raise PrototypeValidationError(category)
    body = value[len(prefix) :]
    if not 12 <= len(body) <= 80 or not all(
        char.isalnum() or char in "_-" for char in body
    ):
        raise PrototypeValidationError(category)
    return value


def _values_absent(
    forbidden_values: Sequence[str],
    *surfaces: str | bytes,
) -> bool:
    for forbidden in forbidden_values:
        forbidden_bytes = forbidden.encode("utf-8")
        for surface in surfaces:
            value = surface.encode("utf-8") if isinstance(surface, str) else surface
            if forbidden_bytes in value:
                return False
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "PROTOTYPE ONLY: run a toy suite against deterministic stubs and "
            "produce a real signed, audit-bound measured diff."
        )
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="empty destination for prototype-only artifacts",
    )
    parser.add_argument(
        "--suite",
        type=Path,
        default=DEFAULT_SUITE_PATH,
        help="closed toy eval fixture",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    with tempfile.TemporaryDirectory(
        prefix="heartwood-rotation-receipt-prototype-"
    ) as temp_dir:
        sentinel_file = Path(temp_dir) / "readable-sentinel.txt"
        environment_value = f"ENV_SENTINEL_{secrets.token_hex(24)}"
        file_value = f"FILE_SENTINEL_{secrets.token_hex(24)}"
        sentinel_file.write_text(file_value, encoding="utf-8")
        negative_control = NegativeControl(
            environment_value=environment_value,
            file_path=sentinel_file,
            file_value=file_value,
        )
        artifacts = run_prototype(
            args.output_dir,
            suite_path=args.suite,
            negative_control=negative_control,
        )
    print(artifacts.report_path.read_text(encoding="utf-8"), end="")
    print("ROTATION_RECEIPT_PROTOTYPE=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
