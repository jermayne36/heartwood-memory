"""Closed, dependency-free schemas for capability contracts and measured diffs.

The schemas in this module deliberately accept identifiers, enums, booleans,
bounded numbers, hashes, and timestamps only. They have no fields for prompts,
memory content, model output, evidence text, raw errors, environments, commands,
credentials, or callable representations.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Mapping


CONTRACT_SCHEMA_VERSION = "1"
RECEIPT_SCHEMA_VERSION = "1"
RECEIPT_SIGNING_VERSION = "heartwood.continuity.rotation-receipt.v1"
RECEIPT_SIGNATURE_DOMAIN = b"heartwood.continuity.rotation-receipt.v1\x00"

_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$")
_REGION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$")
_SIGNATURE_RE = re.compile(
    r"^(?:ed25519:[A-Za-z0-9_-]{43}:[A-Za-z0-9_-]{86}|"
    r"hmac-sha256:[0-9a-f]{64})$"
)
_SECRET_MARKERS = (
    "heartwood_secret_sentinel",
    "hw_secret_sentinel",
    "sk-",
    "rk_",
    "ghp_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "akia",
    "bearer ",
    "begin private key",
    "api_key=",
    "apikey=",
    "password=",
    "secret=",
    "token=",
)


class ContinuityValidationError(ValueError):
    """A continuity artifact failed a fixed-category validation check."""

    def __init__(self, category: str):
        self.category = category
        super().__init__(f"invalid continuity artifact: {category}")


class LatencyClass(str, Enum):
    INTERACTIVE = "interactive"
    BATCH = "batch"
    BULK = "bulk"


class PriceClass(str, Enum):
    ECONOMY = "economy"
    STANDARD = "standard"
    PREMIUM = "premium"


class FallbackPolicyName(str, Enum):
    DEGRADE = "degrade"
    RETRY = "retry"
    RETRY_THEN_DEGRADE = "retry_then_degrade"
    FAIL_CLOSED = "fail_closed"


class Outcome(str, Enum):
    PASS = "pass"
    DEGRADED = "degraded"
    FAILED = "failed"


class ErrorCategory(str, Enum):
    ASSERTION_FAILED = "assertion_failed"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    UNAVAILABLE = "unavailable"
    INVALID_RESPONSE = "invalid_response"
    INTERNAL = "internal"


class EvidenceMode(str, Enum):
    PRODUCTION = "production"
    PROTOTYPE = "prototype"


class FallbackTrigger(str, Enum):
    ON_ERROR = "on_error"
    ON_DEGRADED = "on_degraded"


def sanitize_error_category(error: BaseException) -> ErrorCategory:
    """Reduce an exception to a fixed category without inspecting its message."""
    if isinstance(error, TimeoutError):
        return ErrorCategory.TIMEOUT
    if isinstance(error, PermissionError):
        return ErrorCategory.AUTHORIZATION
    if isinstance(error, ConnectionError):
        return ErrorCategory.UNAVAILABLE
    if isinstance(error, ValueError):
        return ErrorCategory.INVALID_RESPONSE
    return ErrorCategory.INTERNAL


def canonical_json(value: Any) -> str:
    """Return the canonical JSON encoding used for hashes and signatures."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def content_hash(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def validate_principal_id(value: Any) -> str:
    """Validate the fixed-format principal id included in a signed receipt."""
    return _safe_principal(value)


@dataclass(frozen=True)
class StructuredOutput:
    json_mode: bool
    json_schema: bool
    grammar: bool

    def __post_init__(self) -> None:
        _require_bool(self.json_mode, "structured_output")
        _require_bool(self.json_schema, "structured_output")
        _require_bool(self.grammar, "structured_output")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> StructuredOutput:
        data = _require_mapping(value, "structured_output")
        _require_exact_keys(
            data,
            {"json_mode", "json_schema", "grammar"},
            "structured_output",
        )
        return cls(
            json_mode=data["json_mode"],
            json_schema=data["json_schema"],
            grammar=data["grammar"],
        )

    def to_dict(self) -> dict[str, bool]:
        return {
            "json_mode": self.json_mode,
            "json_schema": self.json_schema,
            "grammar": self.grammar,
        }


@dataclass(frozen=True)
class FallbackPolicy:
    target_route_id: str
    policy: FallbackPolicyName

    def __post_init__(self) -> None:
        _opaque_id(self.target_route_id, "route_", "fallback_target_route_id")
        _require_enum(self.policy, FallbackPolicyName, "fallback_policy")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> FallbackPolicy:
        data = _require_mapping(value, "fallback_policy")
        _require_exact_keys(data, {"target_route_id", "policy"}, "fallback_policy")
        return cls(
            target_route_id=data["target_route_id"],
            policy=_parse_enum(data["policy"], FallbackPolicyName, "fallback_policy"),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "target_route_id": self.target_route_id,
            "policy": self.policy.value,
        }


@dataclass(frozen=True)
class DeclarativeFallback:
    on_error: FallbackPolicy | None = None
    on_degraded: FallbackPolicy | None = None

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> DeclarativeFallback:
        data = _require_mapping(value, "fallback")
        _require_exact_keys(
            data,
            set(),
            "fallback",
            optional={"on_error", "on_degraded"},
        )
        return cls(
            on_error=(
                FallbackPolicy.from_dict(data["on_error"])
                if "on_error" in data
                else None
            ),
            on_degraded=(
                FallbackPolicy.from_dict(data["on_degraded"])
                if "on_degraded" in data
                else None
            ),
        )

    def to_dict(self) -> dict[str, dict[str, str]]:
        value: dict[str, dict[str, str]] = {}
        if self.on_error is not None:
            value["on_error"] = self.on_error.to_dict()
        if self.on_degraded is not None:
            value["on_degraded"] = self.on_degraded.to_dict()
        return value


@dataclass(frozen=True)
class CapabilityContract:
    """A closed declaration of one approved model route."""

    schema_version: str
    route_id: str
    provider: str
    model: str
    tool_use: bool
    structured_output: StructuredOutput
    context_window_tokens: int
    latency_class: LatencyClass
    price_class: PriceClass
    residency: str
    fallback: DeclarativeFallback

    def __post_init__(self) -> None:
        _exact_version(self.schema_version, CONTRACT_SCHEMA_VERSION, "contract_schema_version")
        _opaque_id(self.route_id, "route_", "route_id")
        _safe_label(self.provider, "provider")
        _safe_label(self.model, "model")
        _require_bool(self.tool_use, "tool_use")
        if not isinstance(self.structured_output, StructuredOutput):
            raise ContinuityValidationError("structured_output")
        _bounded_int(
            self.context_window_tokens,
            minimum=1,
            maximum=10_000_000,
            category="context_window_tokens",
        )
        _require_enum(self.latency_class, LatencyClass, "latency_class")
        _require_enum(self.price_class, PriceClass, "price_class")
        _safe_region(self.residency)
        if not isinstance(self.fallback, DeclarativeFallback):
            raise ContinuityValidationError("fallback")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> CapabilityContract:
        data = _require_mapping(value, "capability_contract")
        _require_exact_keys(
            data,
            {
                "schema_version",
                "route_id",
                "provider",
                "model",
                "tool_use",
                "structured_output",
                "context_window_tokens",
                "latency_class",
                "price_class",
                "residency",
                "fallback",
            },
            "capability_contract",
        )
        return cls(
            schema_version=data["schema_version"],
            route_id=data["route_id"],
            provider=data["provider"],
            model=data["model"],
            tool_use=data["tool_use"],
            structured_output=StructuredOutput.from_dict(data["structured_output"]),
            context_window_tokens=data["context_window_tokens"],
            latency_class=_parse_enum(data["latency_class"], LatencyClass, "latency_class"),
            price_class=_parse_enum(data["price_class"], PriceClass, "price_class"),
            residency=data["residency"],
            fallback=DeclarativeFallback.from_dict(data["fallback"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "route_id": self.route_id,
            "provider": self.provider,
            "model": self.model,
            "tool_use": self.tool_use,
            "structured_output": self.structured_output.to_dict(),
            "context_window_tokens": self.context_window_tokens,
            "latency_class": self.latency_class.value,
            "price_class": self.price_class.value,
            "residency": self.residency,
            "fallback": self.fallback.to_dict(),
        }

    @property
    def contract_hash(self) -> str:
        return content_hash(self.to_dict())

    def render(self) -> str:
        return canonical_json(self.to_dict()) + "\n"


@dataclass(frozen=True)
class ContractBinding:
    route_id: str
    schema_version: str
    contract_hash: str

    def __post_init__(self) -> None:
        _opaque_id(self.route_id, "route_", "contract_binding_route_id")
        _exact_version(self.schema_version, CONTRACT_SCHEMA_VERSION, "contract_binding_version")
        _hash(self.contract_hash, "contract_hash")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ContractBinding:
        data = _require_mapping(value, "contract_binding")
        _require_exact_keys(
            data,
            {"route_id", "schema_version", "contract_hash"},
            "contract_binding",
        )
        return cls(
            route_id=data["route_id"],
            schema_version=data["schema_version"],
            contract_hash=data["contract_hash"],
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "route_id": self.route_id,
            "schema_version": self.schema_version,
            "contract_hash": self.contract_hash,
        }


@dataclass(frozen=True)
class EvalSuiteBinding:
    eval_suite_id: str
    schema_version: str
    eval_suite_hash: str

    def __post_init__(self) -> None:
        _opaque_id(self.eval_suite_id, "suite_", "eval_suite_id")
        _version_token(self.schema_version, "eval_suite_version")
        _hash(self.eval_suite_hash, "eval_suite_hash")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> EvalSuiteBinding:
        data = _require_mapping(value, "eval_suite_binding")
        _require_exact_keys(
            data,
            {"eval_suite_id", "schema_version", "eval_suite_hash"},
            "eval_suite_binding",
        )
        return cls(
            eval_suite_id=data["eval_suite_id"],
            schema_version=data["schema_version"],
            eval_suite_hash=data["eval_suite_hash"],
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "eval_suite_id": self.eval_suite_id,
            "schema_version": self.schema_version,
            "eval_suite_hash": self.eval_suite_hash,
        }


@dataclass(frozen=True)
class BaselineBinding:
    receipt_id: str
    receipt_hash: str

    def __post_init__(self) -> None:
        _opaque_id(self.receipt_id, "rot_", "baseline_receipt_id")
        _hash(self.receipt_hash, "baseline_receipt_hash")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> BaselineBinding:
        data = _require_mapping(value, "baseline_binding")
        _require_exact_keys(data, {"receipt_id", "receipt_hash"}, "baseline_binding")
        return cls(
            receipt_id=data["receipt_id"],
            receipt_hash=data["receipt_hash"],
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "receipt_id": self.receipt_id,
            "receipt_hash": self.receipt_hash,
        }


@dataclass(frozen=True)
class FallbackObservation:
    attempted: bool
    trigger: FallbackTrigger | None = None
    target_route_id: str | None = None
    result: Outcome | None = None
    error_category: ErrorCategory | None = None

    def __post_init__(self) -> None:
        _require_bool(self.attempted, "fallback_attempted")
        if not self.attempted:
            if any(
                value is not None
                for value in (
                    self.trigger,
                    self.target_route_id,
                    self.result,
                    self.error_category,
                )
            ):
                raise ContinuityValidationError("unobserved_fallback")
            return
        _require_enum(self.trigger, FallbackTrigger, "fallback_trigger")
        if self.target_route_id is None:
            raise ContinuityValidationError("fallback_target_route_id")
        _opaque_id(self.target_route_id, "route_", "fallback_target_route_id")
        _require_enum(self.result, Outcome, "fallback_result")
        _validate_error_binding(self.result, self.error_category, "fallback_error_category")

    @property
    def exercised(self) -> bool:
        return self.attempted and self.result is not None

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> FallbackObservation:
        data = _require_mapping(value, "fallback_observation")
        attempted = data.get("attempted")
        if attempted is False:
            _require_exact_keys(
                data,
                {"attempted", "fallback_exercised"},
                "fallback_observation",
            )
        elif attempted is True:
            _require_exact_keys(
                data,
                {
                    "attempted",
                    "fallback_exercised",
                    "trigger",
                    "target_route_id",
                    "result",
                    "error_category",
                },
                "fallback_observation",
            )
        else:
            raise ContinuityValidationError("fallback_attempted")
        observation = cls(
            attempted=attempted,
            trigger=(
                _parse_enum(data["trigger"], FallbackTrigger, "fallback_trigger")
                if attempted
                else None
            ),
            target_route_id=data.get("target_route_id"),
            result=(
                _parse_enum(data["result"], Outcome, "fallback_result")
                if attempted
                else None
            ),
            error_category=(
                _optional_enum(
                    data.get("error_category"),
                    ErrorCategory,
                    "fallback_error_category",
                )
                if attempted
                else None
            ),
        )
        if data["fallback_exercised"] is not observation.exercised:
            raise ContinuityValidationError("unobserved_fallback")
        return observation

    def to_dict(self) -> dict[str, Any]:
        if not self.attempted:
            return {
                "attempted": False,
                "fallback_exercised": False,
            }
        return {
            "attempted": True,
            "fallback_exercised": True,
            "trigger": self.trigger.value,
            "target_route_id": self.target_route_id,
            "result": self.result.value,
            "error_category": (
                self.error_category.value if self.error_category is not None else None
            ),
        }


@dataclass(frozen=True)
class RotationCase:
    case_id: str
    before: Outcome
    after: Outcome
    delta: float
    before_error_category: ErrorCategory | None
    after_error_category: ErrorCategory | None
    fallback: FallbackObservation

    def __post_init__(self) -> None:
        _opaque_id(self.case_id, "case_", "case_id")
        _require_enum(self.before, Outcome, "before_outcome")
        _require_enum(self.after, Outcome, "after_outcome")
        _bounded_number(self.delta, -1.0, 1.0, "delta")
        _validate_error_binding(self.before, self.before_error_category, "before_error_category")
        _validate_error_binding(self.after, self.after_error_category, "after_error_category")
        if not isinstance(self.fallback, FallbackObservation):
            raise ContinuityValidationError("fallback_observation")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> RotationCase:
        data = _require_mapping(value, "rotation_case")
        _require_exact_keys(
            data,
            {
                "case_id",
                "before",
                "after",
                "delta",
                "before_error_category",
                "after_error_category",
                "fallback",
            },
            "rotation_case",
        )
        return cls(
            case_id=data["case_id"],
            before=_parse_enum(data["before"], Outcome, "before_outcome"),
            after=_parse_enum(data["after"], Outcome, "after_outcome"),
            delta=data["delta"],
            before_error_category=_optional_enum(
                data["before_error_category"],
                ErrorCategory,
                "before_error_category",
            ),
            after_error_category=_optional_enum(
                data["after_error_category"],
                ErrorCategory,
                "after_error_category",
            ),
            fallback=FallbackObservation.from_dict(data["fallback"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "before": self.before.value,
            "after": self.after.value,
            "delta": float(self.delta),
            "before_error_category": (
                self.before_error_category.value
                if self.before_error_category is not None
                else None
            ),
            "after_error_category": (
                self.after_error_category.value
                if self.after_error_category is not None
                else None
            ),
            "fallback": self.fallback.to_dict(),
        }


@dataclass(frozen=True)
class RotationSummary:
    passed: int
    degraded: int
    failed: int

    def __post_init__(self) -> None:
        for count in (self.passed, self.degraded, self.failed):
            _bounded_int(count, 0, 1_000_000, "summary_count")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> RotationSummary:
        data = _require_mapping(value, "rotation_summary")
        _require_exact_keys(data, {"passed", "degraded", "failed"}, "rotation_summary")
        return cls(
            passed=data["passed"],
            degraded=data["degraded"],
            failed=data["failed"],
        )

    def to_dict(self) -> dict[str, int]:
        return {
            "passed": self.passed,
            "degraded": self.degraded,
            "failed": self.failed,
        }


@dataclass(frozen=True)
class RotationReceiptDraft:
    """Validated measured-diff inputs before signing and audit binding."""

    schema_version: str
    receipt_id: str
    evidence_mode: EvidenceMode
    from_route: str
    to_route: str
    from_contract: ContractBinding
    to_contract: ContractBinding
    eval_suite: EvalSuiteBinding
    run_id: str
    prior_baseline: BaselineBinding
    ts: str
    cases: tuple[RotationCase, ...]
    summary: RotationSummary

    def __post_init__(self) -> None:
        _exact_version(self.schema_version, RECEIPT_SCHEMA_VERSION, "receipt_schema_version")
        _opaque_id(self.receipt_id, "rot_", "receipt_id")
        _require_enum(self.evidence_mode, EvidenceMode, "evidence_mode")
        _opaque_id(self.from_route, "route_", "from_route")
        _opaque_id(self.to_route, "route_", "to_route")
        if self.from_route == self.to_route:
            raise ContinuityValidationError("route_rotation")
        if not isinstance(self.from_contract, ContractBinding):
            raise ContinuityValidationError("from_contract")
        if not isinstance(self.to_contract, ContractBinding):
            raise ContinuityValidationError("to_contract")
        if self.from_contract.route_id != self.from_route:
            raise ContinuityValidationError("from_contract_route")
        if self.to_contract.route_id != self.to_route:
            raise ContinuityValidationError("to_contract_route")
        if not isinstance(self.eval_suite, EvalSuiteBinding):
            raise ContinuityValidationError("eval_suite")
        _opaque_id(self.run_id, "run_", "run_id")
        if not isinstance(self.prior_baseline, BaselineBinding):
            raise ContinuityValidationError("prior_baseline")
        _utc_timestamp(self.ts)
        if not isinstance(self.cases, tuple) or not self.cases:
            raise ContinuityValidationError("cases")
        if len(self.cases) > 100_000:
            raise ContinuityValidationError("cases")
        if any(not isinstance(case, RotationCase) for case in self.cases):
            raise ContinuityValidationError("cases")
        case_ids = [case.case_id for case in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise ContinuityValidationError("duplicate_case_id")
        if not isinstance(self.summary, RotationSummary):
            raise ContinuityValidationError("summary")
        expected = {
            Outcome.PASS: self.summary.passed,
            Outcome.DEGRADED: self.summary.degraded,
            Outcome.FAILED: self.summary.failed,
        }
        actual = {outcome: 0 for outcome in Outcome}
        for case in self.cases:
            actual[case.after] += 1
        if actual != expected:
            raise ContinuityValidationError("summary_mismatch")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> RotationReceiptDraft:
        data = _require_mapping(value, "rotation_receipt_draft")
        _require_exact_keys(
            data,
            {
                "schema_version",
                "receipt_id",
                "evidence_mode",
                "from_route",
                "to_route",
                "from_contract",
                "to_contract",
                "eval_suite",
                "run_id",
                "prior_baseline",
                "ts",
                "cases",
                "summary",
            },
            "rotation_receipt_draft",
        )
        cases = data["cases"]
        if not isinstance(cases, list):
            raise ContinuityValidationError("cases")
        return cls(
            schema_version=data["schema_version"],
            receipt_id=data["receipt_id"],
            evidence_mode=_parse_enum(
                data["evidence_mode"],
                EvidenceMode,
                "evidence_mode",
            ),
            from_route=data["from_route"],
            to_route=data["to_route"],
            from_contract=ContractBinding.from_dict(data["from_contract"]),
            to_contract=ContractBinding.from_dict(data["to_contract"]),
            eval_suite=EvalSuiteBinding.from_dict(data["eval_suite"]),
            run_id=data["run_id"],
            prior_baseline=BaselineBinding.from_dict(data["prior_baseline"]),
            ts=data["ts"],
            cases=tuple(RotationCase.from_dict(item) for item in cases),
            summary=RotationSummary.from_dict(data["summary"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "evidence_mode": self.evidence_mode.value,
            "from_route": self.from_route,
            "to_route": self.to_route,
            "from_contract": self.from_contract.to_dict(),
            "to_contract": self.to_contract.to_dict(),
            "eval_suite": self.eval_suite.to_dict(),
            "run_id": self.run_id,
            "prior_baseline": self.prior_baseline.to_dict(),
            "ts": self.ts,
            "cases": [case.to_dict() for case in self.cases],
            "summary": self.summary.to_dict(),
        }


@dataclass(frozen=True)
class SignedRotationReceipt:
    """A versioned, signed, audit-bound measured diff."""

    draft: RotationReceiptDraft
    signing_version: str
    signed_by: str
    audit_seq: int
    receipt_hash: str
    signature: str

    def __post_init__(self) -> None:
        if not isinstance(self.draft, RotationReceiptDraft):
            raise ContinuityValidationError("rotation_receipt_draft")
        _exact_version(
            self.signing_version,
            RECEIPT_SIGNING_VERSION,
            "receipt_signing_version",
        )
        _safe_principal(self.signed_by)
        _bounded_int(self.audit_seq, 1, 9_223_372_036_854_775_807, "audit_seq")
        _hash(self.receipt_hash, "receipt_hash")
        _signature(self.signature)
        if self.receipt_hash != content_hash(self.unsigned_payload()):
            raise ContinuityValidationError("receipt_hash_mismatch")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> SignedRotationReceipt:
        data = _require_mapping(value, "signed_rotation_receipt")
        draft_keys = {
            "schema_version",
            "receipt_id",
            "evidence_mode",
            "from_route",
            "to_route",
            "from_contract",
            "to_contract",
            "eval_suite",
            "run_id",
            "prior_baseline",
            "ts",
            "cases",
            "summary",
        }
        _require_exact_keys(
            data,
            draft_keys
            | {
                "signing_version",
                "signed_by",
                "audit_seq",
                "receipt_hash",
                "signature",
            },
            "signed_rotation_receipt",
        )
        draft = RotationReceiptDraft.from_dict({key: data[key] for key in draft_keys})
        return cls(
            draft=draft,
            signing_version=data["signing_version"],
            signed_by=data["signed_by"],
            audit_seq=data["audit_seq"],
            receipt_hash=data["receipt_hash"],
            signature=data["signature"],
        )

    def unsigned_payload(self) -> dict[str, Any]:
        return {
            **self.draft.to_dict(),
            "signing_version": self.signing_version,
            "signed_by": self.signed_by,
            "audit_seq": self.audit_seq,
        }

    def signable_payload(self) -> dict[str, Any]:
        return {
            **self.unsigned_payload(),
            "receipt_hash": self.receipt_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.signable_payload(),
            "signature": self.signature,
        }

    def render(self) -> str:
        return canonical_json(self.to_dict()) + "\n"


def _require_mapping(value: Any, category: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ContinuityValidationError(category)
    return value


def _require_exact_keys(
    value: Mapping[str, Any],
    required: set[str],
    category: str,
    *,
    optional: set[str] | None = None,
) -> None:
    optional = optional or set()
    if set(value) - (required | optional) or required - set(value):
        raise ContinuityValidationError(f"{category}_fields")


def _reject_secret_markers(value: str) -> None:
    lowered = value.casefold()
    if any(marker in lowered for marker in _SECRET_MARKERS):
        raise ContinuityValidationError("secret_sentinel")


def _safe_label(value: Any, category: str) -> str:
    if not isinstance(value, str):
        raise ContinuityValidationError(category)
    _reject_secret_markers(value)
    if not _LABEL_RE.fullmatch(value):
        raise ContinuityValidationError(category)
    return value


def _safe_region(value: Any) -> str:
    if not isinstance(value, str):
        raise ContinuityValidationError("residency")
    _reject_secret_markers(value)
    if not _REGION_RE.fullmatch(value):
        raise ContinuityValidationError("residency")
    return value


def _safe_principal(value: Any) -> str:
    if not isinstance(value, str):
        raise ContinuityValidationError("signed_by")
    _reject_secret_markers(value)
    if not _PRINCIPAL_RE.fullmatch(value):
        raise ContinuityValidationError("signed_by")
    return value


def _opaque_id(value: Any, prefix: str, category: str) -> str:
    if not isinstance(value, str):
        raise ContinuityValidationError(category)
    _reject_secret_markers(value)
    if not value.startswith(prefix):
        raise ContinuityValidationError(category)
    body = value[len(prefix):]
    if not 12 <= len(body) <= 80 or not re.fullmatch(r"[A-Za-z0-9_-]+", body):
        raise ContinuityValidationError(category)
    return value


def _version_token(value: Any, category: str) -> str:
    if not isinstance(value, str):
        raise ContinuityValidationError(category)
    _reject_secret_markers(value)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}", value):
        raise ContinuityValidationError(category)
    return value


def _exact_version(value: Any, expected: str, category: str) -> None:
    if value != expected:
        raise ContinuityValidationError(category)


def _hash(value: Any, category: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        raise ContinuityValidationError(category)
    return value


def _signature(value: Any) -> str:
    if not isinstance(value, str) or not _SIGNATURE_RE.fullmatch(value):
        raise ContinuityValidationError("signature")
    return value


def _require_bool(value: Any, category: str) -> bool:
    if type(value) is not bool:
        raise ContinuityValidationError(category)
    return value


def _bounded_int(value: Any, minimum: int, maximum: int, category: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ContinuityValidationError(category)
    return value


def _bounded_number(value: Any, minimum: float, maximum: float, category: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContinuityValidationError(category)
    numeric = float(value)
    if not math.isfinite(numeric) or not minimum <= numeric <= maximum:
        raise ContinuityValidationError(category)
    return numeric


def _parse_enum(value: Any, enum_cls: type[Enum], category: str):
    try:
        return enum_cls(value)
    except (TypeError, ValueError) as exc:
        raise ContinuityValidationError(category) from exc


def _optional_enum(value: Any, enum_cls: type[Enum], category: str):
    return None if value is None else _parse_enum(value, enum_cls, category)


def _require_enum(value: Any, enum_cls: type[Enum], category: str) -> None:
    if not isinstance(value, enum_cls):
        raise ContinuityValidationError(category)


def _validate_error_binding(
    outcome: Outcome | None,
    error_category: ErrorCategory | None,
    category: str,
) -> None:
    if outcome is Outcome.FAILED:
        _require_enum(error_category, ErrorCategory, category)
    elif error_category is not None:
        raise ContinuityValidationError(category)


def _utc_timestamp(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 40:
        raise ContinuityValidationError("timestamp")
    _reject_secret_markers(value)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContinuityValidationError("timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ContinuityValidationError("timestamp")
    return value
