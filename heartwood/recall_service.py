"""Warm recall runtime and localhost HTTP service for Phase 1 adoption use."""
from __future__ import annotations

import ctypes
import ctypes.util
import gc
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import ssl
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib import error, request

from .client import Heartwood
from .envelope import Policy
from .ergonomics import list_value, normalize_tenant, principal_from
from .importers.markdown import (
    build_memory_spec,
    dev_models as markdown_dev_models,
    load_markdown_documents,
)
from .policy import Principal
from .retrieval import get_embedder, get_reranker

_DEFAULT_CANARY_TENANT = "tenant:__heartwood_canary__"
_DEFAULT_INGESTION_SLA_S = 6 * 60 * 60
_DEFAULT_RSS_CEILING_MB = 4096.0
_DEFAULT_RSS_WARN_MB = 2048.0
_DEFAULT_RSS_SUSTAIN_SAMPLES = 3
_DEFAULT_RSS_SUSTAIN_WINDOW_S = 60.0
_DEFAULT_WATCHDOG_INTERVAL_S = 30.0
_DEFAULT_ROUNDTRIP_BUDGET_S = 2.0
_DEFAULT_ROUNDTRIP_CACHE_S = _DEFAULT_WATCHDOG_INTERVAL_S
_CANARY_MARKER_PREFIX = "heartwood-roundtrip-canary"
_CANARY_CLEANUP_REASON = "verify_roundtrip hard cleanup"
_LOCAL_DIAGNOSTIC_ADMIN_ROLES = frozenset({"heartwood:diagnostics", "heartwood:admin"})
_MIN_WATCHDOG_INTERVAL_S = 0.1
_DEFAULT_LAUNCHD_LABEL = "com.heartwood.recall"
_DEFAULT_DIAG_LOG = "serve-recall.diag.log"
_DEFAULT_MALLOC_PRESSURE_RELIEF_RECALLS = 1
_DEFAULT_RATE_LIMIT_REQUESTS = 60
_DEFAULT_RATE_LIMIT_WINDOW_S = 60.0
_DEFAULT_MAX_K = 50
_DEFAULT_MAX_TOPC = 200
_LOCAL_READINESS_PATH = "/local/readiness"
_LOCAL_VERIFY_ROUNDTRIP_PATH = "/local/verify_roundtrip"
_LOCAL_VERIFY_INGESTED_PATH = "/local/verify_ingested"
_TASK_VM_INFO = 22
_KERN_SUCCESS = 0
_MALLOC_PRESSURE_RELIEF_FN = None
_MALLOC_PRESSURE_RELIEF_LOOKED_UP = False
_MALLOC_TRIM_FN = None
_MALLOC_TRIM_LOOKED_UP = False


class _TaskVMInfo(ctypes.Structure):
    _fields_ = [
        ("virtual_size", ctypes.c_uint64),
        ("region_count", ctypes.c_int32),
        ("page_size", ctypes.c_int32),
        ("resident_size", ctypes.c_uint64),
        ("resident_size_peak", ctypes.c_uint64),
        ("device", ctypes.c_uint64),
        ("device_peak", ctypes.c_uint64),
        ("internal", ctypes.c_uint64),
        ("internal_peak", ctypes.c_uint64),
        ("external", ctypes.c_uint64),
        ("external_peak", ctypes.c_uint64),
        ("reusable", ctypes.c_uint64),
        ("reusable_peak", ctypes.c_uint64),
        ("purgeable_volatile_pmap", ctypes.c_uint64),
        ("purgeable_volatile_resident", ctypes.c_uint64),
        ("purgeable_volatile_virtual", ctypes.c_uint64),
        ("compressed", ctypes.c_uint64),
        ("compressed_peak", ctypes.c_uint64),
        ("compressed_lifetime", ctypes.c_uint64),
        ("phys_footprint", ctypes.c_uint64),
        ("min_address", ctypes.c_uint64),
        ("max_address", ctypes.c_uint64),
        ("ledger_phys_footprint_peak", ctypes.c_int64),
        ("ledger_purgeable_nonvolatile", ctypes.c_int64),
        ("ledger_purgeable_nonvolatile_compressed", ctypes.c_int64),
        ("ledger_purgeable_volatile", ctypes.c_int64),
        ("ledger_purgeable_volatile_compressed", ctypes.c_int64),
        ("ledger_tag_network_nonvolatile", ctypes.c_int64),
        ("ledger_tag_network_nonvolatile_compressed", ctypes.c_int64),
        ("ledger_tag_network_volatile", ctypes.c_int64),
        ("ledger_tag_network_volatile_compressed", ctypes.c_int64),
        ("ledger_tag_media_footprint", ctypes.c_int64),
        ("ledger_tag_media_footprint_compressed", ctypes.c_int64),
        ("ledger_tag_media_nofootprint", ctypes.c_int64),
        ("ledger_tag_media_nofootprint_compressed", ctypes.c_int64),
        ("ledger_tag_graphics_footprint", ctypes.c_int64),
        ("ledger_tag_graphics_footprint_compressed", ctypes.c_int64),
        ("ledger_tag_graphics_nofootprint", ctypes.c_int64),
        ("ledger_tag_graphics_nofootprint_compressed", ctypes.c_int64),
        ("ledger_tag_neural_footprint", ctypes.c_int64),
        ("ledger_tag_neural_footprint_compressed", ctypes.c_int64),
        ("ledger_tag_neural_nofootprint", ctypes.c_int64),
        ("ledger_tag_neural_nofootprint_compressed", ctypes.c_int64),
        ("limit_bytes_remaining", ctypes.c_uint64),
    ]


class RecallReadinessError(RuntimeError):
    """Raised when production recall startup would silently serve degraded models."""

    def __init__(self, readiness: dict[str, Any]):
        self.readiness = readiness
        checks = readiness.get("checks", {})
        message = {
            "error": "heartwood recall startup readiness failed",
            "checks": checks,
            "embedder": readiness.get("embedder"),
            "reranker": readiness.get("reranker"),
            "db_embedding_dimensions": readiness.get("db_embedding_dimensions"),
        }
        super().__init__(json.dumps(message, sort_keys=True, separators=(",", ":")))


def principal_from_payload(payload: dict[str, Any], *, default_tenant: str) -> Principal:
    return principal_from(
        None,
        id=str(payload.get("principal_id") or payload.get("principal") or "agent:recall"),
        tenant=normalize_tenant(default_tenant),
        roles=(),
        attrs=(),
        clearance="internal",
        default_tenant=default_tenant,
    )


def filters_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    filters = dict(payload.get("filters") or {})
    for key in (
        "subject",
        "method",
        "intent",
        "effective_at",
    ):
        if payload.get(key) not in (None, ""):
            filters[key] = payload[key]
    list_fields = {
        "kind": "kinds",
        "kinds": "kinds",
        "memory_types": "memory_types",
        "policy_scopes": "policy_scopes",
        "allowed_classifications": "allowed_classifications",
        "denied_subjects": "denied_subjects",
        "entities": "entities",
    }
    for source_key, target_key in list_fields.items():
        if payload.get(source_key) not in (None, ""):
            values = list_value(payload[source_key])
            existing = list_value(filters.get(target_key))
            filters[target_key] = tuple(existing + values)
    if payload.get("typed") is not None:
        filters["typed"] = bool(payload["typed"])
    return filters


def percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil((p / 100.0) * len(ordered)) - 1))
    return ordered[index]


@dataclass(frozen=True)
class RecallCredential:
    token_digest: str
    principal: Principal
    rate_limit_requests: int = _DEFAULT_RATE_LIMIT_REQUESTS
    rate_limit_window_s: float = _DEFAULT_RATE_LIMIT_WINDOW_S


@dataclass(frozen=True)
class MemorySample:
    ps_rss_mb: float | None
    phys_footprint_mb: float | None

    @property
    def enforced_mb(self) -> float | None:
        return self.phys_footprint_mb if self.phys_footprint_mb is not None else self.ps_rss_mb


class RecallCredentialStore:
    """Loads per-org bearer verifiers without retaining plaintext tokens."""

    def __init__(
        self,
        *,
        token: str | None = None,
        token_file: str | Path | None = None,
        default_tenant: str,
        default_principal_id: str = "agent:recall",
    ):
        self.default_tenant = normalize_tenant(default_tenant)
        self.default_principal_id = default_principal_id
        self.token_file = Path(token_file) if token_file else None
        self._static_credentials = (
            self._credentials_from_text(token, source="token")
            if token is not None
            else ()
        )
        if self.token_file is not None:
            # Fail closed at startup for empty or malformed files, while still
            # reloading on each request so rotation does not need a redeploy.
            self.credentials()

    @property
    def configured(self) -> bool:
        return bool(self.token_file or self._static_credentials)

    def credentials(self) -> tuple[RecallCredential, ...]:
        if self.token_file is None:
            return self._static_credentials
        text = self.token_file.read_text(encoding="utf-8")
        return self._credentials_from_text(text, source=f"token file {self.token_file}")

    def authenticate(self, authorization: str | None) -> RecallCredential | None:
        if not authorization:
            return None
        scheme, _, raw_token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not raw_token.strip():
            return None
        candidate_digest = _token_digest(raw_token.strip())
        for credential in self.credentials():
            if hmac.compare_digest(candidate_digest, credential.token_digest):
                return credential
        return None

    def _credentials_from_text(self, text: str | None, *, source: str) -> tuple[RecallCredential, ...]:
        if text is None or not text.strip():
            raise ValueError(f"{source} is empty")
        stripped = text.strip()
        if stripped[0] in "{[":
            data = json.loads(stripped)
            if isinstance(data, dict) and isinstance(data.get("credentials"), list):
                entries = data["credentials"]
            elif isinstance(data, list):
                entries = data
            elif isinstance(data, dict):
                entries = [data]
            else:
                raise ValueError(f"{source} must contain a credential object or list")
            credentials = tuple(self._credential_from_mapping(entry, source=source) for entry in entries)
            if not credentials:
                raise ValueError(f"{source} has no credentials")
            return credentials
        return (
            self._credential_from_mapping(
                {"token": stripped},
                source=source,
            ),
        )

    def _credential_from_mapping(self, value: Any, *, source: str) -> RecallCredential:
        if not isinstance(value, dict):
            raise ValueError(f"{source} credential entries must be objects")
        raw_token = value.get("token")
        token_digest = value.get("token_sha256") or value.get("token_digest")
        if raw_token is not None:
            raw_token = str(raw_token).strip()
            if not raw_token:
                raise ValueError(f"{source} credential entry token is empty")
            token_digest = _token_digest(raw_token)
        if not token_digest:
            raise ValueError(f"{source} credential entry missing token or token_sha256")
        tenant = normalize_tenant(value.get("tenant") or self.default_tenant)
        principal = principal_from(
            None,
            id=str(value.get("principal_id") or value.get("principal") or self.default_principal_id),
            tenant=tenant,
            roles=value.get("roles", ()),
            attrs=value.get("attrs", ()),
            clearance=str(value.get("clearance") or "internal"),
            default_tenant=self.default_tenant,
        )
        rate_limit = value.get("rate_limit") if isinstance(value.get("rate_limit"), dict) else {}
        requests = int(
            value.get("rate_limit_requests")
            or rate_limit.get("requests")
            or os.environ.get("HEARTWOOD_RECALL_RATE_LIMIT_REQUESTS", _DEFAULT_RATE_LIMIT_REQUESTS)
        )
        window_s = float(
            value.get("rate_limit_window_s")
            or rate_limit.get("window_seconds")
            or os.environ.get("HEARTWOOD_RECALL_RATE_LIMIT_WINDOW_S", _DEFAULT_RATE_LIMIT_WINDOW_S)
        )
        return RecallCredential(
            token_digest=str(token_digest),
            principal=principal,
            rate_limit_requests=max(1, requests),
            rate_limit_window_s=max(1.0, window_s),
        )


class RecallRateLimiter:
    """Per-credential sliding-window limiter.

    SECURITY INVARIANT (#10003187): the bucket key is ``credential.token_digest`` —
    the SHA-256 digest of the *authenticated* bearer token, a trusted identity the
    server derives itself. It is NEVER keyed off a client-supplied header such as
    ``X-Forwarded-For`` (whose leftmost hop is attacker-controlled behind a proxy
    and would let a caller mint a fresh bucket per request to evade the limit).
    The only client-address read in this service is the loopback gate, which uses
    the real TCP socket peer (``self.client_address``), not a header. Do not change
    this key to anything a request can set. Regression test:
    ``tests/test_warm_recall.py::test_recall_rate_limit_keys_off_credential_not_spoofable_xff``.
    """

    def __init__(self) -> None:
        self._hits: dict[str, tuple[deque[float], float]] = {}
        self._lock = threading.Lock()

    def check(self, credential: RecallCredential) -> tuple[bool, int, int]:
        now = time.monotonic()
        window_s = credential.rate_limit_window_s
        with self._lock:
            self._evict_expired(now)
            bucket = self._hits.get(credential.token_digest)
            if bucket is None:
                hits = deque()
            else:
                hits = bucket[0]
            self._hits[credential.token_digest] = (hits, window_s)
            while hits and now - hits[0] >= window_s:
                hits.popleft()
            if len(hits) >= credential.rate_limit_requests:
                retry_after = max(1, int(math.ceil(window_s - (now - hits[0]))))
                return False, 0, retry_after
            hits.append(now)
            return True, credential.rate_limit_requests - len(hits), 0

    def _evict_expired(self, now: float) -> None:
        expired = []
        for token_digest, (hits, window_s) in self._hits.items():
            while hits and now - hits[0] >= window_s:
                hits.popleft()
            if not hits:
                expired.append(token_digest)
        for token_digest in expired:
            self._hits.pop(token_digest, None)


class RecallEngine:
    """Keeps models, indexes, and tenant clients warm across recall calls."""

    def __init__(
        self,
        *,
        db_path: str | Path,
        default_tenant: str = "tenant:ops",
        dev_models: bool = False,
        index: str = "numpy",
        adopter_tenants: list[str] | tuple[str, ...] | None = None,
    ):
        self.db_path = str(db_path)
        self.default_tenant = normalize_tenant(default_tenant)
        self.adopter_tenants = {
            self.default_tenant,
            *(normalize_tenant(tenant, default=self.default_tenant) for tenant in (adopter_tenants or ())),
        }
        if dev_models:
            self.embedder_pair, self.reranker_pair = markdown_dev_models()
        else:
            self.embedder_pair = get_embedder()
            self.reranker_pair = get_reranker()
        self.index = index
        self.clients: dict[str, Heartwood] = {}
        # RecallHTTPServer is intentionally single-threaded for the local daemon.
        # Keep this engine lock anyway: caches, clients, and numpy index state are
        # shared mutable objects, so any future threaded server stays serialized.
        self._lock = threading.RLock()
        self.latencies_ms: deque[float] = deque(maxlen=2000)
        self._recall_total = 0
        self._verify_roundtrip_cache: dict[str, Any] | None = None
        self._verify_roundtrip_cache_at = 0.0
        self.started_at = time.time()

    @property
    def embedder_name(self) -> str:
        return self.embedder_pair[1]

    @property
    def reranker_name(self) -> str:
        return self.reranker_pair[1]

    def client(self, tenant: str | None = None) -> Heartwood:
        with self._lock:
            tenant_id = normalize_tenant(tenant or self.default_tenant)
            if tenant_id not in self.clients:
                self.clients[tenant_id] = Heartwood(
                    path=self.db_path,
                    tenant=tenant_id,
                    embedder=self.embedder_pair,
                    reranker=self.reranker_pair,
                    index=self.index,
                )
            return self.clients[tenant_id]

    def warm(self, tenants: list[str] | tuple[str, ...] | None = None) -> dict[str, Any]:
        with self._lock:
            tenants = list(tenants or (self.default_tenant,))
            warmed = [normalize_tenant(tenant) for tenant in tenants]
            self.embedder_pair[0](["heartwood warm recall"])
            warm_text = ("heartwood warm recall " * 96).strip()
            warm_candidates = [warm_text] * 50
            for i in range(20):
                self.reranker_pair[0](f"heartwood warm recall {i}", warm_candidates)
            cache_counts = {}
            for tenant in warmed:
                cache_counts[tenant] = self.client(tenant).warm_recall_cache()
            return {
                "ok": True,
                "warmed_count": len(warmed),
                "warmed_text_cache_count": sum(cache_counts.values()),
                "embedder": self.embedder_name,
                "reranker": self.reranker_name,
                "index": self.index,
            }

    def recall(
        self,
        payload: dict[str, Any],
        *,
        principal: Principal | None = None,
        allow_payload_principal: bool = True,
    ) -> dict[str, Any]:
        with self._lock:
            cue = str(payload.get("query") or payload.get("cue") or "").strip()
            if not cue:
                raise ValueError("recall requires query or cue")
            if principal is None:
                if not allow_payload_principal:
                    raise PermissionError("server principal required")
                principal = principal_from_payload(payload, default_tenant=self.default_tenant)
            k = _bounded_positive_int(
                payload.get("k"),
                default=5,
                max_default=_DEFAULT_MAX_K,
                max_env_name="HEARTWOOD_RECALL_MAX_K",
                field="k",
            )
            topc = _bounded_positive_int(
                payload.get("topc") or payload.get("top_candidates"),
                default=50,
                max_default=_DEFAULT_MAX_TOPC,
                max_env_name="HEARTWOOD_RECALL_MAX_TOPC",
                field="topc",
            )
            topc = max(k, topc)
            started = time.perf_counter()
            out = self.client(principal.tenant).recall(
                cue,
                principal=principal,
                filters=filters_from_payload(payload),
                k=k,
                topc=topc,
            )
            latency_ms = (time.perf_counter() - started) * 1000.0
            self.latencies_ms.append(latency_ms)
            self._recall_total += 1
            _maybe_relieve_allocator_pressure(self._recall_total)
            return {
                "ok": True,
                "tenant": principal.tenant,
                "principal_id": principal.id,
                "principal": _principal_payload(principal),
                "latency_ms": round(latency_ms, 3),
                "recall_id": out["recall_id"],
                "index_lag": out["index_lag"],
                "result_count": len(out["results"]),
                "results": out["results"],
                "models": {
                    "embedder": self.embedder_name,
                    "reranker": self.reranker_name,
                    "index": self.index,
                },
            }

    def explain_recall(
        self,
        payload: dict[str, Any],
        *,
        principal: Principal | None = None,
        allow_payload_principal: bool = True,
    ) -> dict[str, Any]:
        """Run a recall and return its safe, in-process explanation receipt."""
        recall = self.recall(
            payload,
            principal=principal,
            allow_payload_principal=allow_payload_principal,
        )
        receipt = dict(self.client(recall["tenant"]).explain_recall(recall["recall_id"]))
        # Keep this licensee-facing surface aligned with the MCP explanation
        # boundary: denied candidates and their reasons are not observable.
        receipt.pop("denied", None)
        receipt.pop("denied_reasons", None)
        if isinstance(receipt.get("strict_dropped"), dict):
            receipt["strict_dropped"].pop("ids", None)
        return {
            "ok": True,
            "tenant": recall["tenant"],
            "principal_id": recall["principal_id"],
            "recall_id": recall["recall_id"],
            "explanation": receipt,
        }

    def verify_roundtrip(
        self,
        payload: dict[str, Any],
        *,
        principal: Principal,
    ) -> dict[str, Any]:
        """Write a canary through Heartwood and prove it is immediately recallable."""
        with self._lock:
            _require_local_diagnostics_admin(principal)
            cache_s = _roundtrip_cache_seconds()
            now = time.monotonic()
            if (
                self._verify_roundtrip_cache is not None
                and cache_s > 0
                and now - self._verify_roundtrip_cache_at < cache_s
            ):
                return {
                    **self._verify_roundtrip_cache,
                    "cached": True,
                    "canary_lifecycle_executed": False,
                    "cache_age_seconds": round(now - self._verify_roundtrip_cache_at, 3),
                    "cache_ttl_seconds": round(cache_s, 3),
                }

            result = self._verify_roundtrip_lifecycle(payload, principal=principal)
            self._verify_roundtrip_cache = {
                **result,
                "cached": False,
                "canary_lifecycle_executed": True,
                "cache_age_seconds": 0.0,
                "cache_ttl_seconds": round(cache_s, 3),
            }
            self._verify_roundtrip_cache_at = time.monotonic()
            return self._verify_roundtrip_cache

    def _verify_roundtrip_lifecycle(
        self,
        payload: dict[str, Any],
        *,
        principal: Principal,
    ) -> dict[str, Any]:
        wrote_at = time.time()
        marker = _canary_marker(wrote_at=wrote_at)
        canary_tenant = _canary_tenant()
        self._assert_reserved_canary_tenant(canary_tenant)
        canary_principal = Principal(
            id=principal.id,
            tenant=canary_tenant,
            roles=tuple(principal.roles),
            attrs=tuple(principal.attrs),
            clearance=principal.clearance,
        )
        subject = f"heartwood:diagnostic:verify_roundtrip:{marker}"
        source_uri = f"heartwood://diagnostics/verify_roundtrip/{marker}"
        memory_id = "diag_roundtrip_" + hashlib.sha256(
            f"{canary_tenant}|{marker}|{wrote_at}".encode("utf-8")
        ).hexdigest()[:24]
        content = f"Heartwood diagnostic canary marker {marker}."
        cleanup_receipt: dict[str, Any] | None = None
        cleanup_error: str | None = None
        recall_error: str | None = None
        recallable_at: float | None = None
        recall_result_count = 0
        try:
            self.client(canary_tenant).remember(
                content,
                subject=subject,
                subject_ids=(subject, marker),
                created_by=principal.id,
                kind="semantic",
                epistemic="observed-fact",
                confidence=1.0,
                salience=0.1,
                source={"kind": "diagnostic-canary", "uri": source_uri},
                policy=Policy(classification="public"),
                memory_id=memory_id,
                policy_scope="diagnostic-canary",
                source_ids=(source_uri, marker),
                index_text=f"{marker} Heartwood diagnostic canary",
            )

            budget_s = _nonnegative_float(
                payload.get("lag_budget_seconds"),
                default=_nonnegative_float_env(
                    "HEARTWOOD_RECALL_ROUNDTRIP_BUDGET_S",
                    _DEFAULT_ROUNDTRIP_BUDGET_S,
                ),
            )
            deadline = time.monotonic() + budget_s
            while True:
                try:
                    out = self.recall(
                        {
                            "query": f"{marker} {source_uri}",
                            "k": 5,
                            "topc": 12,
                            "filters": {"subject": subject},
                        },
                        principal=canary_principal,
                        allow_payload_principal=False,
                    )
                except Exception as exc:  # cleanup still runs in finally
                    recall_error = str(exc)
                    break
                recall_result_count = int(out.get("result_count") or 0)
                if any(result.get("id") == memory_id for result in out.get("results", [])):
                    recallable_at = time.time()
                    break
                if time.monotonic() >= deadline:
                    break
                time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        finally:
            try:
                cleanup_receipt = self.client(canary_tenant).forget(
                    subject,
                    mode="hard",
                    actor=principal.id,
                    reason=_CANARY_CLEANUP_REASON,
                )
            except Exception as exc:  # pragma: no cover - defensive, covered by result surface
                cleanup_error = str(exc)

        cleanup_ok = cleanup_error is None and bool(cleanup_receipt and cleanup_receipt.get("key_shredded"))
        elapsed_end = recallable_at or time.time()
        roundtrip_ok = recallable_at is not None
        return {
            "ok": roundtrip_ok and cleanup_ok,
            "roundtrip_ok": roundtrip_ok,
            "cleanup_ok": cleanup_ok,
            "cleanup_purged": int(cleanup_receipt.get("purged") or 0) if cleanup_receipt else 0,
            "cleanup_error": cleanup_error,
            "recall_error": recall_error,
            "canary_tenant": canary_tenant,
            "canary_subject": subject,
            "source_marker": marker,
            "memory_id": memory_id,
            "source_uri": source_uri,
            "classification": "public",
            "payload_marker_ignored": bool(payload.get("source_marker") or payload.get("marker")),
            "ingestion_lag_seconds": round(max(0.0, elapsed_end - wrote_at), 3),
            "lag_budget_seconds": round(budget_s, 3),
            "wrote_at": _iso_timestamp(wrote_at),
            "recallable_at": _iso_timestamp(recallable_at) if recallable_at else None,
            "recall_result_count": recall_result_count,
        }

    def _assert_reserved_canary_tenant(self, canary_tenant: str) -> None:
        configured = set(self.adopter_tenants)
        configured.update(_tenant_map_tenants(self.default_tenant))
        if canary_tenant in configured:
            raise ValueError("verify_roundtrip canary tenant must differ from configured adopter tenants")

    def verify_ingested(
        self,
        payload: dict[str, Any],
        *,
        principal: Principal,
    ) -> dict[str, Any]:
        """Check whether a named source marker is present and indexed without writing."""
        with self._lock:
            marker = str(payload.get("source_marker") or payload.get("marker") or "").strip()
            if not marker:
                raise ValueError("verify_ingested requires source_marker")
            requested_tenant = normalize_tenant(payload.get("tenant") or principal.tenant)
            canary_tenant = _canary_tenant()
            if requested_tenant != principal.tenant and requested_tenant != canary_tenant:
                raise PermissionError("verify_ingested tenant must match credential tenant or canary tenant")
            memory = self._memory_for_marker(requested_tenant, marker)
            source = _source_status_for_marker(marker)
            wrote_at = source.get("mtime") if source else None
            recallable_at = float(memory["created_at"]) if memory and memory.get("indexed") else None
            if wrote_at is None and memory is not None:
                wrote_at = float(memory["created_at"])
            end = recallable_at or time.time()
            lag = max(0.0, end - wrote_at) if wrote_at is not None else None
            return {
                "ok": bool(memory and memory.get("indexed")),
                "source_marker": marker,
                "tenant": requested_tenant,
                "present": memory is not None,
                "indexed": bool(memory and memory.get("indexed")),
                "memory_id": memory["id"] if memory else None,
                "source_uri": _memory_source_uri(memory) if memory else None,
                "wrote_at": _iso_timestamp(wrote_at) if wrote_at is not None else None,
                "recallable_at": _iso_timestamp(recallable_at) if recallable_at else None,
                "ingestion_lag_seconds": _round_or_none(lag),
            }

    def metrics(self) -> dict[str, Any]:
        with self._lock:
            memory = _current_memory_sample()
            return {
                "ok": True,
                "uptime_s": round(time.time() - self.started_at, 3),
                "recall_count": self._recall_total,
                "latency_sample_count": len(self.latencies_ms),
                "p50_latency_ms": _round_or_none(percentile(self.latencies_ms, 50)),
                "p95_latency_ms": _round_or_none(percentile(self.latencies_ms, 95)),
                "max_latency_ms": _round_or_none(
                    max(self.latencies_ms) if self.latencies_ms else None
                ),
                "rss_mb": _round_or_none(memory.ps_rss_mb),
                "ps_rss_mb": _round_or_none(memory.ps_rss_mb),
                "phys_footprint_mb": _round_or_none(memory.phys_footprint_mb),
                "memory_watchdog_metric": (
                    "phys_footprint_mb"
                    if memory.phys_footprint_mb is not None
                    else "ps_rss_mb"
                ),
                "rss_ceiling_mb": _round_or_none(_watchdog_ceiling_mb()),
                "models": {
                    "embedder": self.embedder_name,
                    "reranker": self.reranker_name,
                    "index": self.index,
                },
            }

    def health(self) -> dict[str, Any]:
        return {"ok": True, "service": "heartwood-recall"}

    def local_readiness(self) -> dict[str, Any]:
        with self._lock:
            embedder_vector = self.embedder_pair[0](["heartwood local readiness"])[0]
            embedder_dimension = int(len(embedder_vector))
            db_dimensions = self._db_embedding_dimensions()
            embedder_dev = _is_dev_model(self.embedder_name)
            reranker_dev = _is_dev_model(self.reranker_name)
            db_dimension_match = len(db_dimensions) == 1 and db_dimensions[0] == embedder_dimension
            ingestion = self._ingestion_readiness()
            model_ok = not embedder_dev and not reranker_dev and db_dimension_match
            return {
                "ok": model_ok and ingestion["ok"],
                "service": "heartwood-recall",
                "local_only": True,
                "embedder": {
                    "name": self.embedder_name,
                    "dimension": embedder_dimension,
                    "dev_fallback": embedder_dev,
                },
                "reranker": {
                    "name": self.reranker_name,
                    "dev_fallback": reranker_dev,
                },
                "index": self.index,
                "db_embedding_dimensions": db_dimensions,
                "ingestion": ingestion,
                "checks": {
                    "non_dev_embedder": not embedder_dev,
                    "non_dev_reranker": not reranker_dev,
                    "db_dimension_match": db_dimension_match,
                    "ingestion_lag_within_sla": ingestion["ok"],
                },
            }

    def assert_ready_to_serve(self, *, allow_dev_models: bool = False) -> dict[str, Any]:
        readiness = self.local_readiness()
        if readiness["ok"] or allow_dev_models:
            return readiness
        raise RecallReadinessError(readiness)

    def _db_embedding_dimensions(self) -> list[int]:
        rows = self.client(self.default_tenant).store.conn.execute(
            "SELECT DISTINCT emb_dim FROM memories WHERE indexed=1 AND emb_dim>0 ORDER BY emb_dim"
        ).fetchall()
        return [int(row["emb_dim"]) for row in rows]

    def _ingestion_readiness(self) -> dict[str, Any]:
        roots = _ingestion_source_roots()
        sla_seconds = _ingestion_sla_seconds()
        base = {
            "ok": True,
            "status": "ok",
            "configured": bool(roots),
            "sla_seconds": sla_seconds,
            "last_import_at": self._last_markdown_import_at(),
            "pending_sources_count": 0,
            "max_pending_lag_seconds": 0.0,
            "oldest_unindexed_source": None,
        }
        if not roots:
            return base

        now = time.time()
        pending = []
        documents = load_markdown_documents(roots)
        tenant_map = _json_env_mapping("HEARTWOOD_RECALL_TENANT_MAP_JSON")
        prefix_epistemic_map = _json_env_mapping("HEARTWOOD_RECALL_PREFIX_EPISTEMIC_MAP_JSON")
        for document in documents:
            if not document.content.strip():
                continue
            spec = build_memory_spec(
                document,
                default_tenant=self.default_tenant,
                tenant_map=tenant_map,
                prefix_epistemic_map=prefix_epistemic_map,
            )
            rows = self.client(spec.tenant).store.memories_by_source_path(
                spec.tenant,
                spec.relative_path,
                source_uri=spec.source_uri,
            )
            indexed_match = any(
                row.get("content_hash") == spec.content_hash and row.get("indexed")
                for row in rows
            )
            if indexed_match:
                continue
            try:
                mtime = document.path.stat().st_mtime
            except OSError:
                mtime = now
            pending.append(
                {
                    "relative_path": document.relative_path,
                    "source_uri": spec.source_uri,
                    "lag_seconds": max(0.0, now - mtime),
                    "mtime": mtime,
                }
            )

        if not pending:
            return base
        oldest = max(pending, key=lambda item: item["lag_seconds"])
        max_lag = float(oldest["lag_seconds"])
        ok = max_lag <= sla_seconds
        return {
            **base,
            "ok": ok,
            "status": "ok" if ok else "warn",
            "pending_sources_count": len(pending),
            "max_pending_lag_seconds": round(max_lag, 3),
            "oldest_unindexed_source": {
                "path": oldest["relative_path"],
                "source_uri": oldest["source_uri"],
                "wrote_at": _iso_timestamp(oldest["mtime"]),
            },
        }

    def _last_markdown_import_at(self) -> str | None:
        conn = self.client(self.default_tenant).store.conn
        try:
            row = conn.execute(
                "SELECT MAX(created_at) AS ts FROM memories "
                "WHERE json_extract(source_json, '$.kind')='markdown'"
            ).fetchone()
        except Exception:
            row = conn.execute(
                "SELECT MAX(created_at) AS ts FROM memories "
                "WHERE source_json LIKE '%\"kind\":\"markdown\"%' "
                "OR source_json LIKE '%\"kind\": \"markdown\"%'"
            ).fetchone()
        if row is None or row["ts"] is None:
            return None
        return _iso_timestamp(float(row["ts"]))

    def _memory_for_marker(self, tenant: str, marker: str) -> dict[str, Any] | None:
        for meta in self.client(tenant).store.candidate_meta(tenant):
            if _memory_matches_marker(meta, marker):
                return meta
        return None

    def forget(self, payload: dict[str, Any], *, principal: Principal | None = None) -> dict[str, Any]:
        with self._lock:
            subject = str(payload.get("subject") or "").strip()
            if not subject:
                raise ValueError("forget requires subject")
            mode = str(payload.get("mode") or "hard").strip()
            if mode != "hard":
                raise ValueError(f"unsupported forget mode: {mode}")
            tenant = principal.tenant if principal else normalize_tenant(payload.get("tenant") or self.default_tenant)
            receipt = self.client(tenant).forget(
                subject,
                mode=mode,
                actor=str(payload.get("actor") or "agent:recall-service"),
                reason=str(payload.get("reason") or ""),
                legal_basis=str(payload.get("legal_basis") or ""),
            )
            return {"ok": True, "tenant": tenant, **receipt}

    def close(self) -> None:
        with self._lock:
            for client in self.clients.values():
                client.store.close()
            self.clients.clear()


class RecallHTTPServer(HTTPServer):
    allow_reuse_address = True


def build_handler(
    engine: RecallEngine,
    *,
    token: str | None = None,
    token_file: str | Path | None = None,
):
    credential_store = RecallCredentialStore(
        token=token,
        token_file=token_file,
        default_tenant=engine.default_tenant,
    )
    rate_limiter = RecallRateLimiter()

    class Handler(BaseHTTPRequestHandler):
        server_version = "HeartwoodRecall/0.1"

        def log_message(self, format: str, *args):  # noqa: A002
            return

        def do_GET(self):  # noqa: N802
            if self.path == "/health":
                self._json(engine.health())
                return
            if self.path == _LOCAL_READINESS_PATH:
                if not self._local_diagnostics_allowed():
                    self._json({"ok": False, "error": "not_found"}, status=404)
                    return
                credential = self._authorized(require_token=credential_store.configured)
                if credential is False:
                    return
                self._json(engine.local_readiness())
                return
            if self.path == "/metrics":
                if self._authorized() is False:   # None (no-auth) and a valid credential both serve; only an explicit reject returns
                    return
                self._json(engine.metrics())
                return
            self._json({"ok": False, "error": "not_found"}, status=404)

        def do_POST(self):  # noqa: N802
            should_relieve_allocator = False
            try:
                if self.path in {_LOCAL_VERIFY_ROUNDTRIP_PATH, _LOCAL_VERIFY_INGESTED_PATH}:
                    if not self._local_diagnostics_allowed():
                        self._json({"ok": False, "error": "not_found"}, status=404)
                        return
                    credential = self._authorized(require_token=True)
                    if credential is False:
                        return
                    payload = self._read_json()
                    principal = credential.principal
                    if not _local_diagnostics_admin_allowed(principal):
                        self._json({"ok": False, "error": "diagnostic_admin_required"}, status=403)
                        return
                    if self.path == _LOCAL_VERIFY_ROUNDTRIP_PATH:
                        self._json(engine.verify_roundtrip(payload, principal=principal))
                    else:
                        self._json(engine.verify_ingested(payload, principal=principal))
                    return
                credential = None
                if self.path == "/forget":
                    credential = self._authorized(require_token=True)
                    if credential is False:
                        return
                else:
                    credential = self._authorized()
                    if credential is False:
                        return
                payload = self._read_json()
                if self.path in {"/recall", "/explain-recall"}:
                    should_relieve_allocator = True
                    principal = credential.principal if isinstance(credential, RecallCredential) else None
                    if self.path == "/recall":
                        self._json(
                            engine.recall(
                                payload,
                                principal=principal,
                                allow_payload_principal=not credential_store.configured,
                            )
                        )
                    else:
                        self._json(
                            engine.explain_recall(
                                payload,
                                principal=principal,
                                allow_payload_principal=not credential_store.configured,
                            )
                        )
                    return
                if self.path == "/forget":
                    principal = credential.principal if isinstance(credential, RecallCredential) else None
                    self._json(engine.forget(payload, principal=principal))
                    return
                if self.path == "/warm":
                    if isinstance(credential, RecallCredential):
                        tenants = [credential.principal.tenant]
                    else:
                        tenants = list_value(payload.get("tenants") or payload.get("tenant"))
                    self._json(engine.warm(tenants or None))
                    return
                self._json({"ok": False, "error": "not_found"}, status=404)
            except Exception as exc:
                self._json({"ok": False, "error": str(exc)}, status=400)
            finally:
                if should_relieve_allocator:
                    _relieve_allocator_pressure_now()

        def _authorized(self, *, require_token: bool = False) -> RecallCredential | bool | None:
            if require_token and not credential_store.configured:
                self._json({"ok": False, "error": "token_required"}, status=401)
                return False
            if not credential_store.configured:
                return None
            credential = credential_store.authenticate(self.headers.get("Authorization"))
            if credential is not None:
                allowed, remaining, retry_after = rate_limiter.check(credential)
                if allowed:
                    return credential
                self._json(
                    {
                        "ok": False,
                        "error": "rate_limited",
                        "retry_after_seconds": retry_after,
                    },
                    status=429,
                    headers={
                        "Retry-After": str(retry_after),
                        "X-RateLimit-Limit": str(credential.rate_limit_requests),
                        "X-RateLimit-Remaining": str(remaining),
                    },
                )
                return False
            self._json({"ok": False, "error": "unauthorized"}, status=401)
            return False

        def _local_diagnostics_allowed(self) -> bool:
            if not _env_bool("HEARTWOOD_RECALL_LOCAL_DIAGNOSTICS", False):
                return False
            return _is_loopback_address(str(self.client_address[0]))

        def _read_json(self) -> dict[str, Any]:
            raw_len = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(raw_len) if raw_len else b"{}"
            return json.loads(raw.decode("utf-8") or "{}")

        def _json(
            self,
            payload: dict[str, Any],
            *,
            status: int = 200,
            headers: dict[str, str] | None = None,
        ) -> None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def serve_recall(
    *,
    db_path: str | Path,
    host: str = "127.0.0.1",
    port: int = 8765,
    default_tenant: str = "tenant:ops",
    warm_tenants: list[str] | None = None,
    token: str | None = None,
    token_file: str | Path | None = None,
    tls_cert_file: str | Path | None = None,
    tls_key_file: str | Path | None = None,
    dev_models: bool = False,
    index: str = "numpy",
    warm_on_start: bool = True,
) -> None:
    _disable_core_dumps()
    _start_memory_watchdog()
    engine = RecallEngine(
        db_path=db_path,
        default_tenant=default_tenant,
        dev_models=dev_models,
        index=index,
        adopter_tenants=warm_tenants,
    )
    try:
        if warm_on_start:
            engine.warm(warm_tenants or [default_tenant])
        engine.assert_ready_to_serve(allow_dev_models=dev_models)
        server = RecallHTTPServer(
            (host, port),
            build_handler(engine, token=token, token_file=token_file),
        )
        if tls_cert_file or tls_key_file:
            if not tls_cert_file or not tls_key_file:
                raise ValueError("TLS requires both tls_cert_file and tls_key_file")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(tls_cert_file), str(tls_key_file))
            server.socket = context.wrap_socket(server.socket, server_side=True)
        scheme = "https" if tls_cert_file else "http"
        print(
            json.dumps(
                {
                    "ok": True,
                    "service": "heartwood-recall",
                    "url": f"{scheme}://{host}:{server.server_port}",
                    "auth": "bearer" if token or token_file else "none",
                }
            ),
            flush=True,
        )
        server.serve_forever()
    finally:
        engine.close()


def _call_service(url: str, path: str, payload: dict[str, Any], *, token: str | None = None) -> dict[str, Any]:
    endpoint = url.rstrip("/") + "/" + path.strip("/")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = {"ok": False, "error": body}
        payload["status"] = exc.code
        return payload


def call_recall_service(url: str, payload: dict[str, Any], *, token: str | None = None) -> dict[str, Any]:
    return _call_service(url, "recall", payload, token=token)


def call_forget_service(url: str, payload: dict[str, Any], *, token: str | None = None) -> dict[str, Any]:
    return _call_service(url, "forget", payload, token=token)


def _round_or_none(value: float | None) -> float | None:
    return None if value is None else round(float(value), 3)


def _iso_timestamp(value: float | None) -> str | None:
    if value is None:
        return None
    return datetime.utcfromtimestamp(float(value)).replace(microsecond=0).isoformat() + "Z"


def _nonnegative_float(raw: Any, *, default: float) -> float:
    if raw in (None, ""):
        return default
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return default
    return value if value >= 0 else default


def _nonnegative_float_env(name: str, default: float) -> float:
    try:
        value = float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default
    return value if value >= 0 else default


def _positive_int_env(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def _nonnegative_int_env(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default
    return value if value >= 0 else default


def _bounded_positive_int(
    raw: Any,
    *,
    default: int,
    max_default: int,
    max_env_name: str,
    field: str,
) -> int:
    if raw in (None, ""):
        value = default
    else:
        try:
            value = int(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{field} must be a positive integer") from exc
    if value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    ceiling = _positive_int_env(max_env_name, max_default)
    return min(value, ceiling)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def _canary_tenant() -> str:
    return normalize_tenant(_DEFAULT_CANARY_TENANT)


def _canary_marker(*, wrote_at: float) -> str:
    nonce = hashlib.sha256(f"{wrote_at}|{os.getpid()}".encode("utf-8")).hexdigest()[:16]
    return f"{_CANARY_MARKER_PREFIX}-{int(wrote_at * 1000)}-{nonce}"


def _roundtrip_cache_seconds() -> float:
    return _nonnegative_float_env(
        "HEARTWOOD_RECALL_ROUNDTRIP_CACHE_S",
        _nonnegative_float_env("HEARTWOOD_RECALL_READINESS_POLL_S", _DEFAULT_ROUNDTRIP_CACHE_S),
    )


def _tenant_map_tenants(default_tenant: str) -> set[str]:
    return {
        normalize_tenant(tenant, default=default_tenant)
        for tenant in _json_env_mapping("HEARTWOOD_RECALL_TENANT_MAP_JSON").values()
    }


def _local_diagnostics_admin_allowed(principal: Principal) -> bool:
    roles = {str(role) for role in principal.roles}
    if roles & _LOCAL_DIAGNOSTIC_ADMIN_ROLES:
        return True
    attrs = principal.attr_map()
    return str(attrs.get("heartwood_diagnostics", "")).lower() in {"1", "true", "yes", "admin"}


def _require_local_diagnostics_admin(principal: Principal) -> None:
    if not _local_diagnostics_admin_allowed(principal):
        raise PermissionError("verify_roundtrip requires a local diagnostics admin principal")


def _ingestion_sla_seconds() -> float:
    return _nonnegative_float_env("HEARTWOOD_RECALL_INGESTION_SLA_S", _DEFAULT_INGESTION_SLA_S)


def _ingestion_source_roots() -> list[Path]:
    raw = os.environ.get("HEARTWOOD_RECALL_SOURCE_ROOTS", "")
    roots = [part for part in raw.split(os.pathsep) if part.strip()]
    singular = os.environ.get("HEARTWOOD_RECALL_SOURCE_ROOT")
    if singular:
        roots.append(singular)
    paths = []
    for root in roots:
        path = Path(root).expanduser()
        if path.exists():
            paths.append(path)
    return paths


def _json_env_mapping(name: str) -> dict[str, str]:
    raw = os.environ.get(name)
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(key): str(value) for key, value in data.items()}


def _memory_source_uri(memory: dict[str, Any] | None) -> str | None:
    if not memory:
        return None
    source = memory.get("source") or {}
    if source.get("uri"):
        return str(source["uri"])
    source_ids = memory.get("source_ids") or ()
    return str(source_ids[0]) if source_ids else None


def _memory_matches_marker(memory: dict[str, Any], marker: str) -> bool:
    if memory.get("id") == marker or memory.get("subject") == marker:
        return True
    source = memory.get("source") or {}
    if marker in {str(source.get("uri") or ""), str(source.get("path") or "")}:
        return True
    if marker in {str(item) for item in (memory.get("source_ids") or ())}:
        return True
    if marker in {str(item) for item in (memory.get("subject_ids") or ())}:
        return True
    return False


def _source_status_for_marker(marker: str) -> dict[str, Any] | None:
    for root in _ingestion_source_roots():
        try:
            documents = load_markdown_documents([root])
        except Exception:
            continue
        for document in documents:
            if marker in {
                str(document.path),
                document.relative_path,
                f"markdown://{document.relative_path}",
            }:
                try:
                    mtime = document.path.stat().st_mtime
                except OSError:
                    mtime = None
                return {
                    "path": str(document.path),
                    "relative_path": document.relative_path,
                    "mtime": mtime,
                }
    return None


def _is_dev_model(name: str) -> bool:
    return "dev" in str(name).lower()


def _is_loopback_address(raw: str) -> bool:
    try:
        return ipaddress.ip_address(raw).is_loopback
    except ValueError:
        return raw in {"localhost"}


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _principal_payload(principal: Principal) -> dict[str, Any]:
    return {
        "id": principal.id,
        "tenant": principal.tenant,
        "roles": list(principal.roles),
        "attrs": dict(principal.attrs),
        "clearance": principal.clearance,
    }


def _disable_core_dumps() -> None:
    if os.environ.get("HEARTWOOD_DISABLE_CORE_DUMPS", "1") in {"0", "false", "False"}:
        return
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass


def _watchdog_ceiling_mb() -> float | None:
    raw = os.environ.get("HEARTWOOD_RECALL_RSS_CEILING_MB", str(_DEFAULT_RSS_CEILING_MB))
    try:
        ceiling = float(raw)
    except ValueError:
        return _DEFAULT_RSS_CEILING_MB
    return ceiling if ceiling > 0 else None


def _watchdog_warn_mb() -> float | None:
    raw = os.environ.get("HEARTWOOD_RECALL_RSS_WARN_MB", str(_DEFAULT_RSS_WARN_MB))
    try:
        warn = float(raw)
    except ValueError:
        return _DEFAULT_RSS_WARN_MB
    return warn if warn > 0 else None


def _watchdog_sustain_samples() -> int:
    return _positive_int_env("HEARTWOOD_RECALL_RSS_SUSTAIN_SAMPLES", _DEFAULT_RSS_SUSTAIN_SAMPLES)


def _watchdog_sustain_window_s() -> float:
    return _nonnegative_float_env(
        "HEARTWOOD_RECALL_RSS_SUSTAIN_WINDOW_SEC",
        _DEFAULT_RSS_SUSTAIN_WINDOW_S,
    )


def _current_rss_mb() -> float | None:
    statm = Path("/proc/self/statm")
    try:
        if statm.exists():
            pages = int(statm.read_text(encoding="utf-8").split()[1])
            return pages * os.sysconf("SC_PAGE_SIZE") / (1024 * 1024)
    except Exception:
        pass
    try:
        proc = subprocess.run(
            ["ps", "-o", "rss=", "-p", str(os.getpid())],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return int(proc.stdout.strip()) / 1024.0
    except Exception:
        pass
    return None


def _current_memory_sample() -> MemorySample:
    ps_rss_mb = _current_rss_mb()
    phys_footprint_mb = _current_phys_footprint_mb()
    return MemorySample(ps_rss_mb=ps_rss_mb, phys_footprint_mb=phys_footprint_mb)


def _current_phys_footprint_mb() -> float | None:
    if sys.platform != "darwin":
        return None
    return _mach_phys_footprint_mb() or _vmmap_phys_footprint_mb()


def _mach_phys_footprint_mb() -> float | None:
    try:
        lib = ctypes.CDLL(ctypes.util.find_library("System") or "/usr/lib/libSystem.dylib")
        lib.mach_task_self.restype = ctypes.c_uint32
        lib.task_info.argtypes = [
            ctypes.c_uint32,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        lib.task_info.restype = ctypes.c_int
        info = _TaskVMInfo()
        count = ctypes.c_uint32(ctypes.sizeof(info) // ctypes.sizeof(ctypes.c_uint32))
        result = lib.task_info(
            lib.mach_task_self(),
            _TASK_VM_INFO,
            ctypes.byref(info),
            ctypes.byref(count),
        )
        if result == _KERN_SUCCESS and info.phys_footprint > 0:
            return info.phys_footprint / (1024 * 1024)
    except Exception:
        pass
    return None


def _vmmap_phys_footprint_mb() -> float | None:
    try:
        proc = subprocess.run(
            ["vmmap", "-summary", str(os.getpid())],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    for line in proc.stdout.splitlines():
        if "Physical footprint:" not in line or "peak" in line.lower():
            continue
        value = _parse_memory_size_mb(line.split(":", 1)[1].strip())
        if value is not None:
            return value
    return None


def _parse_memory_size_mb(raw: str) -> float | None:
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?B?|bytes?)?", raw, re.I)
    if not match:
        return None
    value = float(match.group(1))
    unit = (match.group(2) or "M").upper()
    if unit in {"B", "BYTE", "BYTES"}:
        return value / (1024 * 1024)
    if unit in {"K", "KB"}:
        return value / 1024
    if unit in {"M", "MB"}:
        return value
    if unit in {"G", "GB"}:
        return value * 1024
    if unit in {"T", "TB"}:
        return value * 1024 * 1024
    return None


def _watchdog_launchctl_target() -> str:
    explicit = os.environ.get("HEARTWOOD_RECALL_LAUNCHCTL_TARGET")
    if explicit:
        return explicit
    label = os.environ.get("HEARTWOOD_RECALL_LAUNCHD_LABEL", _DEFAULT_LAUNCHD_LABEL)
    uid = os.getuid() if hasattr(os, "getuid") else 0
    return f"gui/{uid}/{label}"


def _watchdog_interval_s() -> float:
    try:
        interval = float(
            os.environ.get("HEARTWOOD_RECALL_WATCHDOG_INTERVAL_S", _DEFAULT_WATCHDOG_INTERVAL_S)
        )
    except ValueError:
        interval = _DEFAULT_WATCHDOG_INTERVAL_S
    return max(_MIN_WATCHDOG_INTERVAL_S, interval)


def _watchdog_restart_action() -> str:
    if sys.platform == "darwin":
        return "launchctl-kickstart"
    if sys.platform.startswith("linux"):
        return "supervisor-self-exit"
    return "self-exit"


def _watchdog_log_timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _watchdog_diag_log_path() -> Path:
    raw = os.environ.get("HEARTWOOD_RECALL_DIAG_LOG", _DEFAULT_DIAG_LOG)
    return Path(raw).expanduser()


def _format_memory_mb(value: float | None) -> str:
    return "unavailable" if value is None else f"{value:.1f}"


def _watchdog_memory_fields(sample: MemorySample) -> str:
    return (
        f"ps_rss_mb={_format_memory_mb(sample.ps_rss_mb)} "
        f"phys_footprint_mb={_format_memory_mb(sample.phys_footprint_mb)}"
    )


def _torch_thread_count() -> int | None:
    torch_module = sys.modules.get("torch")
    if torch_module is None or not hasattr(torch_module, "get_num_threads"):
        return None
    try:
        return int(torch_module.get_num_threads())
    except Exception:
        return None


def _capture_memory_diagnostics(
    *,
    reason: str,
    sample: MemorySample,
    ceiling_mb: float | None,
    warn_mb: float | None,
    sustained_count: int,
) -> Path | None:
    path = _watchdog_diag_log_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        return None
    header = {
        "timestamp": _watchdog_log_timestamp(),
        "reason": reason,
        "pid": os.getpid(),
        "ps_rss_mb": _round_or_none(sample.ps_rss_mb),
        "phys_footprint_mb": _round_or_none(sample.phys_footprint_mb),
        "ceiling_mb": _round_or_none(ceiling_mb),
        "warn_mb": _round_or_none(warn_mb),
        "sustained_count": sustained_count,
        "threading_active_count": threading.active_count(),
        "torch_thread_count": _torch_thread_count(),
    }
    chunks = [
        "\n=== heartwood recall memory diagnostic ===\n",
        json.dumps(header, sort_keys=True, separators=(",", ":")),
        "\n",
    ]
    for command in (["footprint", "-p", str(os.getpid())], ["vmmap", "-summary", str(os.getpid())]):
        chunks.append(f"$ {' '.join(command)}\n")
        try:
            proc = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=20,
            )
        except Exception as exc:
            chunks.append(f"command_error={type(exc).__name__}: {exc}\n")
            continue
        chunks.append(f"returncode={proc.returncode}\n")
        if proc.stdout:
            chunks.append(proc.stdout)
            if not proc.stdout.endswith("\n"):
                chunks.append("\n")
        if proc.stderr:
            chunks.append("STDERR:\n")
            chunks.append(proc.stderr)
            if not proc.stderr.endswith("\n"):
                chunks.append("\n")
    try:
        with path.open("a", encoding="utf-8") as handle:
            handle.writelines(chunks)
        return path
    except Exception:
        return None


def _kickstart_launchctl(target: str) -> None:
    subprocess.run(
        ["launchctl", "kickstart", "-k", target],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def _allocator_pressure_relief_interval() -> int | None:
    value = _nonnegative_int_env(
        "HEARTWOOD_RECALL_MALLOC_PRESSURE_RELIEF_RECALLS",
        _DEFAULT_MALLOC_PRESSURE_RELIEF_RECALLS,
    )
    return value if value > 0 else None


def _maybe_relieve_allocator_pressure(recall_total: int) -> int | None:
    interval = _allocator_pressure_relief_interval()
    if interval is None or recall_total <= 0 or recall_total % interval != 0:
        return None
    return _relieve_allocator_pressure_now()


def _relieve_allocator_pressure_now() -> int | None:
    gc.collect()
    if sys.platform == "darwin":
        fn = _malloc_zone_pressure_relief()
        args = (None, 0)
    elif sys.platform.startswith("linux"):
        fn = _malloc_trim()
        args = (0,)
    else:
        return None
    if fn is None:
        return None
    try:
        return int(fn(*args))
    except Exception:
        return None


def _malloc_zone_pressure_relief():
    global _MALLOC_PRESSURE_RELIEF_FN
    global _MALLOC_PRESSURE_RELIEF_LOOKED_UP
    if _MALLOC_PRESSURE_RELIEF_LOOKED_UP:
        return _MALLOC_PRESSURE_RELIEF_FN
    _MALLOC_PRESSURE_RELIEF_LOOKED_UP = True
    try:
        lib = ctypes.CDLL(ctypes.util.find_library("System") or "/usr/lib/libSystem.dylib")
        fn = lib.malloc_zone_pressure_relief
        fn.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        fn.restype = ctypes.c_size_t
        _MALLOC_PRESSURE_RELIEF_FN = fn
    except Exception:
        _MALLOC_PRESSURE_RELIEF_FN = None
    return _MALLOC_PRESSURE_RELIEF_FN


def _malloc_trim():
    global _MALLOC_TRIM_FN
    global _MALLOC_TRIM_LOOKED_UP
    if _MALLOC_TRIM_LOOKED_UP:
        return _MALLOC_TRIM_FN
    _MALLOC_TRIM_LOOKED_UP = True
    try:
        lib = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6")
        fn = lib.malloc_trim
        fn.argtypes = [ctypes.c_size_t]
        fn.restype = ctypes.c_int
        _MALLOC_TRIM_FN = fn
    except Exception:
        _MALLOC_TRIM_FN = None
    return _MALLOC_TRIM_FN


def _start_memory_watchdog() -> None:
    if os.environ.get("HEARTWOOD_RECALL_WATCHDOG", "1") in {"0", "false", "False"}:
        return
    ceiling = _watchdog_ceiling_mb()
    if ceiling is None:
        return
    warn = _watchdog_warn_mb()
    sustain_samples = _watchdog_sustain_samples()
    sustain_window_s = _watchdog_sustain_window_s()
    interval = _watchdog_interval_s()
    restart_action = _watchdog_restart_action()
    target = _watchdog_launchctl_target() if restart_action == "launchctl-kickstart" else None

    def watch() -> None:
        sustained: deque[tuple[float, MemorySample]] = deque(maxlen=sustain_samples)
        warned = False
        while True:
            time.sleep(interval)
            sample = _current_memory_sample()
            enforced_mb = sample.enforced_mb
            if enforced_mb is None:
                sustained.clear()
                warned = False
                continue
            if warn is not None and enforced_mb > warn and not warned:
                diag_path = _capture_memory_diagnostics(
                    reason="soft-warn",
                    sample=sample,
                    ceiling_mb=ceiling,
                    warn_mb=warn,
                    sustained_count=len(sustained),
                )
                print(
                    f"{_watchdog_log_timestamp()} heartwood memory watchdog soft warn: "
                    f"{_watchdog_memory_fields(sample)} warn_mb={warn:.1f} "
                    f"ceiling_mb={ceiling:.1f} diag_log={diag_path or 'unavailable'} "
                    "action=diagnose",
                    file=sys.stderr,
                    flush=True,
                )
                warned = True
            elif warn is None or enforced_mb <= warn:
                warned = False
            if enforced_mb <= ceiling:
                if sustained:
                    print(
                        f"{_watchdog_log_timestamp()} heartwood memory watchdog recovered: "
                        f"{_watchdog_memory_fields(sample)} ceiling_mb={ceiling:.1f} "
                        "action=monitor",
                        file=sys.stderr,
                        flush=True,
                    )
                sustained.clear()
                continue
            sustained.append((time.monotonic(), sample))
            elapsed_s = sustained[-1][0] - sustained[0][0] if len(sustained) > 1 else 0.0
            required_elapsed_s = 0.0 if sustain_samples <= 1 else sustain_window_s
            if len(sustained) < sustain_samples or elapsed_s < required_elapsed_s:
                print(
                    f"{_watchdog_log_timestamp()} heartwood memory watchdog threshold observed: "
                    f"{_watchdog_memory_fields(sample)} ceiling_mb={ceiling:.1f} "
                    f"sustained_samples={len(sustained)}/{sustain_samples} "
                    f"sustained_elapsed_s={elapsed_s:.1f}/{required_elapsed_s:.1f} "
                    "action=monitor",
                    file=sys.stderr,
                    flush=True,
                )
                continue
            try:
                diag_path = _capture_memory_diagnostics(
                    reason="sustained-hard-restart",
                    sample=sample,
                    ceiling_mb=ceiling,
                    warn_mb=warn,
                    sustained_count=len(sustained),
                )
                print(
                    f"{_watchdog_log_timestamp()} heartwood memory watchdog sustained ceiling exceeded: "
                    f"{_watchdog_memory_fields(sample)} ceiling_mb={ceiling:.1f} "
                    f"sustained_samples={len(sustained)}/{sustain_samples} "
                    f"sustained_elapsed_s={elapsed_s:.1f}/{required_elapsed_s:.1f} "
                    f"diag_log={diag_path or 'unavailable'} action={restart_action}",
                    file=sys.stderr,
                    flush=True,
                )
                if restart_action == "launchctl-kickstart" and target is not None:
                    _kickstart_launchctl(target)
            finally:
                os._exit(75)

    threading.Thread(target=watch, name="heartwood-rss-watchdog", daemon=True).start()
