"""Warm recall CLI/service tests for generic Phase 1 use."""
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib import error, request

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood.importers.markdown import dev_models, import_markdown_corpus  # noqa: E402
from heartwood import Heartwood, Principal  # noqa: E402
from heartwood.recall_service import (  # noqa: E402
    MemorySample,
    RecallCredential,
    RecallEngine,
    RecallRateLimiter,
    RecallReadinessError,
)


def _write_corpus(root: Path) -> Path:
    memory = root / "memory"
    memory.mkdir()
    (memory / "feedback_acme_owner_guidance.md").write_text(
        "# Acme Payments owner guidance\n\nAlways preserve audit details and provenance in Acme Payments reviews.",
        encoding="utf-8",
    )
    (memory / "reference_acme_finance.md").write_text(
        "---\n"
        "classification: confidential\n"
        "roles: [finance]\n"
        "subject: acme:finance\n"
        "---\n"
        "# Acme Finance\n\nFinance-only Acme treasury margin controls and payment risk policy.",
        encoding="utf-8",
    )
    (memory / "reference_northwind_auth.md").write_text(
        "---\n"
        "tenant: northwind-retail\n"
        "classification: confidential\n"
        "roles: [finance]\n"
        "subject: northwind-retail:auth\n"
        "---\n"
        "# Northwind Retail auth\n\nFinance must review Northwind Retail auth incidents.",
        encoding="utf-8",
    )
    return memory


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    try:
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def _request_json(
    url: str,
    payload: dict | None = None,
    token: str | None = None,
    method: str = "GET",
    extra_headers: dict | None = None,
) -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if extra_headers:
        headers.update(extra_headers)
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = request.Request(url, data=data, headers=headers, method=method)
    with request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _write_credential_file(
    path: Path,
    *,
    token: str,
    tenant: str = "tenant:acme-payments",
    roles: list[str] | None = None,
    attrs: dict | None = None,
    rate_limit_requests: int = 60,
    rate_limit_window_s: float = 60.0,
) -> None:
    path.write_text(
        json.dumps(
            {
                "credentials": [
                    {
                        "token": token,
                        "tenant": tenant,
                        "principal_id": "agent:gateway",
                        "roles": roles or [],
                        "attrs": attrs or {},
                        "clearance": "internal",
                        "rate_limit": {
                            "requests": rate_limit_requests,
                            "window_seconds": rate_limit_window_s,
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )


def _write_two_tenant_credential_file(
    path: Path,
    *,
    acme_token: str,
    northwind_token: str,
) -> None:
    """Two credentials in one file, each bound to a DIFFERENT tenant.

    This is the multi-credential negative-test fixture (#10003541 / roadmap P2-1):
    each bearer token maps to exactly one tenant principal, so cross-tenant reads
    must be impossible and a payload-declared tenant must be ignored.
    """
    path.write_text(
        json.dumps(
            {
                "credentials": [
                    {
                        "token": acme_token,
                        "tenant": "tenant:acme-payments",
                        "principal_id": "agent:acme-gateway",
                        "roles": [],
                        "attrs": {},
                        "clearance": "internal",
                    },
                    {
                        "token": northwind_token,
                        "tenant": "tenant:northwind-retail",
                        "principal_id": "agent:northwind-gateway",
                        "roles": [],
                        "attrs": {},
                        "clearance": "internal",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )


def _seed_two_tenant_corpus(db_path: Path) -> None:
    """Seed one shared DB with a uniquely-marked record in each of two tenants."""
    embedder, reranker = dev_models()
    acme = Heartwood(path=db_path, tenant="tenant:acme-payments", embedder=embedder, reranker=reranker)
    try:
        acme.remember(
            "ACME_CANARY Acme Payments audit provenance retention guidance for reviews.",
            subject="acme:guidance",
            created_by="agent:test",
        )
    finally:
        acme.close()
    northwind = Heartwood(
        path=db_path, tenant="tenant:northwind-retail", embedder=embedder, reranker=reranker
    )
    try:
        northwind.remember(
            "NORTHWIND_CANARY Northwind Retail auth incident review runbook for finance.",
            subject="northwind:guidance",
            created_by="agent:test",
        )
    finally:
        northwind.close()


def _wait_health(base_url: str, proc: subprocess.Popen) -> dict:
    last_error = None
    for _ in range(50):
        if proc.poll() is not None:
            break
        try:
            return _request_json(base_url + "/health")
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            time.sleep(0.1)
    stdout, stderr = proc.communicate(timeout=2)
    raise AssertionError(f"service did not become healthy: {last_error}\nSTDOUT={stdout}\nSTDERR={stderr}")


def _process_rss_mb() -> float:
    proc = subprocess.run(
        ["ps", "-o", "rss=", "-p", str(os.getpid())],
        check=True,
        capture_output=True,
        text=True,
    )
    return int(proc.stdout.strip()) / 1024.0


def _assert_text_cache_lru(client: Heartwood, monkeypatch: pytest.MonkeyPatch) -> None:
    import heartwood.client as client_module

    monkeypatch.setattr(client_module, "_TEXT_CACHE_LIMIT", 3)
    for index in range(5):
        client._cache_text_pair(f"mem_{index}", f"content {index}", f"index {index}")
    assert len(client._text_cache) == 3
    assert list(client._text_cache) == ["mem_2", "mem_3", "mem_4"]

    assert client._text_pair_for_meta({"id": "mem_2", "subject": "subject"}) == (
        "content 2",
        "index 2",
    )
    assert list(client._text_cache) == ["mem_3", "mem_4", "mem_2"]

    client._cache_text_pair("mem_5", "content 5", "index 5")
    assert len(client._text_cache) == 3
    assert list(client._text_cache) == ["mem_4", "mem_2", "mem_5"]


def test_text_cache_lru_eviction_hard_bounds(monkeypatch):
    embedder, reranker = dev_models()
    db = Heartwood(path=":memory:", tenant="tenant:ops", embedder=embedder, reranker=reranker)
    try:
        _assert_text_cache_lru(db, monkeypatch)
    finally:
        db.close()


def test_cross_encoder_reranker_clips_inputs_before_predict(monkeypatch):
    from heartwood import retrieval

    captured_pairs = []

    class FakeCrossEncoder:
        def predict(self, pairs, **kwargs):
            captured_pairs.extend(pairs)
            return [0.5 for _ in pairs]

    monkeypatch.setenv("HEARTWOOD_RERANKER_QUERY_MAX_CHARS", "32")
    monkeypatch.setenv("HEARTWOOD_RERANKER_TEXT_MAX_CHARS", "64")
    monkeypatch.setattr(retrieval, "_load_cross_encoder", lambda *args, **kwargs: FakeCrossEncoder())

    reranker, name = retrieval.get_reranker()
    scores = reranker("query " * 40, ["alpha " * 100, "short text"])

    assert "cross-encoder/ms-marco-MiniLM-L-6-v2" in name
    assert list(scores) == [0.5, 0.5]
    assert len(captured_pairs) == 2
    assert all(len(query) <= 32 for query, _ in captured_pairs)
    assert len(captured_pairs[0][1]) <= 64
    assert captured_pairs[1][1] == "short text"


def test_cross_encoder_reranker_loads_local_model_path_from_env(monkeypatch):
    from heartwood import retrieval

    captured = {}

    class FakeCrossEncoder:
        def predict(self, pairs, **kwargs):
            return [0.5 for _ in pairs]

    def fake_load(model_id, **kwargs):
        captured.update({"model_id": model_id, **kwargs})
        return FakeCrossEncoder()

    monkeypatch.setenv("HEARTWOOD_RERANKER_MODEL_PATH", "/tmp/exp600-checkpoint")
    monkeypatch.setattr(retrieval, "_load_cross_encoder", fake_load)

    reranker, name = retrieval.get_reranker()
    scores = reranker("query", ["doc"])

    assert name == "/tmp/exp600-checkpoint"
    assert list(scores) == [0.5]
    assert captured["model_id"] == "/tmp/exp600-checkpoint"


def test_cross_encoder_reranker_loads_model_key_from_env(monkeypatch):
    from heartwood import retrieval

    captured = {}

    class FakeCrossEncoder:
        def predict(self, pairs, **kwargs):
            return [0.5 for _ in pairs]

    def fake_load(model_id, **kwargs):
        captured.update({"model_id": model_id, **kwargs})
        return FakeCrossEncoder()

    monkeypatch.delenv("HEARTWOOD_RERANKER_MODEL_PATH", raising=False)
    monkeypatch.setenv("HEARTWOOD_RERANKER_MODEL_KEY", "mxbai")
    monkeypatch.setattr(retrieval, "_load_cross_encoder", fake_load)

    reranker, name = retrieval.get_reranker()
    scores = reranker("query", ["doc"])

    assert "mixedbread-ai/mxbai-rerank-base-v2" in name
    assert list(scores) == [0.5]
    assert captured["model_id"] == "mixedbread-ai/mxbai-rerank-base-v2"


def test_model_runtime_disables_tokenizers_parallelism_by_default(monkeypatch):
    import heartwood.retrieval as retrieval

    monkeypatch.delenv("TOKENIZERS_PARALLELISM", raising=False)
    retrieval._configure_torch_cpu_threads()

    assert os.environ["TOKENIZERS_PARALLELISM"] == "false"


def test_model_runtime_forces_tokenizers_parallelism_off_unless_explicitly_allowed(monkeypatch):
    import heartwood.retrieval as retrieval

    monkeypatch.setenv("TOKENIZERS_PARALLELISM", "true")
    monkeypatch.delenv("HEARTWOOD_ALLOW_TOKENIZER_PARALLELISM", raising=False)

    retrieval._configure_torch_cpu_threads()

    assert os.environ["TOKENIZERS_PARALLELISM"] == "false"


def test_model_runtime_allows_explicit_tokenizer_parallelism_escape_hatch(monkeypatch):
    import heartwood.retrieval as retrieval

    monkeypatch.setenv("TOKENIZERS_PARALLELISM", "true")
    monkeypatch.setenv("HEARTWOOD_ALLOW_TOKENIZER_PARALLELISM", "1")

    retrieval._configure_torch_cpu_threads()

    assert os.environ["TOKENIZERS_PARALLELISM"] == "true"


def test_model_runtime_honors_thread_env(monkeypatch):
    import heartwood.retrieval as retrieval

    captured = {}

    class FakeTorch:
        @staticmethod
        def set_num_threads(value):
            captured["threads"] = value

        @staticmethod
        def set_num_interop_threads(value):
            captured["interop_threads"] = value

    monkeypatch.setitem(sys.modules, "torch", FakeTorch())
    monkeypatch.setenv("HEARTWOOD_TORCH_NUM_THREADS", "8")
    monkeypatch.setenv("HEARTWOOD_TORCH_INTEROP_THREADS", "2")

    retrieval._configure_torch_cpu_threads()

    assert captured == {"threads": 8, "interop_threads": 2}


def test_cross_encoder_loader_honors_max_length_env(monkeypatch):
    import types

    import heartwood.retrieval as retrieval

    captured = {}

    class FakeCrossEncoder:
        def __init__(self, source, **kwargs):
            captured.update({"source": source, **kwargs})

    monkeypatch.setitem(
        sys.modules,
        "sentence_transformers",
        types.SimpleNamespace(CrossEncoder=FakeCrossEncoder),
    )
    monkeypatch.setenv("HEARTWOOD_RERANKER_MAX_LENGTH", "128")

    retrieval._load_cross_encoder("local-reranker", max_length=192)

    assert captured["source"] == "local-reranker"
    assert captured["device"] == "cpu"
    assert captured["max_length"] == 128


def test_named_reranker_clips_inputs_and_honors_batch_env(monkeypatch):
    import types

    import heartwood.models as models

    captured = {}

    class FakeCrossEncoder:
        def predict(self, pairs, **kwargs):
            captured["pairs"] = pairs
            captured["kwargs"] = kwargs
            return [0.25 for _ in pairs]

    monkeypatch.setenv("HEARTWOOD_RERANKER_QUERY_MAX_CHARS", "32")
    monkeypatch.setenv("HEARTWOOD_RERANKER_TEXT_MAX_CHARS", "64")
    monkeypatch.setenv("HEARTWOOD_RERANKER_BATCH_SIZE", "7")
    monkeypatch.setattr(
        models,
        "model_spec",
        lambda key: types.SimpleNamespace(
            repo_id="local-reranker",
            revision=None,
            trust_remote_code=False,
        ),
    )
    monkeypatch.setattr(models, "_load_cross_encoder", lambda *args, **kwargs: FakeCrossEncoder())

    rerank, name = models.reranker("minilm")
    scores = rerank("query " * 40, ["alpha " * 100, "short text"])

    assert name == "local-reranker@None"
    assert list(scores) == [0.25, 0.25]
    assert captured["kwargs"]["batch_size"] == 7
    assert all(len(query) <= 32 for query, _ in captured["pairs"])
    assert len(captured["pairs"][0][1]) <= 64
    assert captured["pairs"][1][1] == "short text"


def test_recall_engine_bounds_payload_k_and_topc(monkeypatch):
    captured = {}
    engine = RecallEngine(
        db_path=":memory:",
        default_tenant="tenant:ops",
        dev_models=True,
    )

    class FakeClient:
        def recall(self, cue, *, principal, filters=None, k=8, topc=50):
            captured.update({"cue": cue, "k": k, "topc": topc, "tenant": principal.tenant})
            return {"recall_id": "recall_test", "results": [], "index_lag": 0}

    monkeypatch.setenv("HEARTWOOD_RECALL_MAX_K", "7")
    monkeypatch.setenv("HEARTWOOD_RECALL_MAX_TOPC", "12")
    monkeypatch.setattr(engine, "client", lambda tenant: FakeClient())
    try:
        out = engine.recall(
            {
                "query": "bounded recall request",
                "tenant": "tenant:ops",
                "principal_id": "agent:test",
                "k": 1000,
                "topc": 5000,
            }
        )
    finally:
        engine.close()

    assert out["ok"] is True
    assert captured == {
        "cue": "bounded recall request",
        "k": 7,
        "topc": 12,
        "tenant": "tenant:ops",
    }


def test_recall_engine_rejects_non_positive_k():
    engine = RecallEngine(
        db_path=":memory:",
        default_tenant="tenant:ops",
        dev_models=True,
    )
    try:
        with pytest.raises(ValueError, match="k must be a positive integer"):
            engine.recall(
                {
                    "query": "invalid bounded recall request",
                    "tenant": "tenant:ops",
                    "principal_id": "agent:test",
                    "k": 0,
                }
            )
    finally:
        engine.close()


def test_recall_engine_fails_closed_when_payload_principal_disabled():
    with tempfile.TemporaryDirectory() as temp_dir:
        engine = RecallEngine(
            db_path=Path(temp_dir) / "heartwood.db",
            default_tenant="tenant:ops",
            dev_models=True,
        )
        try:
            with pytest.raises(PermissionError, match="server principal required"):
                engine.recall(
                    {
                        "query": "forged identity should not be trusted",
                        "tenant": "tenant:evil",
                        "principal_id": "agent:attacker",
                        "roles": ["admin"],
                        "clearance": "restricted",
                    },
                    allow_payload_principal=False,
                )
        finally:
            engine.close()


def _diagnostic_admin_principal(tenant: str = "tenant:ops") -> Principal:
    return Principal(id="agent:gateway", tenant=tenant, roles=("heartwood:diagnostics",))


def test_verify_roundtrip_cleans_canary_row_and_numpy_index_vector():
    with tempfile.TemporaryDirectory() as temp_dir:
        engine = RecallEngine(
            db_path=Path(temp_dir) / "heartwood.db",
            default_tenant="tenant:ops",
            dev_models=True,
        )
        try:
            out = engine.verify_roundtrip(
                {"source_marker": "api_key=SHOULD_NOT_APPEAR", "tenant": "tenant:evil", "lag_budget_seconds": 0.1},
                principal=_diagnostic_admin_principal(),
            )
            assert out["ok"] is True
            assert out["roundtrip_ok"] is True
            assert out["cleanup_ok"] is True
            assert out["cleanup_purged"] == 1
            assert out["canary_tenant"] == "tenant:__heartwood_canary__"
            assert out["classification"] == "public"
            assert out["payload_marker_ignored"] is True
            assert out["source_marker"].startswith("heartwood-roundtrip-canary-")
            assert "api_key" not in json.dumps(out)
            assert out["recallable_at"] is not None

            ops_rows = engine.client("tenant:ops").store.candidate_meta("tenant:ops")
            canary_client = engine.client("tenant:__heartwood_canary__")
            canary_rows = canary_client.store.candidate_meta(
                "tenant:__heartwood_canary__"
            )
            assert not ops_rows
            assert not any(row["id"] == out["memory_id"] for row in canary_rows)
            assert out["memory_id"] not in canary_client.index._v
        finally:
            engine.close()


def test_verify_roundtrip_fails_loud_when_canary_not_recallable(monkeypatch):
    with tempfile.TemporaryDirectory() as temp_dir:
        engine = RecallEngine(
            db_path=Path(temp_dir) / "heartwood.db",
            default_tenant="tenant:ops",
            dev_models=True,
        )

        def fake_recall(*args, **kwargs):
            return {"ok": True, "result_count": 0, "results": []}

        monkeypatch.setattr(engine, "recall", fake_recall)
        try:
            out = engine.verify_roundtrip(
                {"source_marker": "g3_delayed_unit", "lag_budget_seconds": 0},
                principal=_diagnostic_admin_principal(),
            )
            assert out["ok"] is False
            assert out["roundtrip_ok"] is False
            assert out["cleanup_ok"] is True
            assert out["cleanup_purged"] == 1
            assert out["recallable_at"] is None
            assert out["ingestion_lag_seconds"] >= 0
            canary_client = engine.client("tenant:__heartwood_canary__")
            assert not canary_client.store.candidate_meta("tenant:__heartwood_canary__")
            assert out["memory_id"] not in canary_client.index._v
        finally:
            engine.close()


def test_verify_roundtrip_forced_recall_exception_still_hard_cleans(monkeypatch):
    with tempfile.TemporaryDirectory() as temp_dir:
        engine = RecallEngine(
            db_path=Path(temp_dir) / "heartwood.db",
            default_tenant="tenant:ops",
            dev_models=True,
        )

        def broken_recall(*args, **kwargs):
            raise RuntimeError("forced recall failure")

        monkeypatch.setattr(engine, "recall", broken_recall)
        try:
            out = engine.verify_roundtrip(
                {"lag_budget_seconds": 0},
                principal=_diagnostic_admin_principal(),
            )
            assert out["ok"] is False
            assert out["roundtrip_ok"] is False
            assert out["recall_error"] == "forced recall failure"
            assert out["cleanup_ok"] is True
            assert out["cleanup_purged"] == 1
            canary_client = engine.client("tenant:__heartwood_canary__")
            assert not canary_client.store.candidate_meta("tenant:__heartwood_canary__")
            assert out["memory_id"] not in canary_client.index._v
        finally:
            engine.close()


def test_verify_roundtrip_requires_diagnostic_admin_principal():
    engine = RecallEngine(
        db_path=":memory:",
        default_tenant="tenant:ops",
        dev_models=True,
    )
    try:
        with pytest.raises(PermissionError, match="local diagnostics admin"):
            engine.verify_roundtrip(
                {"lag_budget_seconds": 0},
                principal=Principal(id="agent:gateway", tenant="tenant:ops"),
            )
    finally:
        engine.close()


def test_verify_roundtrip_rejects_canary_tenant_collision_with_adopter_tenant():
    engine = RecallEngine(
        db_path=":memory:",
        default_tenant="tenant:ops",
        dev_models=True,
        adopter_tenants=("tenant:__heartwood_canary__",),
    )
    try:
        with pytest.raises(ValueError, match="configured adopter tenants"):
            engine.verify_roundtrip(
                {"lag_budget_seconds": 0},
                principal=_diagnostic_admin_principal(),
            )
    finally:
        engine.close()


def test_verify_roundtrip_debounces_canary_lifecycle_and_tags_canary_audit_tenant():
    with tempfile.TemporaryDirectory() as temp_dir:
        engine = RecallEngine(
            db_path=Path(temp_dir) / "heartwood.db",
            default_tenant="tenant:ops",
            dev_models=True,
        )
        try:
            first = engine.verify_roundtrip(
                {"lag_budget_seconds": 0.1},
                principal=_diagnostic_admin_principal(),
            )
            second = engine.verify_roundtrip(
                {"lag_budget_seconds": 0.1},
                principal=_diagnostic_admin_principal(),
            )
            assert first["cached"] is False
            assert first["canary_lifecycle_executed"] is True
            assert second["cached"] is True
            assert second["canary_lifecycle_executed"] is False
            assert second["memory_id"] == first["memory_id"]

            rows = engine.client("tenant:__heartwood_canary__").store.conn.execute(
                "SELECT tenant, action, body FROM audit_log ORDER BY seq"
            ).fetchall()
            actions = [row["action"] for row in rows]
            assert actions.count("remember") == 1
            assert actions.count("recall") == 1
            assert actions.count("forget") == 1
            assert all(row["tenant"] == "tenant:__heartwood_canary__" for row in rows)
            assert all('"tenant":"tenant:__heartwood_canary__"' in row["body"] for row in rows)
        finally:
            engine.close()


def test_verify_ingested_reports_present_indexed_source():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        memory = _write_corpus(root)
        db_path = root / "heartwood.db"
        embedder, reranker = dev_models()
        import_markdown_corpus(
            [memory],
            db_path=db_path,
            tenant_map={"acme": "tenant:acme-payments"},
            embedder=embedder,
            reranker=reranker,
        )
        engine = RecallEngine(
            db_path=db_path,
            default_tenant="tenant:acme-payments",
            dev_models=True,
        )
        try:
            out = engine.verify_ingested(
                {"source_marker": "markdown://memory/feedback_acme_owner_guidance.md"},
                principal=Principal(id="agent:gateway", tenant="tenant:acme-payments"),
            )
            assert out["ok"] is True
            assert out["present"] is True
            assert out["indexed"] is True
            assert out["memory_id"]
            assert out["source_uri"] == "markdown://memory/feedback_acme_owner_guidance.md"
        finally:
            engine.close()


def test_rate_limiter_evicts_expired_token_buckets(monkeypatch):
    now = 100.0
    monkeypatch.setattr("heartwood.recall_service.time.monotonic", lambda: now)
    limiter = RecallRateLimiter()
    old = RecallCredential(
        token_digest="old-token-digest",
        principal=Principal(id="agent:old", tenant="tenant:ops"),
        rate_limit_requests=2,
        rate_limit_window_s=1.0,
    )
    new = RecallCredential(
        token_digest="new-token-digest",
        principal=Principal(id="agent:new", tenant="tenant:ops"),
        rate_limit_requests=2,
        rate_limit_window_s=1.0,
    )

    assert limiter.check(old) == (True, 1, 0)
    assert "old-token-digest" in limiter._hits

    now = 102.0
    assert limiter.check(new) == (True, 1, 0)
    assert "old-token-digest" not in limiter._hits
    assert list(limiter._hits) == ["new-token-digest"]


def test_recall_engine_rejects_degraded_startup_without_explicit_dev_flag():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        memory = _write_corpus(root)
        db_path = root / "heartwood.db"
        embedder, reranker = dev_models()
        import_markdown_corpus(
            [memory],
            db_path=db_path,
            tenant_map={"acme": "tenant:acme-payments"},
            embedder=embedder,
            reranker=reranker,
        )
        engine = RecallEngine(
            db_path=db_path,
            default_tenant="tenant:acme-payments",
            dev_models=True,
        )
        try:
            with pytest.raises(RecallReadinessError) as raised:
                engine.assert_ready_to_serve(allow_dev_models=False)
            readiness = raised.value.readiness
            assert readiness["ok"] is False
            assert readiness["embedder"]["name"] == "hashing-embedder(dev)"
            assert readiness["embedder"]["dev_fallback"] is True
            assert readiness["checks"]["non_dev_embedder"] is False
            assert readiness["checks"]["non_dev_reranker"] is False
            assert readiness["checks"]["db_dimension_match"] is True
        finally:
            engine.close()


def test_recall_engine_allows_degraded_startup_with_explicit_dev_flag():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        memory = _write_corpus(root)
        db_path = root / "heartwood.db"
        embedder, reranker = dev_models()
        import_markdown_corpus(
            [memory],
            db_path=db_path,
            tenant_map={"acme": "tenant:acme-payments"},
            embedder=embedder,
            reranker=reranker,
        )
        engine = RecallEngine(
            db_path=db_path,
            default_tenant="tenant:acme-payments",
            dev_models=True,
        )
        try:
            readiness = engine.assert_ready_to_serve(allow_dev_models=True)
            assert readiness["ok"] is False
            assert readiness["embedder"]["dev_fallback"] is True
            assert readiness["checks"]["db_dimension_match"] is True
        finally:
            engine.close()


def test_memory_watchdog_survives_single_transient_footprint_spike(tmp_path):
    diag_log = tmp_path / "serve-recall.diag.log"
    script = f"""
import builtins
import os
import threading
import time
from pathlib import Path

os.environ["HEARTWOOD_RECALL_RSS_WARN_MB"] = "2000"
os.environ["HEARTWOOD_RECALL_RSS_CEILING_MB"] = "4000"
os.environ["HEARTWOOD_RECALL_RSS_SUSTAIN_SAMPLES"] = "3"
os.environ["HEARTWOOD_RECALL_RSS_SUSTAIN_WINDOW_SEC"] = "0"
os.environ["HEARTWOOD_RECALL_WATCHDOG_INTERVAL_S"] = "0.05"
os.environ["HEARTWOOD_RECALL_DIAG_LOG"] = {str(diag_log)!r}

import heartwood.recall_service as recall_service

samples = iter([
    recall_service.MemorySample(ps_rss_mb=9000.0, phys_footprint_mb=9000.0),
    recall_service.MemorySample(ps_rss_mb=9000.0, phys_footprint_mb=500.0),
    recall_service.MemorySample(ps_rss_mb=9000.0, phys_footprint_mb=500.0),
    recall_service.MemorySample(ps_rss_mb=9000.0, phys_footprint_mb=500.0),
])

def fake_sample():
    try:
        return next(samples)
    except StopIteration:
        return recall_service.MemorySample(ps_rss_mb=9000.0, phys_footprint_mb=500.0)

def fake_diag(**kwargs):
    path = Path(os.environ["HEARTWOOD_RECALL_DIAG_LOG"])
    path.write_text("transient diag captured\\n", encoding="utf-8")
    return path

recovered_seen = threading.Event()

def watched_print(*args, **kwargs):
    builtins.print(*args, **kwargs)
    message = " ".join(str(arg) for arg in args)
    if "heartwood memory watchdog recovered:" in message:
        recovered_seen.set()

recall_service.sys.platform = "darwin"
recall_service.print = watched_print
recall_service._current_memory_sample = fake_sample
recall_service._capture_memory_diagnostics = fake_diag
recall_service._start_memory_watchdog()
if not recovered_seen.wait(timeout=5):
    raise SystemExit("watchdog recovered log not observed")
print("survived transient footprint spike")
"""
    proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        capture_output=True,
        text=True,
        timeout=8,
        check=False,
    )

    assert proc.returncode == 0
    assert "survived transient footprint spike" in proc.stdout
    assert "heartwood memory watchdog soft warn:" in proc.stderr
    assert "heartwood memory watchdog threshold observed:" in proc.stderr
    assert "heartwood memory watchdog recovered:" in proc.stderr
    assert "ps_rss_mb=9000.0 phys_footprint_mb=9000.0" in proc.stderr
    assert "ps_rss_mb=9000.0 phys_footprint_mb=500.0" in proc.stderr
    assert diag_log.read_text(encoding="utf-8") == "transient diag captured\n"


def test_memory_watchdog_exits_75_only_after_sustained_footprint_breach(tmp_path):
    if os.name == "nt":
        pytest.skip("Linux watchdog trigger uses POSIX RSS inspection")
    diag_log = tmp_path / "serve-recall.diag.log"
    script = """
import os
import time
from pathlib import Path

os.environ["HEARTWOOD_RECALL_RSS_WARN_MB"] = "2000"
os.environ["HEARTWOOD_RECALL_RSS_CEILING_MB"] = "4000"
os.environ["HEARTWOOD_RECALL_RSS_SUSTAIN_SAMPLES"] = "2"
os.environ["HEARTWOOD_RECALL_RSS_SUSTAIN_WINDOW_SEC"] = "0"
os.environ["HEARTWOOD_RECALL_WATCHDOG_INTERVAL_S"] = "0.05"
os.environ["HEARTWOOD_RECALL_DIAG_LOG"] = __DIAG_LOG__

import heartwood.recall_service as recall_service

def fake_sample():
    return recall_service.MemorySample(ps_rss_mb=12000.0, phys_footprint_mb=8000.0)

def fake_diag(**kwargs):
    path = Path(os.environ["HEARTWOOD_RECALL_DIAG_LOG"])
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{kwargs['reason']} diag captured\\n")
    return path

clock = iter([0.00, 0.05, 0.10, 0.15, 0.20])

def fake_monotonic():
    try:
        return next(clock)
    except StopIteration:
        return 0.20

recall_service.sys.platform = "linux"
recall_service.time.monotonic = fake_monotonic
recall_service._current_memory_sample = fake_sample
recall_service._capture_memory_diagnostics = fake_diag
recall_service._start_memory_watchdog()
deadline = time.time() + 5
while time.time() < deadline:
    time.sleep(0.05)
raise SystemExit(99)
""".replace("__DIAG_LOG__", repr(str(diag_log)))
    proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        capture_output=True,
        text=True,
        timeout=8,
        check=False,
    )

    assert proc.returncode == 75
    assert re.search(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2} "
        r"heartwood memory watchdog sustained ceiling exceeded:",
        proc.stderr,
    )
    assert "action=supervisor-self-exit" in proc.stderr
    assert "ps_rss_mb=12000.0 phys_footprint_mb=8000.0" in proc.stderr
    assert "sustained_samples=2/2" in proc.stderr
    assert "soft-warn diag captured" in diag_log.read_text(encoding="utf-8")
    assert "sustained-hard-restart diag captured" in diag_log.read_text(encoding="utf-8")


def test_memory_watchdog_respects_nonzero_sustain_window(tmp_path):
    if os.name == "nt":
        pytest.skip("watchdog hard-exit assertions are POSIX-focused")
    kill_diag_log = tmp_path / "kill.diag.log"
    kill_script = """
import os
import time
from pathlib import Path

os.environ["HEARTWOOD_RECALL_RSS_WARN_MB"] = "2000"
os.environ["HEARTWOOD_RECALL_RSS_CEILING_MB"] = "4000"
os.environ["HEARTWOOD_RECALL_RSS_SUSTAIN_SAMPLES"] = "4"
os.environ["HEARTWOOD_RECALL_RSS_SUSTAIN_WINDOW_SEC"] = "0.12"
os.environ["HEARTWOOD_RECALL_WATCHDOG_INTERVAL_S"] = "0.05"
os.environ["HEARTWOOD_RECALL_DIAG_LOG"] = __DIAG_LOG__

import heartwood.recall_service as recall_service

def fake_sample():
    return recall_service.MemorySample(ps_rss_mb=12000.0, phys_footprint_mb=8000.0)

def fake_diag(**kwargs):
    path = Path(os.environ["HEARTWOOD_RECALL_DIAG_LOG"])
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{kwargs['reason']} diag captured\\n")
    return path

recall_service.sys.platform = "linux"
recall_service._current_memory_sample = fake_sample
recall_service._capture_memory_diagnostics = fake_diag
recall_service._start_memory_watchdog()
deadline = time.time() + 5
while time.time() < deadline:
    time.sleep(0.05)
raise SystemExit(99)
""".replace("__DIAG_LOG__", repr(str(kill_diag_log)))
    kill_proc = subprocess.run(
        [sys.executable, "-c", kill_script],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        capture_output=True,
        text=True,
        timeout=8,
        check=False,
    )

    assert kill_proc.returncode == 75
    assert "heartwood memory watchdog sustained ceiling exceeded:" in kill_proc.stderr
    assert "sustained_samples=4/4" in kill_proc.stderr
    assert "sustained_elapsed_s=" in kill_proc.stderr
    assert "/0.1" in kill_proc.stderr
    kill_diag_text = kill_diag_log.read_text(encoding="utf-8")
    assert "soft-warn diag captured" in kill_diag_text
    assert "sustained-hard-restart diag captured" in kill_diag_text

    recover_diag_log = tmp_path / "recover.diag.log"
    recover_script = """
import builtins
import os
import threading
from pathlib import Path

os.environ["HEARTWOOD_RECALL_RSS_WARN_MB"] = "2000"
os.environ["HEARTWOOD_RECALL_RSS_CEILING_MB"] = "4000"
os.environ["HEARTWOOD_RECALL_RSS_SUSTAIN_SAMPLES"] = "2"
os.environ["HEARTWOOD_RECALL_RSS_SUSTAIN_WINDOW_SEC"] = "0.20"
os.environ["HEARTWOOD_RECALL_WATCHDOG_INTERVAL_S"] = "0.05"
os.environ["HEARTWOOD_RECALL_DIAG_LOG"] = __DIAG_LOG__

import heartwood.recall_service as recall_service

samples = iter([
    recall_service.MemorySample(ps_rss_mb=12000.0, phys_footprint_mb=8000.0),
    recall_service.MemorySample(ps_rss_mb=12000.0, phys_footprint_mb=8000.0),
    recall_service.MemorySample(ps_rss_mb=12000.0, phys_footprint_mb=500.0),
])

def fake_sample():
    try:
        return next(samples)
    except StopIteration:
        return recall_service.MemorySample(ps_rss_mb=12000.0, phys_footprint_mb=500.0)

def fake_diag(**kwargs):
    path = Path(os.environ["HEARTWOOD_RECALL_DIAG_LOG"])
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{kwargs['reason']} diag captured\\n")
    return path

clock = iter([0.00, 0.05, 0.10])
recovered_seen = threading.Event()

def fake_monotonic():
    try:
        return next(clock)
    except StopIteration:
        return 0.10

def watched_print(*args, **kwargs):
    builtins.print(*args, **kwargs)
    message = " ".join(str(arg) for arg in args)
    if "heartwood memory watchdog recovered:" in message:
        recovered_seen.set()

recall_service.sys.platform = "linux"
recall_service.time.monotonic = fake_monotonic
recall_service.print = watched_print
recall_service._current_memory_sample = fake_sample
recall_service._capture_memory_diagnostics = fake_diag
recall_service._start_memory_watchdog()
if not recovered_seen.wait(timeout=5):
    raise SystemExit("watchdog recovered log not observed")
print("survived sub-window footprint breach")
""".replace("__DIAG_LOG__", repr(str(recover_diag_log)))
    recover_proc = subprocess.run(
        [sys.executable, "-c", recover_script],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        capture_output=True,
        text=True,
        timeout=8,
        check=False,
    )

    assert recover_proc.returncode == 0
    assert "survived sub-window footprint breach" in recover_proc.stdout
    assert "heartwood memory watchdog threshold observed:" in recover_proc.stderr
    assert "sustained_samples=2/2" in recover_proc.stderr
    assert "/0.2" in recover_proc.stderr
    assert "heartwood memory watchdog recovered:" in recover_proc.stderr
    assert "heartwood memory watchdog sustained ceiling exceeded:" not in recover_proc.stderr
    assert "soft-warn diag captured" in recover_diag_log.read_text(encoding="utf-8")


def test_memory_diagnostics_capture_process_breakdown(tmp_path, monkeypatch):
    import heartwood.recall_service as recall_service

    diag_log = tmp_path / "serve-recall.diag.log"
    monkeypatch.setenv("HEARTWOOD_RECALL_DIAG_LOG", str(diag_log))
    path = recall_service._capture_memory_diagnostics(
        reason="test-diagnostic",
        sample=MemorySample(ps_rss_mb=123.0, phys_footprint_mb=45.0),
        ceiling_mb=4000.0,
        warn_mb=2000.0,
        sustained_count=1,
    )

    assert path == diag_log
    text = diag_log.read_text(encoding="utf-8")
    assert "heartwood recall memory diagnostic" in text
    assert '"reason":"test-diagnostic"' in text
    assert '"ps_rss_mb":123.0' in text
    assert '"phys_footprint_mb":45.0' in text
    assert '"threading_active_count":' in text
    assert "$ footprint -p" in text
    assert "$ vmmap -summary" in text
    if sys.platform == "darwin":
        assert "Dirty" in text or "Physical footprint:" in text


def test_allocator_pressure_relief_runs_on_darwin_interval(monkeypatch):
    import heartwood.recall_service as recall_service

    calls = []

    def fake_pressure_relief():
        def relieve(zone, goal):
            calls.append((zone, goal))
            return 321

        return relieve

    monkeypatch.setattr(recall_service.sys, "platform", "darwin")
    monkeypatch.setenv("HEARTWOOD_RECALL_MALLOC_PRESSURE_RELIEF_RECALLS", "2")
    monkeypatch.setattr(recall_service, "_malloc_zone_pressure_relief", fake_pressure_relief)

    assert recall_service._maybe_relieve_allocator_pressure(1) is None
    assert recall_service._maybe_relieve_allocator_pressure(2) == 321
    assert calls == [(None, 0)]


def test_allocator_pressure_relief_noop_off_darwin(monkeypatch):
    import heartwood.recall_service as recall_service

    monkeypatch.setattr(recall_service.sys, "platform", "win32")
    monkeypatch.setenv("HEARTWOOD_RECALL_MALLOC_PRESSURE_RELIEF_RECALLS", "1")
    monkeypatch.setattr(
        recall_service,
        "_malloc_zone_pressure_relief",
        lambda: pytest.fail("malloc pressure relief should not be loaded off darwin"),
    )
    monkeypatch.setattr(
        recall_service,
        "_malloc_trim",
        lambda: pytest.fail("malloc_trim should not be loaded off linux"),
    )

    assert recall_service._maybe_relieve_allocator_pressure(1) is None


def test_allocator_pressure_relief_runs_on_linux_interval(monkeypatch):
    import heartwood.recall_service as recall_service

    calls = []

    def fake_malloc_trim():
        def trim(pad):
            calls.append(pad)
            return 1

        return trim

    monkeypatch.setattr(recall_service.sys, "platform", "linux")
    monkeypatch.setenv("HEARTWOOD_RECALL_MALLOC_PRESSURE_RELIEF_RECALLS", "2")
    monkeypatch.setattr(recall_service, "_malloc_trim", fake_malloc_trim)

    assert recall_service._maybe_relieve_allocator_pressure(1) is None
    assert recall_service._maybe_relieve_allocator_pressure(2) == 1
    assert calls == [0]


def test_default_text_cache_limit_covers_local_recall_corpus():
    import heartwood.client as client_module

    assert client_module._TEXT_CACHE_LIMIT >= 8192


@pytest.mark.real_model
def test_real_model_path_text_cache_lru_eviction_hard_bounds(monkeypatch):
    if os.environ.get("HEARTWOOD_REAL_MODEL_TESTS") != "1":
        pytest.skip("set HEARTWOOD_REAL_MODEL_TESTS=1 to load real sentence-transformers models")
    pytest.importorskip("sentence_transformers")
    with tempfile.TemporaryDirectory() as temp_dir:
        engine = RecallEngine(
            db_path=Path(temp_dir) / "heartwood.db",
            default_tenant="tenant:ops",
            dev_models=False,
        )
        try:
            assert "hashing-embedder" not in engine.embedder_name
            assert "lexical-overlap" not in engine.reranker_name
            _assert_text_cache_lru(engine.client("tenant:ops"), monkeypatch)
            print(
                "real_model_lru "
                f"embedder={engine.embedder_name} "
                f"reranker={engine.reranker_name} "
                "cache_limit=3 final_keys=mem_4,mem_2,mem_5"
            )
        finally:
            engine.close()


@pytest.mark.real_model
def test_real_model_recall_rss_soak_bounded():
    if os.environ.get("HEARTWOOD_REAL_MODEL_SOAK") != "1":
        pytest.skip("set HEARTWOOD_REAL_MODEL_SOAK=1 for the opt-in real-model RSS soak")
    pytest.importorskip("sentence_transformers")
    calls = int(os.environ.get("HEARTWOOD_REAL_MODEL_SOAK_CALLS", "30"))
    max_delta_mb = float(os.environ.get("HEARTWOOD_REAL_MODEL_SOAK_MAX_DELTA_MB", "300"))
    with tempfile.TemporaryDirectory() as temp_dir:
        engine = RecallEngine(
            db_path=Path(temp_dir) / "heartwood.db",
            default_tenant="tenant:ops",
            dev_models=False,
        )
        try:
            assert "hashing-embedder" not in engine.embedder_name
            assert "lexical-overlap" not in engine.reranker_name
            client = engine.client("tenant:ops")
            for index in range(18):
                client.remember(
                    (
                        f"Heartwood real model RSS soak record {index}. "
                        "Recall should keep model memory bounded while reranking "
                        "long enough text to exercise the cross encoder. "
                    ) * 16,
                    subject=f"soak:{index}",
                    created_by="agent:test",
                )
            engine.warm(["tenant:ops"])
            rss_before = _process_rss_mb()
            for index in range(calls):
                engine.recall(
                    {
                        "query": f"Which Heartwood RSS soak record mentions bounded reranking {index % 7}?",
                        "tenant": "tenant:ops",
                        "principal_id": "agent:test",
                        "k": 5,
                        "topc": 12,
                    }
                )
            rss_after = _process_rss_mb()
            print(
                "real_model_soak "
                f"calls={calls} "
                f"rss_before_mb={rss_before:.1f} "
                f"rss_after_mb={rss_after:.1f} "
                f"rss_delta_mb={rss_after - rss_before:.1f} "
                f"max_delta_mb={max_delta_mb:.1f}"
            )
            assert rss_after - rss_before < max_delta_mb
        finally:
            engine.close()


def test_warm_recall_engine_and_benchmark():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        memory = _write_corpus(root)
        db_path = root / "heartwood.db"
        embedder, reranker = dev_models()
        import_markdown_corpus(
            [memory],
            db_path=db_path,
            tenant_map={"acme": "tenant:acme-payments"},
            embedder=embedder,
            reranker=reranker,
        )

        engine = RecallEngine(db_path=db_path, default_tenant="tenant:acme-payments", dev_models=True)
        try:
            engine.warm(["tenant:acme-payments"])
            out = engine.recall(
                {
                    "query": "what should I preserve in Acme Payments reviews?",
                    "tenant": "tenant:acme-payments",
                    "principal_id": "agent:orchestrator",
                    "k": 3,
                }
            )
            assert out["ok"] is True
            assert out["latency_ms"] < 500.0
            assert out["results"]
            assert "audit details" in out["results"][0]["content"]

            for _ in range(5):
                engine.recall(
                    {
                        "query": "Acme Payments audit provenance guidance",
                        "tenant": "tenant:acme-payments",
                        "principal_id": "agent:orchestrator",
                        "k": 3,
                    }
                )
            metrics = engine.metrics()
            assert metrics["recall_count"] == 6
            assert metrics["p95_latency_ms"] < 500.0
        finally:
            engine.close()


def test_bench_recall_summary_only_stdout_keeps_full_artifact():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        memory = _write_corpus(root)
        db_path = root / "heartwood.db"
        output_path = root / "bench.json"
        embedder, reranker = dev_models()
        import_markdown_corpus(
            [memory],
            db_path=db_path,
            tenant_map={"acme": "tenant:acme-payments"},
            embedder=embedder,
            reranker=reranker,
        )

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "heartwood.cli",
                "bench-recall",
                "--db",
                str(db_path),
                "--tenant",
                "tenant:acme-payments",
                "--principal-id",
                "agent:orchestrator",
                "--query",
                "what should I preserve in Acme Payments reviews?",
                "--repeat",
                "1",
                "--dev-models",
                "--summary-only",
                "--output",
                str(output_path),
            ],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            capture_output=True,
            text=True,
            check=True,
        )
        stdout_payload = json.loads(result.stdout)
        artifact_payload = json.loads(output_path.read_text(encoding="utf-8"))
        assert "calls" not in stdout_payload
        assert stdout_payload["call_count"] == 1
        assert artifact_payload["call_count"] == 1
        assert len(artifact_payload["calls"]) == 1
        assert artifact_payload["calls"][0]["result_count"] > 0


def test_warm_recall_http_service_with_token():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        memory = _write_corpus(root)
        db_path = root / "heartwood.db"
        embedder, reranker = dev_models()
        import_markdown_corpus(
            [memory],
            db_path=db_path,
            tenant_map={"acme": "tenant:acme-payments"},
            embedder=embedder,
            reranker=reranker,
        )

        port = _free_port()
        base_url = f"http://127.0.0.1:{port}"
        token = "test-token"
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "heartwood.cli",
                "serve-recall",
                "--db",
                str(db_path),
                "--tenant",
                "tenant:acme-payments",
                "--warm-tenant",
                "tenant:acme-payments",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--token",
                token,
                "--dev-models",
            ],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            health = _wait_health(base_url, proc)
            assert health["ok"] is True
            assert health == {"ok": True, "service": "heartwood-recall"}
            assert "warmed_tenants" not in health
            assert "key_custody" not in health

            try:
                _request_json(base_url + "/recall", {"query": "audit details"}, method="POST")
                raise AssertionError("unauthenticated recall should have failed")
            except error.HTTPError as exc:
                assert exc.code == 401

            out = _request_json(
                base_url + "/recall",
                {
                    "query": "Acme Payments audit provenance guidance",
                    "tenant": "tenant:acme-payments",
                    "principal_id": "agent:orchestrator",
                    "k": 3,
                },
                token=token,
                method="POST",
            )
            assert out["ok"] is True
            assert out["result_count"] >= 1
            assert out["latency_ms"] < 500.0

            metrics = _request_json(base_url + "/metrics", token=token)
            assert metrics["recall_count"] == 1
            assert metrics["p95_latency_ms"] < 500.0
            assert "warmed_tenants" not in metrics
            assert "db_path" not in metrics
        finally:
            proc.terminate()
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate(timeout=5)
            assert "warmed_tenants" not in stdout
            assert "tenant:acme-payments" not in stdout
            assert str(db_path) not in stdout
            assert token not in stdout
            assert token not in stderr


def test_warm_recall_http_metrics_no_auth_mode():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        db_path = root / "heartwood.db"

        port = _free_port()
        base_url = f"http://127.0.0.1:{port}"
        env = os.environ.copy()
        env.pop("HEARTWOOD_RECALL_TOKEN", None)
        env.pop("HEARTWOOD_RECALL_TOKEN_FILE", None)
        env.pop("HEARTWOOD_RECALL_CREDENTIAL_FILE", None)
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "heartwood.cli",
                "serve-recall",
                "--db",
                str(db_path),
                "--tenant",
                "tenant:ops",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--dev-models",
            ],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        try:
            health = _wait_health(base_url, proc)
            assert health == {"ok": True, "service": "heartwood-recall"}
            req = request.Request(base_url + "/metrics", method="GET")
            with request.urlopen(req, timeout=10) as resp:
                assert resp.status == 200
                metrics = json.loads(resp.read().decode("utf-8"))
            assert metrics["ok"] is True
            assert metrics["recall_count"] == 0
            assert "latency_sample_count" in metrics
            assert "p95_latency_ms" in metrics
            assert "warmed_tenants" not in metrics
            assert "db_path" not in metrics
            assert "tenant:ops" not in json.dumps(metrics)
        finally:
            proc.terminate()
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate(timeout=5)
            assert "warmed_tenants" not in stdout
            assert "tenant:ops" not in stdout
            assert str(db_path) not in stdout
            assert "token" not in stderr.lower()


def test_warm_recall_local_readiness_requires_explicit_local_diagnostics():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        db_path = root / "heartwood.db"
        token = "local-readiness-token"

        port = _free_port()
        base_url = f"http://127.0.0.1:{port}"
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "heartwood.cli",
                "serve-recall",
                "--db",
                str(db_path),
                "--tenant",
                "tenant:ops",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--token",
                token,
                "--dev-models",
            ],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            health = _wait_health(base_url, proc)
            assert health == {"ok": True, "service": "heartwood-recall"}
            try:
                _request_json(base_url + "/local/readiness", token=token)
                raise AssertionError("local readiness should be disabled by default")
            except error.HTTPError as exc:
                assert exc.code == 404
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


def test_warm_recall_local_readiness_reports_dimension_without_health_expansion():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        memory = _write_corpus(root)
        db_path = root / "heartwood.db"
        token = "local-readiness-token"
        embedder, reranker = dev_models()
        import_markdown_corpus(
            [memory],
            db_path=db_path,
            tenant_map={"acme": "tenant:acme-payments"},
            embedder=embedder,
            reranker=reranker,
        )

        port = _free_port()
        base_url = f"http://127.0.0.1:{port}"
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "heartwood.cli",
                "serve-recall",
                "--db",
                str(db_path),
                "--tenant",
                "tenant:acme-payments",
                "--warm-tenant",
                "tenant:acme-payments",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--token",
                token,
                "--dev-models",
            ],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            env={
                **os.environ,
                "HEARTWOOD_RECALL_LOCAL_DIAGNOSTICS": "1",
            },
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            health = _wait_health(base_url, proc)
            assert health == {"ok": True, "service": "heartwood-recall"}
            readiness = _request_json(base_url + "/local/readiness", token=token)
            assert readiness["ok"] is False
            assert readiness["local_only"] is True
            assert readiness["embedder"] == {
                "name": "hashing-embedder(dev)",
                "dimension": 256,
                "dev_fallback": True,
            }
            assert readiness["db_embedding_dimensions"] == [256]
            assert readiness["ingestion"] == {
                "ok": True,
                "status": "ok",
                "configured": False,
                "sla_seconds": 21600,
                "last_import_at": readiness["ingestion"]["last_import_at"],
                "pending_sources_count": 0,
                "max_pending_lag_seconds": 0.0,
                "oldest_unindexed_source": None,
            }
            assert readiness["checks"]["non_dev_embedder"] is False
            assert readiness["checks"]["db_dimension_match"] is True
            assert readiness["checks"]["ingestion_lag_within_sla"] is True
            assert "warmed_tenants" not in readiness
            assert "key_custody" not in readiness
        finally:
            proc.terminate()
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate(timeout=5)
            assert "warmed_tenants" not in stdout
            assert token not in stdout
            assert token not in stderr


def test_local_readiness_ingestion_block_warns_on_stale_unindexed_source(monkeypatch):
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        memory = _write_corpus(root)
        db_path = root / "heartwood.db"
        embedder, reranker = dev_models()
        import_markdown_corpus(
            [memory],
            db_path=db_path,
            tenant_map={"acme": "tenant:acme-payments"},
            embedder=embedder,
            reranker=reranker,
        )
        stale = memory / "reference_stale_roundtrip.md"
        stale.write_text(
            "# Stale roundtrip source\n\nG3_STALE_SOURCE should be imported before readiness is green.",
            encoding="utf-8",
        )
        stale_mtime = time.time() - 7200
        os.utime(stale, (stale_mtime, stale_mtime))
        monkeypatch.setenv("HEARTWOOD_RECALL_SOURCE_ROOTS", str(memory))
        monkeypatch.setenv("HEARTWOOD_RECALL_INGESTION_SLA_S", "3600")
        monkeypatch.setenv("HEARTWOOD_RECALL_TENANT_MAP_JSON", '{"acme":"tenant:acme-payments"}')

        engine = RecallEngine(
            db_path=db_path,
            default_tenant="tenant:acme-payments",
            dev_models=True,
        )
        try:
            readiness = engine.local_readiness()
            ingestion = readiness["ingestion"]
            assert readiness["ok"] is False
            assert ingestion["ok"] is False
            assert ingestion["status"] == "warn"
            assert ingestion["configured"] is True
            assert ingestion["pending_sources_count"] == 1
            assert ingestion["max_pending_lag_seconds"] >= 7100
            assert ingestion["oldest_unindexed_source"]["path"] == "memory/reference_stale_roundtrip.md"
            assert readiness["checks"]["ingestion_lag_within_sla"] is False
        finally:
            engine.close()


def test_warm_recall_http_verify_roundtrip_local_authenticated_endpoint():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        db_path = root / "heartwood.db"
        credential_path = root / "credentials.json"
        token = "verify-roundtrip-token"
        _write_credential_file(
            credential_path,
            token=token,
            tenant="tenant:ops",
            roles=["heartwood:diagnostics"],
        )

        port = _free_port()
        base_url = f"http://127.0.0.1:{port}"
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "heartwood.cli",
                "serve-recall",
                "--db",
                str(db_path),
                "--tenant",
                "tenant:ops",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--credential-file",
                str(credential_path),
                "--dev-models",
            ],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            env={
                **os.environ,
                "HEARTWOOD_RECALL_LOCAL_DIAGNOSTICS": "1",
            },
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            _wait_health(base_url, proc)
            out = _request_json(
                base_url + "/local/verify_roundtrip",
                {"source_marker": "g3_http_roundtrip", "lag_budget_seconds": 0.25},
                token=token,
                method="POST",
            )
            assert out["ok"] is True
            assert out["roundtrip_ok"] is True
            assert out["cleanup_ok"] is True
            assert out["canary_tenant"] == "tenant:__heartwood_canary__"
            assert out["source_marker"].startswith("heartwood-roundtrip-canary-")
            assert out["payload_marker_ignored"] is True
            assert out["recallable_at"] is not None
        finally:
            proc.terminate()
            stdout, stderr = proc.communicate(timeout=5)
            assert token not in stdout
            assert token not in stderr


def test_warm_recall_http_verify_roundtrip_requires_diagnostic_admin_credential():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        db_path = root / "heartwood.db"
        credential_path = root / "credentials.json"
        token = "verify-roundtrip-non-admin-token"
        _write_credential_file(credential_path, token=token, tenant="tenant:ops")

        port = _free_port()
        base_url = f"http://127.0.0.1:{port}"
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "heartwood.cli",
                "serve-recall",
                "--db",
                str(db_path),
                "--tenant",
                "tenant:ops",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--credential-file",
                str(credential_path),
                "--dev-models",
            ],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            env={
                **os.environ,
                "HEARTWOOD_RECALL_LOCAL_DIAGNOSTICS": "1",
            },
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            _wait_health(base_url, proc)
            with pytest.raises(error.HTTPError) as exc_info:
                _request_json(
                    base_url + "/local/verify_roundtrip",
                    {"lag_budget_seconds": 0},
                    token=token,
                    method="POST",
                )
            assert exc_info.value.code == 403
        finally:
            proc.terminate()
            stdout, stderr = proc.communicate(timeout=5)
            assert token not in stdout
            assert token not in stderr


def test_authenticated_http_recall_uses_credential_principal_not_body_escalation():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        memory = _write_corpus(root)
        db_path = root / "heartwood.db"
        credential_path = root / "credentials.json"
        token = "hw_boundary_token"
        _write_credential_file(credential_path, token=token)
        embedder, reranker = dev_models()
        import_markdown_corpus(
            [memory],
            db_path=db_path,
            tenant_map={"acme": "tenant:acme-payments"},
            embedder=embedder,
            reranker=reranker,
        )

        port = _free_port()
        base_url = f"http://127.0.0.1:{port}"
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "heartwood.cli",
                "serve",
                "--db",
                str(db_path),
                "--tenant",
                "tenant:acme-payments",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--credential-file",
                str(credential_path),
                "--dev-models",
            ],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            _wait_health(base_url, proc)
            foreign = _request_json(
                base_url + "/recall",
                {
                    "query": "Northwind Retail auth finance incidents",
                    "tenant": "tenant:northwind-retail",
                    "principal_id": "agent:attacker",
                    "clearance": "restricted",
                    "roles": ["finance"],
                    "k": 5,
                    "topc": 20,
                },
                token=token,
                method="POST",
            )
            assert foreign["tenant"] == "tenant:acme-payments"
            assert foreign["principal"] == {
                "id": "agent:gateway",
                "tenant": "tenant:acme-payments",
                "roles": [],
                "attrs": {},
                "clearance": "internal",
            }
            assert all("Northwind Retail" not in result["content"] for result in foreign["results"])

            escalated = _request_json(
                base_url + "/recall",
                {
                    "query": "Acme treasury margin controls payment risk policy",
                    "tenant": "tenant:acme-payments",
                    "principal_id": "agent:attacker",
                    "clearance": "restricted",
                    "roles": ["finance"],
                    "k": 5,
                    "topc": 20,
                },
                token=token,
                method="POST",
            )
            assert escalated["tenant"] == "tenant:acme-payments"
            assert escalated["principal"]["clearance"] == "internal"
            assert escalated["principal"]["roles"] == []
            assert all(result["classification"] not in {"confidential", "restricted"} for result in escalated["results"])
            assert all("finance" not in result["content"].lower() for result in escalated["results"])
        finally:
            proc.terminate()
            stdout, stderr = proc.communicate(timeout=5)
            assert token not in stdout
            assert token not in stderr


def test_per_org_credential_file_rotates_without_redeploy():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        memory = _write_corpus(root)
        db_path = root / "heartwood.db"
        credential_path = root / "credentials.json"
        old_token = "hw_old_rotation_token"
        new_token = "hw_new_rotation_token"
        _write_credential_file(credential_path, token=old_token)
        embedder, reranker = dev_models()
        import_markdown_corpus(
            [memory],
            db_path=db_path,
            tenant_map={"acme": "tenant:acme-payments"},
            embedder=embedder,
            reranker=reranker,
        )

        port = _free_port()
        base_url = f"http://127.0.0.1:{port}"
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "heartwood.cli",
                "serve",
                "--db",
                str(db_path),
                "--tenant",
                "tenant:acme-payments",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--credential-file",
                str(credential_path),
                "--dev-models",
            ],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            _wait_health(base_url, proc)
            before = _request_json(
                base_url + "/recall",
                {"query": "Acme Payments audit provenance guidance", "k": 3},
                token=old_token,
                method="POST",
            )
            assert before["ok"] is True

            _write_credential_file(credential_path, token=new_token)
            try:
                _request_json(
                    base_url + "/recall",
                    {"query": "Acme Payments audit provenance guidance", "k": 3},
                    token=old_token,
                    method="POST",
                )
                raise AssertionError("old token should fail after credential-file rotation")
            except error.HTTPError as exc:
                assert exc.code == 401

            after = _request_json(
                base_url + "/recall",
                {"query": "Acme Payments audit provenance guidance", "k": 3},
                token=new_token,
                method="POST",
            )
            assert after["ok"] is True
        finally:
            proc.terminate()
            stdout, stderr = proc.communicate(timeout=5)
            assert old_token not in stdout
            assert old_token not in stderr
            assert new_token not in stdout
            assert new_token not in stderr


def test_per_org_credential_rate_limit_returns_429_and_token_not_logged():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        memory = _write_corpus(root)
        db_path = root / "heartwood.db"
        credential_path = root / "credentials.json"
        token = "hw_sentinel_token_for_log_capture"
        _write_credential_file(credential_path, token=token, rate_limit_requests=2)
        embedder, reranker = dev_models()
        import_markdown_corpus(
            [memory],
            db_path=db_path,
            tenant_map={"acme": "tenant:acme-payments"},
            embedder=embedder,
            reranker=reranker,
        )

        port = _free_port()
        base_url = f"http://127.0.0.1:{port}"
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "heartwood.cli",
                "serve",
                "--db",
                str(db_path),
                "--tenant",
                "tenant:acme-payments",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--credential-file",
                str(credential_path),
                "--dev-models",
            ],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            _wait_health(base_url, proc)
            payload = {"query": "Acme Payments audit provenance guidance", "k": 3}
            assert _request_json(base_url + "/recall", payload, token=token, method="POST")["ok"] is True
            try:
                _request_json(base_url + "/recall", payload, token=f"{token}-bad", method="POST")
                raise AssertionError("bad token should be rejected")
            except error.HTTPError as exc:
                assert exc.code == 401
            assert _request_json(base_url + "/recall", payload, token=token, method="POST")["ok"] is True
            try:
                _request_json(base_url + "/recall", payload, token=token, method="POST")
                raise AssertionError("third request inside the window should be rate limited")
            except error.HTTPError as exc:
                assert exc.code == 429
                assert int(exc.headers["X-RateLimit-Limit"]) == 2
                assert int(exc.headers["X-RateLimit-Remaining"]) == 0
        finally:
            proc.terminate()
            stdout, stderr = proc.communicate(timeout=5)
            assert token not in stdout
            assert token not in stderr


def test_r3_token_file_auth_for_serve_recall():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        memory = _write_corpus(root)
        db_path = root / "heartwood.db"
        token_path = root / "recall-token.txt"
        token_path.write_text("file-token\n", encoding="utf-8")
        embedder, reranker = dev_models()
        import_markdown_corpus(
            [memory],
            db_path=db_path,
            tenant_map={"acme": "tenant:acme-payments"},
            embedder=embedder,
            reranker=reranker,
        )

        port = _free_port()
        base_url = f"http://127.0.0.1:{port}"
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "heartwood.cli",
                "serve-recall",
                "--db",
                str(db_path),
                "--tenant",
                "tenant:acme-payments",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--token-file",
                str(token_path),
                "--dev-models",
            ],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            _wait_health(base_url, proc)
            out = _request_json(
                base_url + "/recall",
                {
                    "query": "Acme Payments audit provenance guidance",
                    "tenant": "tenant:acme-payments",
                    "principal_id": "agent:orchestrator",
                    "k": 3,
                },
                token="file-token",
                method="POST",
            )
            assert out["ok"] is True
            assert out["result_count"] >= 1
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


def test_r3_empty_token_file_fails_closed():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        db_path = root / "heartwood.db"
        for token_contents in ("", " \n\t"):
            token_path = root / "recall-token.txt"
            token_path.write_text(token_contents, encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "heartwood.cli",
                    "serve-recall",
                    "--db",
                    str(db_path),
                    "--tenant",
                    "tenant:ops",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(_free_port()),
                    "--token-file",
                    str(token_path),
                    "--dev-models",
                ],
                cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                capture_output=True,
                text=True,
                timeout=5,
            )
            assert proc.returncode == 1
            assert f"heartwood error: token file {token_path} is empty" in proc.stderr
            assert '"auth": "none"' not in proc.stdout


def test_g6_cli_forget_purges_subject():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        db_path = root / "heartwood.db"
        embedder, reranker = dev_models()
        db = Heartwood(path=db_path, tenant="tenant:ops", embedder=embedder, reranker=reranker)
        try:
            db.remember(
                "Delete this customer preference after DSAR.",
                subject="customer:erase",
                created_by="agent:test",
            )
        finally:
            db.close()

        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "heartwood.cli",
                "forget",
                "--db",
                str(db_path),
                "--tenant",
                "tenant:ops",
                "--subject",
                "customer:erase",
                "--actor",
                "agent:test",
                "--reason",
                "DSAR",
                "--dev-models",
            ],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            capture_output=True,
            text=True,
            check=True,
        )
        out = json.loads(proc.stdout)
        assert out["ok"] is True
        assert out["purged"] == 1

        db = Heartwood(path=db_path, tenant="tenant:ops", embedder=embedder, reranker=reranker)
        try:
            recalled = db.recall(
                "customer preference DSAR",
                principal=db.principal("agent:test"),
                filters={"subject": "customer:erase"},
                k=3,
            )
            assert recalled["results"] == []
        finally:
            db.close()


def test_g6_warm_recall_http_forget_requires_auth_and_purges():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        db_path = root / "heartwood.db"
        embedder, reranker = dev_models()
        db = Heartwood(path=db_path, tenant="tenant:ops", embedder=embedder, reranker=reranker)
        try:
            db.remember(
                "Delete this HTTP customer preference after DSAR.",
                subject="customer:http-erase",
                created_by="agent:test",
            )
        finally:
            db.close()

        port = _free_port()
        base_url = f"http://127.0.0.1:{port}"
        token = "test-token"
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "heartwood.cli",
                "serve-recall",
                "--db",
                str(db_path),
                "--tenant",
                "tenant:ops",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--token",
                token,
                "--dev-models",
            ],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            _wait_health(base_url, proc)
            try:
                _request_json(
                    base_url + "/forget",
                    {"tenant": "tenant:ops", "subject": "customer:http-erase"},
                    method="POST",
                )
                raise AssertionError("unauthenticated forget should have failed")
            except error.HTTPError as exc:
                assert exc.code == 401

            try:
                _request_json(
                    base_url + "/forget",
                    {"tenant": "tenant:ops", "subject": "customer:http-erase", "mode": "soft"},
                    token=token,
                    method="POST",
                )
                raise AssertionError("unknown forget mode should have failed")
            except error.HTTPError as exc:
                assert exc.code == 400
                body = json.loads(exc.read().decode("utf-8"))
                assert body["ok"] is False
                assert "unsupported forget mode" in body["error"]

            still_present = _request_json(
                base_url + "/recall",
                {
                    "query": "HTTP customer preference DSAR",
                    "tenant": "tenant:ops",
                    "principal_id": "agent:test",
                    "k": 3,
                },
                token=token,
                method="POST",
            )
            assert still_present["ok"] is True
            assert still_present["result_count"] >= 1

            receipt = _request_json(
                base_url + "/forget",
                {"tenant": "tenant:ops", "subject": "customer:http-erase", "actor": "agent:test", "reason": "DSAR"},
                token=token,
                method="POST",
            )
            assert receipt["ok"] is True
            assert receipt["purged"] == 1

            after = _request_json(
                base_url + "/recall",
                {
                    "query": "HTTP customer preference DSAR",
                    "tenant": "tenant:ops",
                    "principal_id": "agent:test",
                    "k": 3,
                },
                token=token,
                method="POST",
            )
            assert after["ok"] is True
            assert after["results"] == []
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


def test_cross_tenant_two_credential_isolation_negative():
    """P2-1 (#10003541): runnable cross-tenant isolation negative test.

    Proves the server-authoritative principal binding (IDOR fix) end-to-end with a
    TWO-credential token file — the least-tested high-stakes path and the first
    thing a pentester probes. Four invariants, each asserted below:

      (1) A configured credential store exposes two tokens, one per tenant.
      (2) Each token recalls ONLY its own tenant's record (no cross-tenant leak).
      (3) A payload-declared `tenant` (and forged principal/clearance/roles) is
          IGNORED — the principal is bound from the authenticated credential.
      (4) The engine raises PermissionError("server principal required") when a
          credential store is configured but no server principal is present.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        db_path = root / "heartwood.db"
        _seed_two_tenant_corpus(db_path)

        # Invariant (4): the engine-level fail-closed guard. With a credential store
        # configured the handler always passes allow_payload_principal=False; assert
        # the guard fires directly so the IDOR floor is provable without the network.
        guard_engine = RecallEngine(db_path=db_path, default_tenant="tenant:acme-payments", dev_models=True)
        try:
            with pytest.raises(PermissionError, match="server principal required"):
                guard_engine.recall(
                    {
                        "query": "ACME_CANARY audit provenance guidance",
                        "tenant": "tenant:northwind-retail",
                        "principal_id": "agent:attacker",
                        "roles": ["finance"],
                        "clearance": "restricted",
                    },
                    principal=None,
                    allow_payload_principal=False,
                )
        finally:
            guard_engine.close()

        credential_path = root / "credentials.json"
        acme_token = "hw_acme_isolation_token"
        northwind_token = "hw_northwind_isolation_token"
        _write_two_tenant_credential_file(
            credential_path, acme_token=acme_token, northwind_token=northwind_token
        )

        port = _free_port()
        base_url = f"http://127.0.0.1:{port}"
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "heartwood.cli",
                "serve",
                "--db",
                str(db_path),
                "--tenant",
                "tenant:acme-payments",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--credential-file",
                str(credential_path),
                "--dev-models",
            ],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            _wait_health(base_url, proc)

            # Invariant (2) + (3): the acme token, even while FORGING tenant/principal/
            # clearance/roles toward northwind, is bound to acme and reads only acme.
            acme_view = _request_json(
                base_url + "/recall",
                {
                    "query": "audit provenance retention guidance for reviews",
                    "tenant": "tenant:northwind-retail",
                    "principal_id": "agent:attacker",
                    "clearance": "restricted",
                    "roles": ["finance"],
                    "k": 5,
                    "topc": 20,
                },
                token=acme_token,
                method="POST",
            )
            assert acme_view["tenant"] == "tenant:acme-payments"  # payload tenant ignored
            assert acme_view["principal"] == {
                "id": "agent:acme-gateway",
                "tenant": "tenant:acme-payments",
                "roles": [],
                "attrs": {},
                "clearance": "internal",
            }
            acme_blob = json.dumps(acme_view)
            assert "ACME_CANARY" in acme_blob
            assert "NORTHWIND_CANARY" not in acme_blob

            # The acme token cannot reach northwind data even when it asks for it by
            # northwind topic AND forges the northwind tenant.
            acme_probe_northwind = _request_json(
                base_url + "/recall",
                {
                    "query": "Northwind Retail auth incident review runbook",
                    "tenant": "tenant:northwind-retail",
                    "principal_id": "agent:attacker",
                    "k": 5,
                    "topc": 20,
                },
                token=acme_token,
                method="POST",
            )
            assert acme_probe_northwind["tenant"] == "tenant:acme-payments"
            assert "NORTHWIND_CANARY" not in json.dumps(acme_probe_northwind)

            # Invariant (2) + (3) mirrored: the northwind token reads only northwind,
            # and forging the acme tenant does not cross the boundary.
            northwind_view = _request_json(
                base_url + "/recall",
                {
                    "query": "auth incident review runbook for finance",
                    "tenant": "tenant:acme-payments",
                    "principal_id": "agent:attacker",
                    "clearance": "restricted",
                    "roles": ["finance"],
                    "k": 5,
                    "topc": 20,
                },
                token=northwind_token,
                method="POST",
            )
            assert northwind_view["tenant"] == "tenant:northwind-retail"  # payload tenant ignored
            assert northwind_view["principal"]["id"] == "agent:northwind-gateway"
            northwind_blob = json.dumps(northwind_view)
            assert "NORTHWIND_CANARY" in northwind_blob
            assert "ACME_CANARY" not in northwind_blob
        finally:
            proc.terminate()
            stdout, stderr = proc.communicate(timeout=5)
            # Invariant (1): neither raw token is ever emitted to the process streams.
            assert acme_token not in stdout
            assert acme_token not in stderr
            assert northwind_token not in stdout
            assert northwind_token not in stderr


def test_recall_rate_limit_keys_off_credential_not_spoofable_xff():
    """P2-4 (#10003187): the rate limiter keys off the authenticated credential,
    NOT a client-supplied X-Forwarded-For header.

    An attacker who rotates `X-Forwarded-For` on every request must NOT be able to
    mint a fresh rate-limit bucket (which would let them evade the per-credential
    limit). The limiter bucket key is `credential.token_digest` — a trusted,
    authenticated identity derived from the bearer token, never from a spoofable
    proxy header. This test rotates XFF across requests on a single token with a
    limit of 2 and asserts the 3rd request is still 429.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        memory = _write_corpus(root)
        db_path = root / "heartwood.db"
        credential_path = root / "credentials.json"
        token = "hw_xff_isolation_token"
        _write_credential_file(credential_path, token=token, rate_limit_requests=2)
        embedder, reranker = dev_models()
        import_markdown_corpus(
            [memory],
            db_path=db_path,
            tenant_map={"acme": "tenant:acme-payments"},
            embedder=embedder,
            reranker=reranker,
        )

        port = _free_port()
        base_url = f"http://127.0.0.1:{port}"
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "heartwood.cli",
                "serve",
                "--db",
                str(db_path),
                "--tenant",
                "tenant:acme-payments",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--credential-file",
                str(credential_path),
                "--dev-models",
            ],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            _wait_health(base_url, proc)
            payload = {"query": "Acme Payments audit provenance guidance", "k": 3}

            # Two allowed requests, each with a DIFFERENT forged client IP.
            first = _request_json(
                base_url + "/recall", payload, token=token, method="POST",
                extra_headers={"X-Forwarded-For": "203.0.113.1"},
            )
            assert first["ok"] is True
            second = _request_json(
                base_url + "/recall", payload, token=token, method="POST",
                extra_headers={"X-Forwarded-For": "203.0.113.2"},
            )
            assert second["ok"] is True

            # Third request, yet another forged client IP. If the limiter keyed off
            # XFF, this fresh IP would reset the bucket and succeed. It must 429.
            try:
                _request_json(
                    base_url + "/recall", payload, token=token, method="POST",
                    extra_headers={"X-Forwarded-For": "203.0.113.3"},
                )
                raise AssertionError(
                    "XFF rotation reset the rate limit — limiter is keyed off a spoofable header"
                )
            except error.HTTPError as exc:
                assert exc.code == 429
                assert int(exc.headers["X-RateLimit-Limit"]) == 2
                assert int(exc.headers["X-RateLimit-Remaining"]) == 0
        finally:
            proc.terminate()
            stdout, stderr = proc.communicate(timeout=5)
            assert token not in stdout
            assert token not in stderr


def main():
    test_warm_recall_engine_and_benchmark()
    test_warm_recall_http_service_with_token()
    test_r3_token_file_auth_for_serve_recall()
    test_r3_empty_token_file_fails_closed()
    test_g6_cli_forget_purges_subject()
    test_g6_warm_recall_http_forget_requires_auth_and_purges()
    # Server-authoritative principal binding / cross-tenant isolation (IDOR floor).
    test_recall_engine_fails_closed_when_payload_principal_disabled()
    test_authenticated_http_recall_uses_credential_principal_not_body_escalation()
    test_cross_tenant_two_credential_isolation_negative()
    test_recall_rate_limit_keys_off_credential_not_spoofable_xff()
    print("WARM RECALL TESTS PASSED")


if __name__ == "__main__":
    main()
