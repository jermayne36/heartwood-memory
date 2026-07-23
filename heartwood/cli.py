"""Command-line entrypoint for Phase 1 Heartwood product workflows."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .client import Heartwood
from .importers.edges import import_edges
from .importers.markdown import dev_models, import_markdown_corpus
from .key_custody import LocalKmsCustodian, root_to_b64
from .recall_service import RecallEngine, call_recall_service, call_forget_service, serve_recall


def _env_bool(name: str, default: bool = True) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def cmd_import_markdown(args: argparse.Namespace) -> dict:
    embedder = reranker = None
    if args.dev_models:
        embedder, reranker = dev_models()
    return import_markdown_corpus(
        args.source,
        db_path=args.db,
        default_tenant=args.default_tenant,
        created_by=args.created_by,
        tenant_map=_json_mapping(args.tenant_map_json),
        prefix_epistemic_map=_json_mapping(args.prefix_epistemic_map_json),
        embedder=embedder,
        reranker=reranker,
        update=args.update,
        stop_on_error=args.stop_on_error,
    )


def cmd_import_edges(args: argparse.Namespace) -> dict:
    return import_edges(
        db_path=args.db,
        sources=args.source or (),
        proposal_jsonl=args.proposal_jsonl,
        tenant=args.tenant,
        wikilink_kind=args.wikilink_kind,
        stop_on_error=args.stop_on_error,
    )


def cmd_bulk_remember(args: argparse.Namespace) -> dict:
    embedder = reranker = None
    if args.dev_models:
        embedder, reranker = dev_models()
    db = Heartwood(
        path=args.db,
        tenant=args.tenant,
        embedder=embedder,
        reranker=reranker,
        index=args.index,
    )
    try:
        report = db.remember_many(
            _load_records(args.input),
            default_created_by=args.created_by,
            default_tenant=args.tenant,
            stop_on_error=args.stop_on_error,
        )
        return {"db_path": str(args.db), **report}
    finally:
        db.close()


def _recall_payload(args: argparse.Namespace) -> dict:
    filters = json.loads(args.filters_json) if args.filters_json else {}
    payload = {
        "query": args.query,
        "tenant": args.tenant,
        "principal_id": args.principal_id,
        "roles": args.roles,
        "attrs": args.attrs,
        "clearance": args.clearance,
        "k": args.k,
        "topc": args.topc,
        "filters": filters,
    }
    for key in ("subject", "method", "intent", "effective_at"):
        value = getattr(args, key, None)
        if value not in (None, ""):
            payload[key] = value
    if getattr(args, "typed", False):
        payload["typed"] = True
    if getattr(args, "entities", None):
        payload["entities"] = args.entities
    return payload


def cmd_recall(args: argparse.Namespace) -> dict:
    payload = _recall_payload(args)
    if args.url:
        return call_recall_service(args.url, payload, token=_token(args))
    if not args.db:
        raise ValueError("recall requires --db unless --url is used")
    engine = RecallEngine(
        db_path=args.db,
        default_tenant=args.tenant,
        dev_models=args.dev_models,
        index=args.index,
    )
    try:
        engine.warm([args.tenant])
        return engine.recall(payload)
    finally:
        engine.close()


def cmd_serve_recall(args: argparse.Namespace) -> None:
    token_file = (
        args.credential_file
        or args.token_file
        or os.environ.get("HEARTWOOD_RECALL_CREDENTIAL_FILE")
        or os.environ.get("HEARTWOOD_RECALL_TOKEN_FILE")
    )
    token = None
    if token_file is None:
        if args.token:
            print(
                "heartwood warning: --token is deprecated because argv can expose secrets; "
                "use HEARTWOOD_RECALL_TOKEN or --token-file.",
                file=sys.stderr,
            )
            token = args.token
        else:
            token = os.environ.get("HEARTWOOD_RECALL_TOKEN")
    serve_recall(
        db_path=args.db,
        host=args.host,
        port=args.port,
        default_tenant=args.tenant,
        warm_tenants=args.warm_tenant or [args.tenant],
        token=token,
        token_file=token_file,
        tls_cert_file=args.tls_cert_file,
        tls_key_file=args.tls_key_file,
        dev_models=args.dev_models,
        index=args.index,
        warm_on_start=_env_bool("HEARTWOOD_RECALL_WARM_ON_START", True),
    )
    return None


def _forget_payload(args: argparse.Namespace) -> dict:
    return {
        "tenant": args.tenant,
        "subject": args.subject,
        "mode": args.mode,
        "actor": args.actor,
        "reason": args.reason,
        "legal_basis": args.legal_basis,
    }


def cmd_forget(args: argparse.Namespace) -> dict:
    payload = _forget_payload(args)
    if args.url:
        return call_forget_service(args.url, payload, token=_token(args))
    if not args.db:
        raise ValueError("forget requires --db unless --url is used")
    embedder = reranker = None
    if args.dev_models:
        embedder, reranker = dev_models()
    db = Heartwood(path=args.db, tenant=args.tenant, embedder=embedder, reranker=reranker, index=args.index)
    try:
        return {"ok": True, "tenant": db.tenant, **db.forget(
            args.subject,
            mode=args.mode,
            actor=args.actor,
            reason=args.reason,
            legal_basis=args.legal_basis,
        )}
    finally:
        db.close()


def cmd_purge(args: argparse.Namespace) -> dict:
    embedder = reranker = None
    if args.dev_models:
        embedder, reranker = dev_models()
    db = Heartwood(
        path=args.db,
        tenant=args.tenant,
        embedder=embedder,
        reranker=reranker,
        index=args.index,
    )
    try:
        purged = db.purge(args.id, actor=args.actor)
        return {"ok": purged, "tenant": db.tenant, "id": args.id, "purged": purged}
    finally:
        db.close()


def cmd_init_identity(args: argparse.Namespace) -> dict:
    root_key = os.urandom(32)
    root_b64 = root_to_b64(root_key)
    key_id = args.key_id
    principals = list(args.principal or ())
    custodian = LocalKmsCustodian(root_key=root_key, key_id=key_id)
    registered: list[dict[str, str]] = []
    if args.db:
        embedder, reranker = dev_models()
        db = Heartwood(
            path=args.db,
            tenant=args.tenant,
            embedder=embedder,
            reranker=reranker,
            key_custodian=custodian,
        )
        try:
            for principal in principals:
                public_key = db.signer.register(principal)
                registered.append(
                    {
                        "tenant": db.tenant,
                        "principal": principal,
                        "algorithm": "ed25519",
                        "public_key_prefix": root_to_b64(public_key)[:16],
                    }
                )
        finally:
            db.close()
    return {
        "ok": True,
        "tenant": args.tenant,
        "db_path": str(args.db) if args.db else None,
        "root_export": f"export HEARTWOOD_KEY_CUSTODY_ROOT_B64={root_b64}",
        "key_id_export": f"export HEARTWOOD_KEY_CUSTODY_KEY_ID={key_id}",
        "vault_notice": (
            "Store this root in YOUR vault; Heartwood never sees it and does not persist it."
        ),
        "registered_principals": registered,
        "multi_agent_example": [
            f"export HEARTWOOD_KEY_CUSTODY_ROOT_B64={root_b64}",
            f"export HEARTWOOD_KEY_CUSTODY_KEY_ID={key_id}",
            "heartwood import-markdown ./memory "
            f"--db {args.db or 'heartwood.db'} "
            f"--created-by {principals[0] if principals else 'agent:researcher'}",
            "heartwood import-markdown ./team-memory "
            f"--db {args.db or 'heartwood.db'} "
            f"--created-by {principals[1] if len(principals) > 1 else 'agent:reviewer'}",
        ],
    }


def cmd_strict_preflight(args: argparse.Namespace) -> dict:
    embedder = reranker = None
    if args.dev_models:
        embedder, reranker = dev_models()
    db = Heartwood(
        path=args.db,
        tenant=args.tenant,
        embedder=embedder,
        reranker=reranker,
        index=args.index,
        strict_signatures="off",
        strict_legacy_exemption="off",
    )
    try:
        if args.activate:
            manifest_path = args.manifest or os.environ.get(
                "HEARTWOOD_STRICT_CUTOVER_PATH"
            )
            manifest_digest = args.manifest_digest or os.environ.get(
                "HEARTWOOD_STRICT_CUTOVER_DIGEST"
            )
            if not manifest_path or not manifest_digest:
                raise ValueError(
                    "strict-preflight --activate requires --manifest and "
                    "--manifest-digest (or the matching HEARTWOOD_STRICT_* env vars)"
                )
            return db.activate_strict_cutover(
                manifest_path=str(manifest_path),
                manifest_digest=manifest_digest,
                operator=args.operator,
            )
        if args.approve_report_digest:
            if not args.manifest_out:
                raise ValueError(
                    "strict-preflight --approve-report-digest requires --manifest-out"
                )
            return db.seal_strict_cutover(
                approved_report_digest=args.approve_report_digest,
                manifest_path=str(args.manifest_out),
                operator=args.operator,
                reason=args.reason,
            )
        if args.manifest_out or args.manifest or args.manifest_digest:
            raise ValueError(
                "manifest options require --approve-report-digest or --activate"
            )
        return db.strict_preflight()
    finally:
        db.close()


def cmd_bench_recall(args: argparse.Namespace) -> dict:
    queries = list(args.query or ())
    if args.queries_file:
        queries.extend(_load_queries(args.queries_file))
    if not queries:
        raise ValueError("bench-recall requires --query or --queries-file")
    latencies = []
    calls = []
    engine = None
    try:
        if not args.url:
            if not args.db:
                raise ValueError("bench-recall requires --db unless --url is used")
            engine = RecallEngine(
                db_path=args.db,
                default_tenant=args.tenant,
                dev_models=args.dev_models,
                index=args.index,
            )
            engine.warm([args.tenant])
        for _ in range(args.repeat):
            for query in queries:
                payload = _recall_payload(argparse.Namespace(**{**vars(args), "query": query}))
                out = (
                    call_recall_service(args.url, payload, token=_token(args))
                    if args.url
                    else engine.recall(payload)
                )
                if not out.get("ok"):
                    raise RuntimeError(out.get("error") or "recall failed")
                latencies.append(float(out["latency_ms"]))
                calls.append({"query": query, "latency_ms": out["latency_ms"], "result_count": out["result_count"]})
    finally:
        if engine:
            engine.close()

    p95 = _percentile(latencies, 95)
    passed = p95 <= args.max_p95_ms
    report = {
        "ok": True,
        "query_count": len(queries),
        "call_count": len(latencies),
        "p50_latency_ms": round(_percentile(latencies, 50), 3),
        "p95_latency_ms": round(p95, 3),
        "max_latency_ms": round(max(latencies), 3),
        "max_p95_ms": args.max_p95_ms,
        "passed": passed,
        "calls": calls,
    }
    if args.require_pass and not passed:
        raise RuntimeError(f"p95 latency {p95:.3f}ms exceeds {args.max_p95_ms:.3f}ms")
    return report


def _add_recall_args(parser: argparse.ArgumentParser, *, query_required: bool = True) -> None:
    parser.add_argument("--db", type=Path, help="Heartwood SQLite database. Required unless --url is used.")
    if query_required:
        parser.add_argument("--query", required=True)
    parser.add_argument("--tenant", default="tenant:ops")
    parser.add_argument("--principal-id", default="agent:recall")
    parser.add_argument("--roles", default="")
    parser.add_argument("--attrs", default="")
    parser.add_argument("--clearance", default="internal")
    parser.add_argument("--k", type=int, default=5)
    parser.add_argument("--topc", type=int, default=50)
    parser.add_argument("--subject", default="")
    parser.add_argument("--method", default="")
    parser.add_argument("--typed", action="store_true")
    parser.add_argument("--intent", default="")
    parser.add_argument("--entity", dest="entities", action="append")
    parser.add_argument("--effective-at", default="")
    parser.add_argument("--filters-json", default="")
    parser.add_argument("--token", help="Deprecated: bearer token for --url service calls. Prefer HEARTWOOD_RECALL_TOKEN or --token-file.")
    parser.add_argument("--token-file", type=Path, help="File containing the bearer token for --url service calls.")
    parser.add_argument("--dev-models", action="store_true", help="Use deterministic local test models.")
    parser.add_argument("--index", default="numpy", choices=("numpy", "auto", "sqlite-vec"))


def _load_queries(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    if path.suffix.lower() == ".json":
        data = json.loads(text)
        if isinstance(data, list):
            return [str(item.get("query") if isinstance(item, dict) else item) for item in data]
        if isinstance(data, dict):
            return [str(item) for item in data.get("queries", [])]
    queries = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            data = json.loads(line)
            queries.append(str(data.get("query") or data.get("cue") or ""))
        else:
            queries.append(line)
    return [query for query in queries if query]


def _load_records(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    if path.suffix.lower() == ".json":
        data = json.loads(text)
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and isinstance(data.get("records"), list):
            return data["records"]
        raise ValueError("JSON input must be a list or an object with records[]")

    records = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        data = json.loads(line)
        if not isinstance(data, dict):
            raise ValueError(f"JSONL line {line_number} must be an object")
        records.append(data)
    return records


def _json_mapping(value: str) -> dict[str, str]:
    if not value:
        return {}
    data = json.loads(value)
    if not isinstance(data, dict):
        raise ValueError("mapping JSON must be an object")
    return {str(key): str(val) for key, val in data.items()}


def _percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int((p / 100.0) * len(ordered) + 0.999999) - 1))
    return ordered[index]


def _token(args: argparse.Namespace) -> str | None:
    token_file = getattr(args, "token_file", None) or os.environ.get("HEARTWOOD_RECALL_TOKEN_FILE")
    if token_file:
        token = Path(token_file).read_text(encoding="utf-8").strip()
        if not token:
            raise ValueError(f"token file {token_file} is empty")
        return token
    if getattr(args, "token", None):
        print(
            "heartwood warning: --token is deprecated because argv can expose secrets; "
            "use HEARTWOOD_RECALL_TOKEN or --token-file.",
            file=sys.stderr,
        )
        return args.token
    return os.environ.get("HEARTWOOD_RECALL_TOKEN")


def write_output(args: argparse.Namespace, payload: dict) -> None:
    if payload is None:
        return
    text = json.dumps(payload, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    stdout_payload = payload
    if getattr(args, "summary_only", False) and isinstance(payload, dict):
        stdout_payload = {key: value for key, value in payload.items() if key != "calls"}
    print(json.dumps(stdout_payload, indent=2))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Heartwood Memory CLI.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    ingest = subparsers.add_parser(
        "import-markdown",
        aliases=("ingest-markdown",),
        help="Bulk-import Markdown/frontmatter memory files into a Heartwood SQLite store.",
    )
    ingest.add_argument("source", nargs="+", type=Path, help="Markdown file or directory to import.")
    ingest.add_argument("--db", type=Path, required=True, help="Target Heartwood SQLite database.")
    ingest.add_argument("--default-tenant", default="tenant:ops")
    ingest.add_argument("--created-by", default="agent:markdown-importer")
    ingest.add_argument(
        "--tenant-map-json",
        default="",
        help="Optional JSON object mapping path tokens to tenant ids, e.g. '{\"acme\":\"tenant:acme-payments\"}'.",
    )
    ingest.add_argument(
        "--prefix-epistemic-map-json",
        default="",
        help="Optional JSON object mapping filename prefixes to epistemic classes.",
    )
    ingest.add_argument(
        "--dev-models",
        action="store_true",
        help="Use deterministic hashing/lexical models for fast local tests.",
    )
    ingest.add_argument(
        "--update",
        action="store_true",
        help="Replace stale rows from the same source path before importing.",
    )
    ingest.add_argument(
        "--stop-on-error",
        action="store_true",
        help="Abort immediately on the first malformed source file.",
    )
    ingest.add_argument(
        "--allow-partial",
        action="store_true",
        help="Exit 0 even when the report contains failed_count > 0.",
    )
    ingest.add_argument("--output", type=Path)
    ingest.set_defaults(handler=cmd_import_markdown)

    edges = subparsers.add_parser(
        "import-edges",
        help="Import provenance/graph edges from proposal JSONL and markdown wikilinks.",
    )
    edges.add_argument(
        "source",
        nargs="*",
        type=Path,
        help="Markdown file or directory to scan for [[wikilinks]].",
    )
    edges.add_argument("--db", type=Path, required=True, help="Target Heartwood SQLite database.")
    edges.add_argument("--tenant", default="tenant:ops")
    edges.add_argument(
        "--proposal-jsonl",
        type=Path,
        help="JSONL proposal with src_id, dst_id, and type/kind fields.",
    )
    edges.add_argument(
        "--wikilink-kind",
        default="links_to",
        help="Edge kind to write for markdown [[wikilinks]].",
    )
    edges.add_argument(
        "--stop-on-error",
        action="store_true",
        help="Abort immediately on the first malformed proposal row.",
    )
    edges.add_argument("--output", type=Path)
    edges.set_defaults(handler=cmd_import_edges)

    bulk = subparsers.add_parser(
        "bulk-remember",
        aliases=("remember-many",),
        help="Bulk-write JSON/JSONL memory records through the public Heartwood API.",
    )
    bulk.add_argument("--input", type=Path, required=True, help="JSON list/object or JSONL memory records.")
    bulk.add_argument("--db", type=Path, required=True, help="Target Heartwood SQLite database.")
    bulk.add_argument("--tenant", default="tenant:ops", help="Default tenant for records without tenant.")
    bulk.add_argument("--created-by", default="agent:bulk", help="Default producer principal.")
    bulk.add_argument("--stop-on-error", action="store_true")
    bulk.add_argument("--dev-models", action="store_true", help="Use deterministic local test models.")
    bulk.add_argument("--index", default="numpy", choices=("numpy", "auto", "sqlite-vec"))
    bulk.add_argument("--output", type=Path)
    bulk.set_defaults(handler=cmd_bulk_remember)

    recall = subparsers.add_parser(
        "recall",
        help="Policy-enforced recall from a Heartwood store or warm recall service.",
    )
    _add_recall_args(recall)
    recall.add_argument("--url", help="Warm recall service base URL, e.g. http://127.0.0.1:8765")
    recall.add_argument("--json", action="store_true", help="Emit JSON. This is the default.")
    recall.add_argument("--output", type=Path)
    recall.set_defaults(handler=cmd_recall)

    serve = subparsers.add_parser(
        "serve-recall",
        aliases=("serve",),
        help="Run a localhost warm recall service for hook/agent calls.",
    )
    serve.add_argument("--db", type=Path, required=True, help="Heartwood SQLite database.")
    serve.add_argument("--tenant", default="tenant:ops", help="Default tenant.")
    serve.add_argument("--warm-tenant", action="append", help="Tenant to warm at service start; repeatable.")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--token", help="Deprecated: optional bearer token required for recall/metrics requests. Prefer HEARTWOOD_RECALL_TOKEN or --token-file.")
    serve.add_argument("--token-file", type=Path, help="File containing the bearer token required for recall/metrics requests.")
    serve.add_argument("--credential-file", type=Path, help="JSON per-org credential file; falls back to --token-file for legacy plaintext tokens.")
    serve.add_argument("--tls-cert-file", type=Path, help="TLS certificate for daemon-side HTTPS termination.")
    serve.add_argument("--tls-key-file", type=Path, help="TLS private key for daemon-side HTTPS termination.")
    serve.add_argument("--dev-models", action="store_true", help="Use deterministic local test models.")
    serve.add_argument("--index", default="numpy", choices=("numpy", "auto", "sqlite-vec"))
    serve.set_defaults(handler=cmd_serve_recall)

    forget = subparsers.add_parser(
        "forget",
        help="Crypto-shred a subject through a local store or authenticated warm recall service.",
    )
    forget.add_argument("--db", type=Path, help="Heartwood SQLite database. Required unless --url is used.")
    forget.add_argument("--url", help="Warm recall service base URL, e.g. http://127.0.0.1:8765")
    forget.add_argument("--tenant", default="tenant:ops")
    forget.add_argument("--subject", required=True)
    forget.add_argument("--mode", default="hard", choices=("hard",))
    forget.add_argument("--actor", default="agent:cli")
    forget.add_argument("--reason", default="")
    forget.add_argument("--legal-basis", dest="legal_basis", default="")
    forget.add_argument("--token", help="Deprecated: bearer token for --url service calls. Prefer HEARTWOOD_RECALL_TOKEN or --token-file.")
    forget.add_argument("--token-file", type=Path, help="File containing the bearer token for --url service calls.")
    forget.add_argument("--dev-models", action="store_true", help="Use deterministic local test models.")
    forget.add_argument("--index", default="numpy", choices=("numpy", "auto", "sqlite-vec"))
    forget.add_argument("--output", type=Path)
    forget.set_defaults(handler=cmd_forget)

    purge = subparsers.add_parser(
        "purge",
        help="Physically delete one memory row without shredding the subject key.",
    )
    purge.add_argument("--db", type=Path, required=True, help="Target Heartwood SQLite database.")
    purge.add_argument("--tenant", default="tenant:ops")
    purge.add_argument("--id", required=True, help="Memory id to delete.")
    purge.add_argument("--actor", default="agent:cli")
    purge.add_argument("--dev-models", action="store_true", help="Use deterministic local test models.")
    purge.add_argument("--index", default="numpy", choices=("numpy", "auto", "sqlite-vec"))
    purge.add_argument("--output", type=Path)
    purge.set_defaults(handler=cmd_purge)

    identity = subparsers.add_parser(
        "init-identity",
        help="Generate a customer-held custody root and register durable principal identities.",
    )
    identity.add_argument(
        "--db",
        type=Path,
        help="Optional Heartwood SQLite database for principal registration.",
    )
    identity.add_argument("--tenant", default="tenant:ops")
    identity.add_argument("--principal", action="append", help="Principal id to register; repeat for each agent.")
    identity.add_argument("--key-id", default="env-root-v1")
    identity.add_argument("--output", type=Path)
    identity.set_defaults(handler=cmd_init_identity)

    strict = subparsers.add_parser(
        "strict-preflight",
        help=(
            "Audit every stored record for strict mode; optionally seal or activate "
            "an exact operator-approved cutover snapshot."
        ),
    )
    strict.add_argument("--db", type=Path, required=True, help="Target Heartwood SQLite database.")
    strict.add_argument("--tenant", default="tenant:ops")
    strict.add_argument("--operator", default="agent:strict-operator")
    strict.add_argument("--reason", default="")
    strict.add_argument(
        "--approve-report-digest",
        help="Exact report digest approved by the operator; rescanned under a write lock.",
    )
    strict.add_argument(
        "--manifest-out",
        type=Path,
        help="New strict-cutover artifact path used with --approve-report-digest.",
    )
    strict.add_argument(
        "--activate",
        action="store_true",
        help="Append the activation transition after validating the exact seal head.",
    )
    strict.add_argument("--manifest", type=Path, help="Sealed strict-cutover artifact.")
    strict.add_argument(
        "--manifest-digest",
        help="Exact sha256:<hex> operator-config pin for --manifest.",
    )
    strict.add_argument("--dev-models", action="store_true")
    strict.add_argument("--index", default="numpy", choices=("numpy", "auto", "sqlite-vec"))
    strict.add_argument("--output", type=Path)
    strict.set_defaults(handler=cmd_strict_preflight)

    bench = subparsers.add_parser(
        "bench-recall",
        help="Measure warm recall latency and optionally require the p95 SLO.",
    )
    _add_recall_args(bench, query_required=False)
    bench.add_argument("--query", action="append", help="Query to benchmark; repeatable.")
    bench.add_argument("--queries-file", type=Path, help="JSON, JSONL, or plain text query file.")
    bench.add_argument("--repeat", type=int, default=5)
    bench.add_argument("--max-p95-ms", type=float, default=500.0)
    bench.add_argument("--require-pass", action="store_true")
    bench.add_argument(
        "--summary-only",
        action="store_true",
        help="Print only aggregate benchmark fields; --output still receives the full call array.",
    )
    bench.add_argument("--url", help="Warm recall service base URL.")
    bench.add_argument("--output", type=Path)
    bench.set_defaults(handler=cmd_bench_recall)

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    try:
        payload = args.handler(args)
    except Exception as exc:
        print(f"heartwood error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    write_output(args, payload)
    if (
        isinstance(payload, dict)
        and int(payload.get("failed_count") or 0) > 0
        and not getattr(args, "allow_partial", False)
    ):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
