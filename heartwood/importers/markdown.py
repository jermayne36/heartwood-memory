"""Markdown/frontmatter importer for derived Heartwood memory stores.

The importer keeps Markdown files as the human-readable source of truth and
rebuilds Heartwood memory projections from them. It is intentionally dependency
free: frontmatter support covers the simple YAML subset used by agent memory
files while allowing explicit metadata to override filename-based inference.
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

import numpy as np

from ..client import Heartwood
from ..contextual_ingest import (
    ContextualDocument,
    default_egress_request_builder,
    ingest_contextual,
)
from ..envelope import Epistemic, Kind, Policy, hash_content
from ..policy import Principal
from ..retrieval import get_embedder, get_reranker, tokenize
from ..store import Store

SECRET_HINTS = (
    "password",
    "secret",
    "api_key",
    "apikey",
    "token",
    "credential",
    "private_key",
)

# Real-secret formats. Precise on purpose: detect actual secret material in the
# BODY, not topic words in the filename. Placeholders/examples are excluded.
_SECRET_CONTENT_PATTERNS = (
    r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"\bsk-[A-Za-z0-9]{20,}\b",
    r"\bAIza[0-9A-Za-z_\-]{35}\b",
    r"\bghp_[A-Za-z0-9]{36}\b",
    r"\bgithub_pat_[A-Za-z0-9_]{60,}\b",
    r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
)
_SECRET_PLACEHOLDER_HINTS = (
    "example",
    "xxxx",
    "your-",
    "your_",
    "changeme",
    "redacted",
    "placeholder",
    "sk-test",
    "<",
    "...",
    "akiaiosfodnn7example",
)

DEFAULT_PREFIX_EPISTEMIC_MAP = {
    "feedback_": Epistemic.USER_STATED.value,
    "reference_": Epistemic.IMPORTED_SOURCE.value,
    "project_": Epistemic.OBSERVED_FACT.value,
}


@dataclass(frozen=True)
class MarkdownDocument:
    path: Path
    relative_path: str
    frontmatter: dict[str, Any]
    content: str


@dataclass(frozen=True)
class MarkdownMemorySpec:
    path: Path
    relative_path: str
    tenant: str
    memory_id: str
    subject: str
    subject_ids: tuple[str, ...]
    kind: str
    epistemic: str
    created_by: str
    classification: str
    pii: bool
    roles: tuple[str, ...]
    attrs: tuple[tuple[str, str], ...]
    policy_scope: str
    confidence: float
    salience: float
    source_uri: str
    content_hash: str
    content: str
    entities: tuple[str, ...]
    valid_from: str | None
    valid_until: str | None


def import_markdown_corpus(
    sources: Iterable[str | Path],
    *,
    db_path: str | Path,
    default_tenant: str = "tenant:ops",
    default_principal: str = "owner:operator",
    created_by: str | None = None,
    tenant_map: Mapping[str, str] | None = None,
    prefix_epistemic_map: Mapping[str, str] | None = None,
    embedder=None,
    reranker=None,
    contextual_threshold_tokens: int | None = None,
    contextual_generator=None,
    contextual_egress_request_builder=None,
    contextual_target_tokens: int = 180,
    contextual_overlap: int = 30,
    update: bool = False,
    stop_on_error: bool = False,
) -> dict[str, Any]:
    """Bulk-import Markdown files into a Heartwood SQLite store.

    Multiple tenants are supported by opening a tenant-scoped Heartwood client
    per tenant over the same SQLite path. Import is idempotent for identical
    file content because memory ids include the source path and content hash.
    """
    source_paths = [Path(source) for source in sources]
    documents = load_markdown_documents(source_paths)
    source_document_counts = _source_document_counts(source_paths, documents)
    row_counts_before = _memory_counts(db_path)
    embedder, reranker = _resolve_models(embedder, reranker)
    producer = created_by or default_principal
    imported: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    errors: list[dict[str, str]] = []
    purged: list[dict[str, str]] = []
    tenants: Counter[str] = Counter()

    for source, count in source_document_counts.items():
        if source.is_dir() and count == 0:
            errors.append(
                {
                    "path": str(source),
                    "error": "directory source produced zero markdown documents",
                }
            )

    specs: list[MarkdownMemorySpec] = []
    for document in documents:
        if not document.content.strip():
            continue
        try:
            specs.append(
                build_memory_spec(
                    document,
                    default_tenant=default_tenant,
                    default_created_by=producer,
                    tenant_map=tenant_map,
                    prefix_epistemic_map=prefix_epistemic_map,
                )
            )
        except Exception as exc:  # noqa: BLE001
            errors.append({"path": document.relative_path, "error": str(exc)})
            if stop_on_error:
                raise

    by_tenant: dict[str, list[MarkdownMemorySpec]] = {}
    for spec in specs:
        by_tenant.setdefault(spec.tenant, []).append(spec)

    for tenant, tenant_specs in sorted(by_tenant.items()):
        dimension_error = _embedding_dimension_error(db_path, embedder)
        if dimension_error:
            errors.append(dimension_error)
            if stop_on_error:
                raise ValueError(dimension_error["error"])
            break
        db = Heartwood(
            path=str(db_path),
            tenant=tenant,
            embedder=embedder,
            reranker=reranker,
        )
        try:
            for spec in tenant_specs:
                try:
                    use_contextual = (
                        contextual_generator is not None
                        and contextual_threshold_tokens is not None
                        and len(tokenize(spec.content)) > contextual_threshold_tokens
                    )
                    existing_id = (
                        f"{spec.memory_id}:chunk:0000"
                        if use_contextual else spec.memory_id
                    )
                    existing = db.store.get_meta(existing_id)
                    post_import_purge_rows: list[dict[str, Any]] = []
                    if update:
                        prior_rows = db.store.memories_by_source_path(
                            spec.tenant,
                            spec.relative_path,
                            source_uri=spec.source_uri,
                        )
                        stale_prior_rows = [
                            row for row in prior_rows
                            if row.get("content_hash") != spec.content_hash
                        ]
                        if existing and existing.get("content_hash") == spec.content_hash:
                            _purge_prior_rows(db, spec, stale_prior_rows, purged)
                            existing = db.store.get_meta(existing_id)
                        elif existing and stale_prior_rows:
                            _ensure_signing_available(db, spec.created_by)
                            _purge_prior_rows(db, spec, stale_prior_rows, purged)
                            existing = db.store.get_meta(existing_id)
                        else:
                            post_import_purge_rows = stale_prior_rows
                    if existing:
                        skipped.append(
                            {
                                "path": spec.relative_path,
                                "tenant": spec.tenant,
                                "id": existing_id,
                                "reason": "already_imported",
                            }
                        )
                        continue
                    if _secret_hint_text(spec.relative_path, {"pii": spec.pii}):
                        warnings.append(
                            {
                                "path": spec.relative_path,
                                "tenant": spec.tenant,
                                "warning": f"secret-like filename/metadata; VERIFY no secret in body (classified: {spec.classification})",
                            }
                        )
                    policy = Policy(
                        classification=spec.classification,
                        pii=spec.pii,
                        roles=spec.roles,
                        attrs=spec.attrs,
                    )
                    if use_contextual:
                        result = ingest_contextual(
                            db,
                            ContextualDocument(
                                content=spec.content,
                                subject=spec.subject,
                                subject_ids=spec.subject_ids,
                                created_by=spec.created_by,
                                kind=spec.kind,
                                epistemic=spec.epistemic,
                                confidence=spec.confidence,
                                salience=spec.salience,
                                source={
                                    "kind": "markdown",
                                    "uri": spec.source_uri,
                                    "path": spec.relative_path,
                                },
                                policy=policy,
                                memory_id=spec.memory_id,
                                policy_scope=spec.policy_scope,
                                valid_from=spec.valid_from,
                                valid_until=spec.valid_until,
                                entities=spec.entities,
                                source_ids=(spec.source_uri,),
                            ),
                            generator=contextual_generator,
                            egress_request_builder=(
                                contextual_egress_request_builder
                                or default_egress_request_builder
                            ),
                            principal=Principal(
                                id=spec.created_by,
                                tenant=spec.tenant,
                                clearance=spec.classification,
                            ),
                            target_tokens=contextual_target_tokens,
                            overlap=contextual_overlap,
                        )
                        if result.mode == "contextual":
                            for record in result.records:
                                imported.append(
                                    {
                                        "path": spec.relative_path,
                                        "tenant": spec.tenant,
                                        "id": record.chunk_id,
                                        "context_id": record.context_id,
                                        "epistemic": spec.epistemic,
                                        "kind": spec.kind,
                                        "classification": spec.classification,
                                        "ingest_mode": "contextual",
                                    }
                                )
                                tenants[tenant] += 1
                            _purge_prior_rows(db, spec, post_import_purge_rows, purged)
                        else:
                            imported.append(
                                {
                                    "path": spec.relative_path,
                                    "tenant": spec.tenant,
                                    "id": result.ids[0],
                                    "epistemic": spec.epistemic,
                                    "kind": spec.kind,
                                    "classification": spec.classification,
                                    "ingest_mode": result.mode,
                                    "fallback_reason": result.fallback_reason,
                                }
                            )
                            tenants[tenant] += 1
                            _purge_prior_rows(db, spec, post_import_purge_rows, purged)
                        continue
                    source_span = {
                        "source_id": spec.source_uri,
                        "span_id": f"{spec.source_uri}#body",
                        "text": spec.content,
                        "content_hash": spec.content_hash,
                    }
                    mem_id = db.remember(
                        spec.content,
                        subject=spec.subject,
                        subject_ids=spec.subject_ids,
                        created_by=spec.created_by,
                        kind=spec.kind,
                        epistemic=spec.epistemic,
                        confidence=spec.confidence,
                        salience=spec.salience,
                        source={
                            "kind": "markdown",
                            "uri": spec.source_uri,
                            "path": spec.relative_path,
                        },
                        policy=policy,
                        memory_id=spec.memory_id,
                        policy_scope=spec.policy_scope,
                        valid_from=spec.valid_from,
                        valid_until=spec.valid_until,
                        entities=spec.entities,
                        source_ids=(spec.source_uri,),
                        source_spans=(source_span,),
                    )
                    imported.append(
                        {
                            "path": spec.relative_path,
                            "tenant": spec.tenant,
                            "id": mem_id,
                            "epistemic": spec.epistemic,
                            "kind": spec.kind,
                            "classification": spec.classification,
                        }
                    )
                    tenants[tenant] += 1
                    _purge_prior_rows(db, spec, post_import_purge_rows, purged)
                except Exception as exc:  # noqa: BLE001
                    errors.append(
                        {
                            "path": spec.relative_path,
                            "tenant": spec.tenant,
                            "id": spec.memory_id,
                            "error": str(exc),
                        }
                    )
                    if stop_on_error:
                        raise
        finally:
            db.store.close()

    row_counts_after = _memory_counts(db_path)
    return _import_report(
        db_path=db_path,
        documents=documents,
        source_document_counts=source_document_counts,
        imported=imported,
        skipped=skipped,
        errors=errors,
        warnings=warnings,
        purged=purged,
        tenants=tenants,
        row_counts_before=row_counts_before,
        row_counts_after=row_counts_after,
    )


def _memory_counts(db_path: str | Path) -> dict[str, int]:
    store = Store(str(db_path))
    try:
        return store.memory_counts_by_tenant()
    finally:
        store.close()


def _memory_embedding_dimensions(db_path: str | Path) -> list[int]:
    store = Store(str(db_path))
    try:
        rows = store.conn.execute(
            "SELECT DISTINCT emb_dim FROM memories "
            "WHERE indexed=1 AND emb_dim>0 ORDER BY emb_dim"
        ).fetchall()
        return [int(row["emb_dim"]) for row in rows]
    finally:
        store.close()


def _resolve_models(embedder, reranker):
    if embedder is None:
        embedder = get_embedder()
    if reranker is None:
        reranker = get_reranker()
    return embedder, reranker


def _embedding_dimension_error(
    db_path: str | Path,
    embedder,
) -> dict[str, Any] | None:
    db_dimensions = _memory_embedding_dimensions(db_path)
    if not db_dimensions:
        return None
    vector = embedder[0](["heartwood import-markdown dimension check"])[0]
    import_dimension = int(len(vector))
    if len(db_dimensions) == 1 and db_dimensions[0] == import_dimension:
        return None
    return {
        "path": str(db_path),
        "code": "embedding_dimension_mismatch",
        "error": (
            "embedding dimension mismatch: existing indexed rows have "
            f"dimensions {db_dimensions}, but import embedder {embedder[1]!r} "
            f"produces dimension {import_dimension}; refusing to write "
            "unservable rows"
        ),
        "existing_dimensions": ",".join(str(dim) for dim in db_dimensions),
        "import_dimension": str(import_dimension),
        "embedder": str(embedder[1]),
    }


def _import_report(
    *,
    db_path: str | Path,
    documents: list[MarkdownDocument],
    source_document_counts: dict[Path, int],
    imported: list[dict[str, str]],
    skipped: list[dict[str, str]],
    errors: list[dict[str, str]],
    warnings: list[dict[str, str]],
    purged: list[dict[str, str]],
    tenants: Counter[str],
    row_counts_before: dict[str, int],
    row_counts_after: dict[str, int],
) -> dict[str, Any]:
    processed_paths = {row["path"] for row in imported} | {row["path"] for row in skipped}
    source_coverage_count = len(processed_paths)
    source_lag_count = max(0, len(documents) - source_coverage_count)
    row_count_before = sum(row_counts_before.values())
    row_count_after = sum(row_counts_after.values())
    return {
        "ok": not errors,
        "db_path": str(db_path),
        "source_count": len(documents),
        "source_counts": {str(source): count for source, count in source_document_counts.items()},
        "imported_count": len(imported),
        "skipped_count": len(skipped),
        "failed_count": len(errors),
        "purged_count": len(purged),
        # Deprecated alias for `purged_count`, kept for one release so existing
        # report consumers keep working. These rows are deleted, not moved to
        # review_state="superseded"; the old name described the wrong mechanism.
        # Removal target: 0.3.0.
        "superseded_count": len(purged),
        "source_coverage_count": source_coverage_count,
        "source_lag_count": source_lag_count,
        "memory_row_count_before": row_count_before,
        "memory_row_count_after": row_count_after,
        "memory_row_count_delta": row_count_after - row_count_before,
        "memory_row_counts_before": row_counts_before,
        "memory_row_counts_after": row_counts_after,
        "tenant_counts": dict(sorted(tenants.items())),
        "imported": imported,
        "skipped": skipped,
        "purged": purged,
        "superseded": purged,  # Deprecated alias for `purged`. Removal target: 0.3.0.
        "errors": errors,
        "warnings": warnings,
    }


def _source_document_counts(
    sources: Iterable[Path],
    documents: Iterable[MarkdownDocument],
) -> dict[Path, int]:
    docs = list(documents)
    counts: dict[Path, int] = {}
    for source in sources:
        if source.is_dir():
            counts[source] = sum(1 for document in docs if _is_relative_to(document.path, source))
        elif source.is_file() and source.suffix.lower() == ".md":
            counts[source] = sum(1 for document in docs if document.path == source)
    return counts


def _purge_prior_rows(
    db: Heartwood,
    spec: MarkdownMemorySpec,
    rows: Iterable[dict[str, Any]],
    purged: list[dict[str, str]],
) -> None:
    """Delete prior rows for a changed source file.

    This is a hard delete via ``db.purge`` — it does not move rows to
    ``review_state="superseded"``. To retire a governed record, transition or
    expire it explicitly first; see docs/api/recall-visibility-and-retirement.md.
    """
    for row in rows:
        if db.purge(row["id"], actor=spec.created_by):
            purged.append(
                {
                    "path": spec.relative_path,
                    "tenant": spec.tenant,
                    "id": row["id"],
                    "reason": "source_changed",
                }
            )


def _ensure_signing_available(db: Heartwood, principal_id: str) -> None:
    db.signer.register(principal_id)


def load_markdown_documents(sources: Iterable[str | Path]) -> list[MarkdownDocument]:
    roots = [Path(source) for source in sources]
    files: list[tuple[Path, Path]] = []
    for source in roots:
        if source.is_file() and source.suffix.lower() == ".md":
            files.append((source.parent, source))
        elif source.is_dir():
            for path in source.rglob("*.md"):
                if _is_hidden(path, root=source):
                    continue
                files.append((source.parent, path))
    documents = []
    for root, path in sorted(files, key=lambda item: str(item[1]).lower()):
        text = path.read_text(encoding="utf-8")
        frontmatter, body = split_frontmatter(text)
        documents.append(
            MarkdownDocument(
                path=path,
                relative_path=path.relative_to(root).as_posix(),
                frontmatter=frontmatter,
                content=body.strip(),
            )
        )
    return documents


def build_memory_spec(
    document: MarkdownDocument,
    *,
    default_tenant: str = "tenant:ops",
    default_created_by: str = "owner:operator",
    tenant_map: Mapping[str, str] | None = None,
    prefix_epistemic_map: Mapping[str, str] | None = None,
) -> MarkdownMemorySpec:
    meta = document.frontmatter
    tenant = normalize_tenant(
        _first(meta, "tenant", "tenant_id")
        or infer_tenant(document.relative_path, tenant_map=tenant_map, default=default_tenant),
        default=default_tenant,
    )
    kind = str(_first(meta, "kind", "memory_type") or infer_kind(document.relative_path))
    Kind(kind)
    epistemic = str(
        _first(meta, "epistemic", "epistemic_class")
        or infer_epistemic(document.relative_path, prefix_epistemic_map=prefix_epistemic_map)
    )
    Epistemic(epistemic)
    explicit_classification = _first(meta, "classification")
    pii = bool_value(_first(meta, "pii", "contains_pii"), default=False)
    classification = str(explicit_classification or ("restricted" if pii else "internal"))
    # Auto-restrict ONLY on detected secret CONTENT, and never override explicit frontmatter.
    if explicit_classification is None and _secret_content(document.content):
        classification = "restricted"
        pii = True
    tenant_slug = tenant.split(":", 1)[-1]
    stem = Path(document.relative_path).stem
    subject = str(_first(meta, "subject", "subject_id") or f"memory:{tenant_slug}:{_slug(stem)}")
    subject_ids = tuple(str(item) for item in list_value(_first(meta, "subject_ids"), default=[]))
    if not subject_ids:
        subject_ids = (subject, f"tenant:{tenant_slug}", f"file:{_slug(stem)}")
    created_by = str(_first(meta, "created_by", "producer") or infer_created_by(document.relative_path, default_created_by))
    policy_scope = str(_first(meta, "policy_scope") or tenant_slug)
    source_uri = str(_first(meta, "source_uri", "source_id") or f"markdown://{document.relative_path}")
    content_hash = hash_content(document.content)
    memory_id = str(_first(meta, "memory_id", "id") or stable_memory_id(tenant, document.relative_path, content_hash))
    return MarkdownMemorySpec(
        path=document.path,
        relative_path=document.relative_path,
        tenant=tenant,
        memory_id=memory_id,
        subject=subject,
        subject_ids=subject_ids,
        kind=kind,
        epistemic=epistemic,
        created_by=created_by,
        classification=classification,
        pii=pii,
        roles=tuple(str(item) for item in list_value(_first(meta, "roles"), default=[])),
        attrs=tuple(_attr_pair(item) for item in list_value(_first(meta, "attrs"), default=[])),
        policy_scope=policy_scope,
        confidence=float(_first(meta, "confidence") or 0.9),
        salience=float(_first(meta, "salience") or 0.6),
        source_uri=source_uri,
        content_hash=content_hash,
        content=document.content,
        entities=tuple(str(item) for item in list_value(_first(meta, "entities"), default=[])),
        valid_from=_none_or_str(_first(meta, "valid_from")),
        valid_until=_none_or_str(_first(meta, "valid_until")),
    )


def split_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    normalized = text.replace("\r\n", "\n")
    lines = normalized.split("\n")
    if not lines or lines[0].strip() != "---":
        return {}, normalized
    for index in range(1, len(lines)):
        if lines[index].strip() == "---":
            frontmatter_text = "\n".join(lines[1:index])
            body = "\n".join(lines[index + 1 :])
            return parse_frontmatter(frontmatter_text), body
    return {}, normalized


def parse_frontmatter(text: str) -> dict[str, Any]:
    data: dict[str, Any] = {}
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        raw = lines[index]
        index += 1
        if not raw.strip() or raw.lstrip().startswith("#") or ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        key = key.strip()
        value = value.strip()
        if value:
            data[key] = parse_scalar(value)
            continue
        items: list[str] = []
        while index < len(lines):
            candidate = lines[index]
            stripped = candidate.strip()
            if not stripped:
                index += 1
                continue
            if not stripped.startswith("- "):
                break
            items.append(stripped[2:].strip())
            index += 1
        data[key] = [parse_scalar(item) for item in items]
    return data


def parse_scalar(value: str) -> Any:
    value = value.strip()
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    lowered = value.lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [parse_scalar(part.strip()) for part in inner.split(",")]
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def infer_tenant(
    relative_path: str,
    *,
    tenant_map: Mapping[str, str] | None = None,
    default: str = "tenant:ops",
) -> str:
    haystack = relative_path.lower().replace("-", "_")
    for needle, tenant in (tenant_map or {}).items():
        normalized = str(needle).lower().replace("-", "_")
        if normalized and normalized in haystack:
            return normalize_tenant(tenant, default=default)
    if "team_memory" in haystack or "team-memory" in haystack:
        return "tenant:ops"
    if any(token in haystack for token in ("dispatch", "infra", "orchestrat", "feedback", "reference", "project")):
        return "tenant:ops"
    return default


def infer_kind(relative_path: str) -> str:
    stem = Path(relative_path).stem.lower()
    if stem.startswith("reference_"):
        return Kind.SOURCE.value
    return Kind.SEMANTIC.value


def infer_epistemic(relative_path: str, *, prefix_epistemic_map: Mapping[str, str] | None = None) -> str:
    """Infer epistemic class from a default prefix convention callers may override."""
    stem = Path(relative_path).stem.lower()
    mapping = dict(DEFAULT_PREFIX_EPISTEMIC_MAP)
    for prefix, epistemic in (prefix_epistemic_map or {}).items():
        mapping[str(prefix).lower()] = str(epistemic)
    for prefix in ("feedback_", "reference_"):
        epistemic = mapping.pop(prefix, None)
        if epistemic and stem.startswith(prefix):
            Epistemic(epistemic)
            return epistemic
    if "hypothesis" in stem:
        return Epistemic.HYPOTHESIS.value
    if "inferred" in stem or "belief" in stem:
        return Epistemic.INFERRED_BELIEF.value
    for prefix, epistemic in mapping.items():
        if stem.startswith(prefix):
            Epistemic(epistemic)
            return epistemic
    return Epistemic.IMPORTED_SOURCE.value


def infer_created_by(relative_path: str, default: str) -> str:
    return default


def stable_memory_id(tenant: str, relative_path: str, content_hash: str) -> str:
    slug = _slug(Path(relative_path).stem)[:36] or "markdown"
    digest = hashlib.sha256(f"{tenant}|{relative_path}|{content_hash}".encode("utf-8")).hexdigest()[:16]
    return f"md_{slug}_{digest}"


def normalize_tenant(value: Any, *, default: str = "tenant:ops") -> str:
    if not value:
        return default
    text = str(value).strip()
    if not text:
        return default
    return text if ":" in text else f"tenant:{text}"


def _lexical_rerank(query: str, texts: list[str]) -> np.ndarray:
    query_tokens = set(tokenize(query))
    scores = np.zeros(len(texts), dtype=np.float32)
    for index, text in enumerate(texts):
        doc_tokens = set(tokenize(text))
        scores[index] = len(query_tokens & doc_tokens) / (len(query_tokens | doc_tokens) or 1)
    return scores


def dev_models():
    from ..retrieval import _hashing_embed

    return (_hashing_embed, "hashing-embedder(dev)"), (_lexical_rerank, "lexical-reranker(dev)")


def _first(mapping: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def _none_or_str(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    return slug or "memory"


def _is_hidden(path: Path, *, root: Path | None = None) -> bool:
    parts = path.parts
    if root is not None:
        try:
            parts = path.relative_to(root).parts
        except ValueError:
            parts = path.parts
    return any(part.startswith(".") for part in parts)


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def bool_value(value: Any, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def list_value(value: Any, *, default: list[Any]) -> list[Any]:
    if value is None:
        return list(default)
    if isinstance(value, (list, tuple)):
        return list(value)
    if isinstance(value, str) and "," in value:
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, str) and value:
        return [value]
    return list(default)


def _attr_pair(value: Any) -> tuple[str, str]:
    if isinstance(value, (list, tuple)) and len(value) == 2:
        return str(value[0]), str(value[1])
    text = str(value)
    if "=" in text:
        key, val = text.split("=", 1)
        return key.strip(), val.strip()
    if ":" in text:
        key, val = text.split(":", 1)
        return key.strip(), val.strip()
    raise ValueError(f"attr must be key=value, got {value!r}")


def _secret_content(text: str) -> bool:
    """True only when the BODY contains real secret material (not a placeholder)."""
    lowered = text.lower()
    for pattern in _SECRET_CONTENT_PATTERNS:
        for match in re.finditer(pattern, text):
            window = lowered[max(0, match.start() - 24) : match.end() + 24]
            if any(hint in window for hint in _SECRET_PLACEHOLDER_HINTS):
                continue
            return True
    return False


def _secret_hint(spec: MarkdownMemorySpec) -> bool:
    return spec.classification == "restricted" and _secret_hint_text(spec.relative_path, {"pii": spec.pii})


def _secret_hint_text(relative_path: str, meta: dict[str, Any]) -> bool:
    haystack = " ".join(
        [
            relative_path.lower(),
            " ".join(str(value).lower() for value in meta.values() if isinstance(value, str)),
        ]
    )
    return any(hint in haystack for hint in SECRET_HINTS)
