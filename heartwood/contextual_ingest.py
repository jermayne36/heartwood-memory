"""Contextual-retrieval ingestion orchestration."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .chunking import Chunk, chunk_document
from .egress import generation_allowed
from .envelope import Epistemic, Kind, Policy, TruthStatus, hash_content
from .review import ReviewState


CONTEXTUAL_AUX_POLICY_SCOPE = "contextual-aux"


@dataclass(frozen=True)
class ContextualDocument:
    content: str
    subject: str
    created_by: str
    kind: str = Kind.SOURCE.value
    epistemic: str = Epistemic.IMPORTED_SOURCE.value
    confidence: float = 0.9
    salience: float = 0.6
    source: dict[str, Any] = field(default_factory=dict)
    policy: Policy = field(default_factory=Policy)
    memory_id: str | None = None
    policy_scope: str = "default"
    valid_from: str | None = None
    valid_until: str | None = None
    entities: tuple[str, ...] = ()
    source_ids: tuple[str, ...] = ()
    subject_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class ContextualChunkRecord:
    chunk_id: str
    context_id: str
    chunk: Chunk
    context_text: str
    index_text: str
    egress: dict[str, Any]
    faithfulness: dict[str, Any] | None


@dataclass(frozen=True)
class IngestResult:
    mode: str
    ids: tuple[str, ...]
    chunk_ids: tuple[str, ...] = ()
    context_ids: tuple[str, ...] = ()
    records: tuple[ContextualChunkRecord, ...] = ()
    fallback_reason: str | None = None


Generator = Callable[..., str | dict[str, Any]]
EgressRequestBuilder = Callable[..., dict[str, Any]]


def ingest_contextual(
    client,
    document: ContextualDocument,
    *,
    generator: Generator,
    egress_request_builder: EgressRequestBuilder,
    principal,
    faithfulness: bool = True,
    target_tokens: int = 180,
    overlap: int = 30,
    window_chars: int = 1600,
    support_threshold: float = 0.35,
    review_threshold: float = 0.18,
) -> IngestResult:
    """Chunk a document, generate faithful context, and index context + chunk text."""
    chunks = chunk_document(document.content, target_tokens=target_tokens, overlap=overlap)
    if not chunks:
        return IngestResult(mode="empty", ids=())

    prepared: list[dict[str, Any]] = []
    for chunk in chunks:
        source_spans = _source_spans(document, chunk, window_chars=window_chars)
        egress_request = egress_request_builder(
            document=document,
            chunk=chunk,
            source_spans=source_spans,
            principal=principal,
        )
        egress = client.evaluate_egress(egress_request)
        if not generation_allowed(egress):
            return _fallback_whole_file(client, document, f"egress:{egress['decision']}")

        generated = generator(
            document=document,
            chunk=chunk,
            source_spans=source_spans,
            principal=principal,
            egress=egress,
        )
        context_text, model_version = _context_text(generated)
        if not context_text.strip():
            return _fallback_whole_file(client, document, "empty_context")

        assessment = None
        if faithfulness:
            assessment = _assess_context(
                client,
                document,
                chunk,
                context_text,
                source_spans,
                support_threshold=support_threshold,
                review_threshold=review_threshold,
            )
            if assessment["decision"] != "accepted":
                return _fallback_whole_file(client, document, f"faithfulness:{assessment['decision']}")

        prepared.append(
            {
                "chunk": chunk,
                "context_text": context_text,
                "model_version": model_version,
                "source_spans": source_spans,
                "egress": egress,
                "faithfulness": assessment,
            }
        )

    records: list[ContextualChunkRecord] = []
    for item in prepared:
        chunk = item["chunk"]
        chunk_id = _chunk_id(document, chunk)
        context_text = item["context_text"]
        index_text = f"{context_text}\n\n{chunk.text}"
        chunk_span = item["source_spans"][0]
        chunk_id = client.remember(
            chunk.text,
            subject=document.subject,
            subject_ids=document.subject_ids or (document.subject,),
            created_by=document.created_by,
            kind=document.kind,
            epistemic=document.epistemic,
            confidence=document.confidence,
            salience=document.salience,
            source=_source(document, chunk),
            policy=document.policy,
            memory_id=chunk_id,
            policy_scope=document.policy_scope,
            valid_from=document.valid_from,
            valid_until=document.valid_until,
            entities=document.entities,
            source_ids=_source_ids(document),
            source_spans=(chunk_span,),
            index_text=index_text,
        )
        context_id = client.remember(
            context_text,
            subject=document.subject,
            subject_ids=document.subject_ids or (document.subject,),
            created_by=_principal_id(principal),
            kind=Kind.GENERATED.value,
            epistemic=Epistemic.MODEL_GENERATED.value,
            confidence=min(document.confidence, 0.75),
            salience=min(document.salience, 0.35),
            source={
                "kind": "contextual-ingest",
                "uri": f"heartwood://context/{chunk_id}",
                "source_uri": _source_uri(document),
            },
            policy=document.policy,
            memory_id=f"{chunk_id}:context",
            truth_status=TruthStatus.GENERATED_SUPPORTED.value,
            policy_scope=CONTEXTUAL_AUX_POLICY_SCOPE,
            valid_from=document.valid_from,
            valid_until=document.valid_until,
            entities=document.entities,
            source_ids=_source_ids(document),
            source_spans=tuple(item["source_spans"]),
            model_version=item["model_version"],
            review_state=ReviewState.PROPOSED.value,
        )
        client.add_provenance_edge(context_id, chunk_id, kind="contextualizes")
        records.append(
            ContextualChunkRecord(
                chunk_id=chunk_id,
                context_id=context_id,
                chunk=chunk,
                context_text=context_text,
                index_text=index_text,
                egress=item["egress"],
                faithfulness=item["faithfulness"],
            )
        )

    return IngestResult(
        mode="contextual",
        ids=tuple(record.chunk_id for record in records),
        chunk_ids=tuple(record.chunk_id for record in records),
        context_ids=tuple(record.context_id for record in records),
        records=tuple(records),
    )


def default_egress_request_builder(*, document: ContextualDocument, chunk: Chunk,
                                   source_spans: list[dict[str, Any]], principal) -> dict[str, Any]:
    return {
        "request_id": f"contextual:{_source_uri(document)}:{chunk.ordinal}",
        "actor": _principal_id(principal),
        "model": {
            "provider": "anthropic",
            "runtime": "external",
            "region": "us",
            "retention": "zero",
            "training_opt_out": True,
        },
        "policy": {
            "allow_external_models": True,
            "allowed_providers": ["anthropic"],
            "allowed_regions": ["us"],
            "require_zero_retention": True,
            "deny_classifications": [],
            "deny_pii_labels": [],
            "human_review_classifications": [],
        },
        "source_spans": source_spans,
    }


def _fallback_whole_file(client, document: ContextualDocument, reason: str) -> IngestResult:
    source_span = {
        "source_id": _source_uri(document),
        "span_id": f"{_source_uri(document)}#body",
        "text": document.content,
        "content_hash": hash_content(document.content),
        "classification": document.policy.classification,
        "pii_labels": ["pii"] if document.policy.pii else [],
    }
    mem_id = client.remember(
        document.content,
        subject=document.subject,
        subject_ids=document.subject_ids or (document.subject,),
        created_by=document.created_by,
        kind=document.kind,
        epistemic=document.epistemic,
        confidence=document.confidence,
        salience=document.salience,
        source={**document.source, "uri": _source_uri(document)},
        policy=document.policy,
        memory_id=document.memory_id,
        policy_scope=document.policy_scope,
        valid_from=document.valid_from,
        valid_until=document.valid_until,
        entities=document.entities,
        source_ids=_source_ids(document),
        source_spans=(source_span,),
    )
    return IngestResult(mode="fallback", ids=(mem_id,), fallback_reason=reason)


def _source_spans(document: ContextualDocument, chunk: Chunk, *, window_chars: int) -> list[dict[str, Any]]:
    source_uri = _source_uri(document)
    window_start = max(0, chunk.char_start - window_chars // 2)
    window_end = min(len(document.content), chunk.char_end + window_chars // 2)
    return [
        {
            "source_id": source_uri,
            "span_id": f"{source_uri}#chunk-{chunk.ordinal:04d}",
            "text": chunk.text,
            "content_hash": hash_content(chunk.text),
            "classification": document.policy.classification,
            "pii_labels": ["pii"] if document.policy.pii else [],
            "char_start": chunk.char_start,
            "char_end": chunk.char_end,
        },
        {
            "source_id": source_uri,
            "span_id": f"{source_uri}#window-{chunk.ordinal:04d}",
            "text": document.content[window_start:window_end],
            "classification": document.policy.classification,
            "pii_labels": ["pii"] if document.policy.pii else [],
            "char_start": window_start,
            "char_end": window_end,
        },
    ]


def _assess_context(client, document: ContextualDocument, chunk: Chunk, context_text: str,
                    source_spans: list[dict[str, Any]], *,
                    support_threshold: float, review_threshold: float) -> dict[str, Any]:
    candidate = {
        "candidate_id": f"contextual:{_source_uri(document)}:{chunk.ordinal}",
        "actor": document.created_by,
        "source_spans": source_spans,
        "claims": [
            {
                "claim_id": f"context-{chunk.ordinal:04d}",
                "text": context_text,
                "source_span_ids": [span["span_id"] for span in source_spans],
                "material": True,
            }
        ],
    }
    return client.assess_faithfulness(
        candidate,
        support_threshold=support_threshold,
        review_threshold=review_threshold,
    )


def _source(document: ContextualDocument, chunk: Chunk) -> dict[str, Any]:
    source = dict(document.source)
    source.setdefault("kind", "contextual-chunk")
    source.setdefault("uri", _source_uri(document))
    source["chunk_ordinal"] = chunk.ordinal
    source["char_start"] = chunk.char_start
    source["char_end"] = chunk.char_end
    return source


def _source_uri(document: ContextualDocument) -> str:
    if document.source.get("uri"):
        return str(document.source["uri"])
    if document.source_ids:
        return str(document.source_ids[0])
    if document.memory_id:
        return f"heartwood://document/{document.memory_id}"
    return f"heartwood://subject/{document.subject}"


def _source_ids(document: ContextualDocument) -> tuple[str, ...]:
    return tuple(document.source_ids) or (_source_uri(document),)


def _chunk_id(document: ContextualDocument, chunk: Chunk) -> str | None:
    if document.memory_id is None:
        return None
    return f"{document.memory_id}:chunk:{chunk.ordinal:04d}"


def _context_text(generated: str | dict[str, Any]) -> tuple[str, str | None]:
    if isinstance(generated, dict):
        text = generated.get("context") or generated.get("text") or generated.get("content") or ""
        model_version = generated.get("model_version")
        return str(text), str(model_version) if model_version else None
    return str(generated), None


def _principal_id(principal) -> str:
    return str(getattr(principal, "id", principal))
