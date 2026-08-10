"""Helpers for storing and resolving governed source spans."""
from __future__ import annotations

import hashlib
from typing import Any


def normalize_self_spans(
    source_spans: tuple | list,
    *,
    content_hash: str,
) -> tuple[dict[str, Any], ...]:
    """Replace byte-identical source text with a reference to row content."""
    normalized = []
    for source_span in source_spans:
        span = dict(source_span)
        text = span.get("text")
        text_hash = None
        if isinstance(text, str):
            text_hash = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
        if span.get("text_ref") == "self":
            if span.get("content_hash") != content_hash:
                raise ValueError("self-referenced span hash differs from row content hash")
            span.pop("text", None)
        elif text_hash == content_hash and span.get("content_hash") == content_hash:
            span.pop("text", None)
            span["text_ref"] = "self"
        normalized.append(span)
    return tuple(normalized)


def split_source_span_texts(
    source_spans: tuple | list,
) -> tuple[tuple[dict[str, Any], ...], tuple[str, ...]]:
    """Move non-self span text into an ordered payload for encryption."""
    stored_spans = []
    encrypted_texts = []
    for source_span in source_spans:
        span = dict(source_span)
        text = span.pop("text", None)
        if span.get("text_ref") == "self":
            stored_spans.append(span)
            continue
        if span.get("text_ref") == "encrypted":
            raise ValueError("encrypted source span must be rehydrated before persistence")
        if text is not None:
            if not isinstance(text, str):
                raise TypeError("source span text must be a string")
            span.setdefault(
                "content_hash",
                "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest(),
            )
            span["text_ref"] = "encrypted"
            span["text_index"] = len(encrypted_texts)
            encrypted_texts.append(text)
        stored_spans.append(span)
    return tuple(stored_spans), tuple(encrypted_texts)


def resolve_source_span_text(span: dict[str, Any], client=None) -> str | None:
    """Resolve inline, self-referenced, or encrypted span text."""
    text = span.get("text")
    if isinstance(text, str):
        return text
    if client is None:
        return None
    memory_id = span.get("memory_id")
    if not memory_id:
        return None
    if span.get("text_ref") == "self":
        meta = client.store.get_meta(str(memory_id))
        if not meta or span.get("content_hash") != meta.get("content_hash"):
            return None
        return client._read_content_unchecked(str(memory_id))
    if span.get("text_ref") == "encrypted":
        return client._read_source_span_text_unchecked(
            str(memory_id),
            text_index=span.get("text_index"),
            content_hash=span.get("content_hash"),
        )
    return None
