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


def resolve_source_span_text(span: dict[str, Any], client=None) -> str | None:
    """Resolve inline or self-referenced span text without persisting plaintext."""
    text = span.get("text")
    if isinstance(text, str):
        return text
    if span.get("text_ref") != "self" or client is None:
        return None
    memory_id = span.get("memory_id")
    if not memory_id:
        return None
    meta = client.store.get_meta(str(memory_id))
    if not meta or span.get("content_hash") != meta.get("content_hash"):
        return None
    return client._read_content_unchecked(str(memory_id))
