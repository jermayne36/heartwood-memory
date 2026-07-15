"""Deterministic, structure-aware document chunking."""
from __future__ import annotations

import re
from dataclasses import dataclass


TOKEN_RE = re.compile(r"[A-Za-z0-9]+")


@dataclass(frozen=True)
class Chunk:
    ordinal: int
    text: str
    char_start: int
    char_end: int
    token_estimate: int


@dataclass(frozen=True)
class _Span:
    char_start: int
    char_end: int
    token_estimate: int


def chunk_document(text: str, *, target_tokens: int, overlap: int) -> list[Chunk]:
    """Split text into deterministic chunks while preserving original offsets."""
    if target_tokens <= 0:
        raise ValueError("target_tokens must be positive")
    if overlap < 0:
        raise ValueError("overlap must be non-negative")
    if overlap >= target_tokens:
        raise ValueError("overlap must be smaller than target_tokens")
    if not text.strip():
        return []

    spans = _size_bound_spans(text, _structural_spans(text), target_tokens)
    packed = _pack_spans(spans, target_tokens)
    expanded = _apply_overlap(text, packed, overlap)
    return [
        Chunk(
            ordinal=index,
            text=text[span.char_start:span.char_end],
            char_start=span.char_start,
            char_end=span.char_end,
            token_estimate=_token_count(text[span.char_start:span.char_end]),
        )
        for index, span in enumerate(expanded)
        if span.char_start < span.char_end
    ]


def _structural_spans(text: str) -> list[_Span]:
    """Return markdown-heading and paragraph spans over the original text."""
    spans: list[_Span] = []
    block_start: int | None = None
    block_end: int | None = None
    offset = 0

    for line in text.splitlines(keepends=True):
        line_start = offset
        line_end = offset + len(line)
        offset = line_end
        stripped = line.strip()

        if not stripped:
            if block_start is not None and block_end is not None:
                _append_span(spans, text, block_start, block_end)
                block_start = None
                block_end = None
            continue

        is_heading = stripped.startswith("#")
        if is_heading and block_start is not None and block_end is not None:
            _append_span(spans, text, block_start, block_end)
            block_start = None
            block_end = None

        if block_start is None:
            block_start = line_start
        block_end = line_end

    if block_start is not None and block_end is not None:
        _append_span(spans, text, block_start, block_end)
    return spans


def _append_span(spans: list[_Span], text: str, start: int, end: int) -> None:
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    if start < end:
        spans.append(_Span(start, end, _token_count(text[start:end])))


def _size_bound_spans(text: str, spans: list[_Span], target_tokens: int) -> list[_Span]:
    out: list[_Span] = []
    for span in spans:
        if span.token_estimate <= target_tokens:
            out.append(span)
            continue
        matches = list(TOKEN_RE.finditer(text, span.char_start, span.char_end))
        if not matches:
            out.append(span)
            continue
        for start_index in range(0, len(matches), target_tokens):
            window = matches[start_index:start_index + target_tokens]
            if not window:
                continue
            out.append(
                _Span(
                    window[0].start(),
                    window[-1].end(),
                    len(window),
                )
            )
    return out


def _pack_spans(spans: list[_Span], target_tokens: int) -> list[_Span]:
    packed: list[_Span] = []
    current_start: int | None = None
    current_end: int | None = None
    current_tokens = 0

    for span in spans:
        would_exceed = current_start is not None and current_tokens + span.token_estimate > target_tokens
        if would_exceed:
            packed.append(_Span(current_start, current_end or current_start, current_tokens))
            current_start = None
            current_end = None
            current_tokens = 0

        if current_start is None:
            current_start = span.char_start
        current_end = span.char_end
        current_tokens += span.token_estimate

    if current_start is not None:
        packed.append(_Span(current_start, current_end or current_start, current_tokens))
    return packed


def _apply_overlap(text: str, spans: list[_Span], overlap: int) -> list[_Span]:
    if overlap == 0 or len(spans) < 2:
        return spans

    tokens = list(TOKEN_RE.finditer(text))
    expanded: list[_Span] = []
    for index, span in enumerate(spans):
        start = span.char_start
        if index:
            token_index = next(
                (i for i, token in enumerate(tokens) if token.start() >= span.char_start),
                len(tokens),
            )
            if token_index > 0:
                start = tokens[max(0, token_index - overlap)].start()
        expanded.append(_Span(start, span.char_end, _token_count(text[start:span.char_end])))
    return expanded


def _token_count(text: str) -> int:
    return len(TOKEN_RE.findall(text))
