"""Deterministic offline models shared by the demo writer and MCP reader."""

from __future__ import annotations

import numpy as np


EMBEDDER_NAME = "rotation-demo-deterministic-embedder"
RERANKER_NAME = "rotation-demo-deterministic-reranker"


def embed(texts: list[str]) -> np.ndarray:
    """Embed the tiny synthetic corpus without downloads or network calls."""
    vocab = (
        "project",
        "juniper",
        "deploy",
        "release",
        "security",
        "approval",
        "block",
        "us-west",
        "control",
    )
    vectors = np.zeros((len(texts), len(vocab) + 1), dtype=np.float32)
    for row, text in enumerate(texts):
        lowered = text.lower()
        vectors[row, 0] = 1.0
        for column, token in enumerate(vocab, start=1):
            vectors[row, column] = float(token in lowered)
    return vectors


def rerank(query: str, texts: list[str]) -> np.ndarray:
    query_tokens = set(query.lower().split())
    return np.asarray(
        [len(query_tokens & set(text.lower().split())) for text in texts],
        dtype=np.float32,
    )
