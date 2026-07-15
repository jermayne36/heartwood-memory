"""Named production model loaders (embedders + rerankers).

The engine takes any (callable, name) pair, so these are convenience wrappers
around the 2026 SOTA open models. Each returns
(fn, name) ready to pass to Heartwood(embedder=..., reranker=...).

    from heartwood import Heartwood
    from heartwood.models import embedder, reranker
    db = Heartwood(embedder=embedder("embeddinggemma"), reranker=reranker("bge-v2"),
               index="sqlite-vec")

Requires `sentence-transformers`. If it's missing, importing/using a loader
raises a clear error; the engine's built-in fallbacks still work without it.
"""
from __future__ import annotations

import numpy as np

from .model_cache import model_spec
from .retrieval import (
    DEFAULT_CROSS_ENCODER_MAX_LENGTH,
    DEFAULT_CROSS_ENCODER_BATCH_SIZE,
    DEFAULT_CROSS_ENCODER_QUERY_MAX_CHARS,
    DEFAULT_CROSS_ENCODER_TEXT_MAX_CHARS,
    DEFAULT_ST_MAX_LENGTH,
    _clip_for_cross_encoder,
    _load_cross_encoder,
    _load_st_model,
    _positive_int_env,
    _torch_inference_context,
)

EMBEDDERS = {
    "embeddinggemma": "embeddinggemma",  # on-device / private mode
    "bge-m3": "bge-m3",                  # dense+sparse+multivector
    "qwen3": "qwen3",                    # top MTEB (small variant)
    "minilm": "minilm-embedder",
}
RERANKERS = {
    "bge-v2": "bge-v2",
    "mxbai": "mxbai",
    "jina": "jina",
    "minilm": "ms-marco-minilm-reranker",
}


def embedder(name="embeddinggemma"):
    key = EMBEDDERS.get(name, name)
    spec = model_spec(key)
    model = _load_st_model(
        spec.repo_id,
        revision=spec.revision,
        trust_remote_code=spec.trust_remote_code,
        max_length=DEFAULT_ST_MAX_LENGTH,
    )

    def embed(texts):
        v = model.encode(list(texts), convert_to_numpy=True, show_progress_bar=False,
                         normalize_embeddings=True)
        return v.astype(np.float32)

    return embed, f"{spec.repo_id}@{spec.revision}"


def reranker(name="bge-v2"):
    key = RERANKERS.get(name, name)
    spec = model_spec(key)
    ce = _load_cross_encoder(
        spec.repo_id,
        revision=spec.revision,
        trust_remote_code=spec.trust_remote_code,
        max_length=DEFAULT_CROSS_ENCODER_MAX_LENGTH,
    )

    def rerank(query, texts):
        if not texts:
            return np.zeros(0, dtype=np.float32)
        clipped_query = _clip_for_cross_encoder(
            query,
            _positive_int_env(
                "HEARTWOOD_RERANKER_QUERY_MAX_CHARS",
                DEFAULT_CROSS_ENCODER_QUERY_MAX_CHARS,
            ),
        )
        text_max_chars = _positive_int_env(
            "HEARTWOOD_RERANKER_TEXT_MAX_CHARS",
            DEFAULT_CROSS_ENCODER_TEXT_MAX_CHARS,
        )
        pairs = [
            (clipped_query, _clip_for_cross_encoder(t, text_max_chars))
            for t in texts
        ]
        with _torch_inference_context():
            scores = ce.predict(
                pairs,
                show_progress_bar=False,
                batch_size=_positive_int_env(
                    "HEARTWOOD_RERANKER_BATCH_SIZE",
                    DEFAULT_CROSS_ENCODER_BATCH_SIZE,
                ),
            )
        return np.asarray(
            scores,
            dtype=np.float32,
        )

    return rerank, f"{spec.repo_id}@{spec.revision}"
