"""Hybrid retrieval: dense + BM25 (RRF) + cross-encoder rerank.

This is the benchmark-validated design:
spreading activation was CUT across LoCoMo + LongMemEval; tuned hybrid wins.

Models are pluggable. Scaffold defaults are dependency-free; production model
selection is runtime-configured and reported by the recall readiness endpoint.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
from collections import defaultdict
from contextlib import nullcontext

import numpy as np

from .model_cache import MODEL_SPECS, ModelSpec, model_spec, resolve_model_source

_TOKEN = re.compile(r"[a-z0-9]+")
DEFAULT_ST_MAX_LENGTH = 512
DEFAULT_CROSS_ENCODER_MAX_LENGTH = 192
DEFAULT_ST_BATCH_SIZE = 32
DEFAULT_CROSS_ENCODER_BATCH_SIZE = 16
DEFAULT_CROSS_ENCODER_TEXT_MAX_CHARS = 4096
DEFAULT_CROSS_ENCODER_QUERY_MAX_CHARS = 2048


def _positive_int_env(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def _configure_torch_cpu_threads() -> None:
    """Bound long-lived daemon RSS and latency on CPU-backed MiniLM models."""
    if os.environ.get("HEARTWOOD_ALLOW_TOKENIZER_PARALLELISM", "").lower() not in {"1", "true", "yes"}:
        os.environ["TOKENIZERS_PARALLELISM"] = "false"
    else:
        os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
    try:
        import torch
    except Exception:
        return
    threads = _positive_int_env(
        "HEARTWOOD_TORCH_NUM_THREADS",
        max(1, min(4, os.cpu_count() or 1)),
    )
    torch.set_num_threads(threads)
    try:
        torch.set_num_interop_threads(
            _positive_int_env("HEARTWOOD_TORCH_INTEROP_THREADS", 1)
        )
    except RuntimeError:
        pass


def _torch_inference_context():
    try:
        import torch
    except Exception:
        return nullcontext()
    return torch.inference_mode()


def _load_st_model(
    model_id: str,
    *,
    revision: str | None = None,
    trust_remote_code: bool = False,
    max_length: int | None = DEFAULT_ST_MAX_LENGTH,
):
    _configure_torch_cpu_threads()
    from sentence_transformers import SentenceTransformer
    kwargs = {"device": "cpu"}
    if trust_remote_code:
        kwargs["trust_remote_code"] = True
    source = model_id
    if revision is not None:
        source = resolve_model_source(_spec_for_model(model_id, revision, trust_remote_code))
    model = SentenceTransformer(source, **kwargs)
    if max_length is not None and hasattr(model, "max_seq_length"):
        model.max_seq_length = max_length
    return model


def _load_cross_encoder(
    model_id: str,
    *,
    revision: str | None = None,
    trust_remote_code: bool = False,
    max_length: int = DEFAULT_CROSS_ENCODER_MAX_LENGTH,
):
    _configure_torch_cpu_threads()
    from sentence_transformers import CrossEncoder
    kwargs = {
        "device": "cpu",
        "max_length": _positive_int_env(
            "HEARTWOOD_RERANKER_MAX_LENGTH",
            max_length,
        ),
    }
    if trust_remote_code:
        kwargs["trust_remote_code"] = True
    source = model_id
    if revision is not None:
        source = resolve_model_source(_spec_for_model(model_id, revision, trust_remote_code))
    return CrossEncoder(source, **kwargs)


def _spec_for_model(model_id: str, revision: str, trust_remote_code: bool) -> ModelSpec:
    for spec in MODEL_SPECS.values():
        if spec.repo_id == model_id and spec.revision == revision:
            return spec
    return ModelSpec(
        key=model_id,
        repo_id=model_id,
        revision=revision,
        trust_remote_code=trust_remote_code,
    )


def tokenize(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


# --------------------------------------------------------------------------- #
# Pluggable models (graceful fallback to dependency-free implementations)
# --------------------------------------------------------------------------- #
def get_embedder():
    try:
        spec = model_spec("minilm-embedder")
        model = _load_st_model(spec.repo_id, revision=spec.revision)

        def embed(texts):
            with _torch_inference_context():
                v = model.encode(
                    list(texts),
                    convert_to_numpy=True,
                    show_progress_bar=False,
                    batch_size=_positive_int_env("HEARTWOOD_EMBEDDER_BATCH_SIZE", DEFAULT_ST_BATCH_SIZE),
                )
            return _l2norm(v.astype(np.float32))

        return embed, f"{spec.repo_id}@{spec.revision}"
    except Exception:
        return _hashing_embed, "hashing-embedder(dev)"


def _hashing_embed(texts, dim: int = 256):
    vecs = np.zeros((len(texts), dim), dtype=np.float32)
    for i, t in enumerate(texts):
        for tok in tokenize(t):
            h = int(hashlib.md5(tok.encode()).hexdigest(), 16)
            vecs[i, h % dim] += 1.0
    return _l2norm(vecs)


def _l2norm(v):
    if v.ndim == 1:
        n = np.linalg.norm(v) or 1.0
        return v / n
    n = np.linalg.norm(v, axis=1, keepdims=True)
    n[n == 0] = 1.0
    return v / n


def get_reranker():
    try:
        model_path = os.environ.get("HEARTWOOD_RERANKER_MODEL_PATH", "").strip()
        if model_path:
            ce = _load_cross_encoder(model_path)
            model_name = model_path
        else:
            spec = model_spec(
                os.environ.get(
                    "HEARTWOOD_RERANKER_MODEL_KEY",
                    "ms-marco-minilm-reranker",
                )
            )
            ce = _load_cross_encoder(spec.repo_id, revision=spec.revision)
            model_name = f"{spec.repo_id}@{spec.revision}"

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
                scores = np.asarray(
                    ce.predict(
                        pairs,
                        show_progress_bar=False,
                        batch_size=_positive_int_env(
                            "HEARTWOOD_RERANKER_BATCH_SIZE",
                            DEFAULT_CROSS_ENCODER_BATCH_SIZE,
                        ),
                    ),
                    dtype=np.float32,
                )
            return scores

        return rerank, model_name
    except Exception:
        def rerank(query, texts):
            q = set(tokenize(query))
            out = np.zeros(len(texts), dtype=np.float32)
            for i, t in enumerate(texts):
                d = set(tokenize(t))
                out[i] = len(q & d) / (len(q | d) or 1)
            return out

        return rerank, "lexical-overlap-reranker(dev)"


def _clip_for_cross_encoder(text, max_chars: int) -> str:
    """Bound native tokenizer allocation before model-side token truncation."""
    value = str(text or "")
    if max_chars <= 0 or len(value) <= max_chars:
        return value
    marker = "\n...\n"
    if max_chars <= len(marker):
        return value[:max_chars]
    remaining = max_chars - len(marker)
    head_chars = remaining // 2
    tail_chars = remaining - head_chars
    return f"{value[:head_chars]}{marker}{value[-tail_chars:]}"


# --------------------------------------------------------------------------- #
# BM25 (in-house) and RRF
# --------------------------------------------------------------------------- #
def bm25_scores(query_tokens, corpus_tokens, k1=1.5, b=0.75):
    N = len(corpus_tokens)
    if N == 0:
        return np.zeros(0, dtype=np.float32)
    return bm25_scores_prepared(query_tokens, prepare_bm25_corpus(corpus_tokens), k1=k1, b=b)


def prepare_bm25_corpus(corpus_tokens):
    N = len(corpus_tokens)
    if N == 0:
        return {
            "N": 0,
            "doclen": np.zeros(0, dtype=np.float32),
            "avgdl": 1.0,
            "df": {},
            "tfs": [],
        }
    doclen = np.array([len(d) for d in corpus_tokens], dtype=np.float32)
    avgdl = float(doclen.mean()) or 1.0
    df = defaultdict(int)
    tfs = []
    for toks in corpus_tokens:
        c = defaultdict(int)
        for w in toks:
            c[w] += 1
        tfs.append(c)
        for w in c:
            df[w] += 1
    return {"N": N, "doclen": doclen, "avgdl": avgdl, "df": df, "tfs": tfs}


def bm25_scores_prepared(query_tokens, corpus, k1=1.5, b=0.75):
    N = corpus["N"]
    if N == 0:
        return np.zeros(0, dtype=np.float32)
    doclen = corpus["doclen"]
    avgdl = corpus["avgdl"]
    df = corpus["df"]
    tfs = corpus["tfs"]
    s = np.zeros(N, dtype=np.float32)
    for w in set(query_tokens):
        n = df.get(w)
        if not n:
            continue
        idf = math.log(1 + (N - n + 0.5) / (n + 0.5))
        for i, c in enumerate(tfs):
            f = c.get(w, 0)
            if f:
                s[i] += idf * (f * (k1 + 1)) / (f + k1 * (1 - b + b * doclen[i] / avgdl))
    return s


def rrf(rank_lists, k=60):
    scores = defaultdict(float)
    for rl in rank_lists:
        for rank, idx in enumerate(rl):
            scores[idx] += 1.0 / (k + rank + 1)
    return scores


# --------------------------------------------------------------------------- #
# Fuse precomputed dense (from the VectorIndex) + lexical (BM25), then rerank.
# Dense scoring is done by the pluggable VectorIndex (numpy / sqlite-vec), so this
# stays index-agnostic. Candidates are already policy-filtered by the caller.
# --------------------------------------------------------------------------- #
def fuse_rerank(
    reranker,
    query,
    candidates,
    dense_map,
    lexical_map,
    k=8,
    topc=50,
    collapse_keys: dict[str, str] | None = None,
    precedence: dict[str, int] | None = None,
):
    """candidates: list of {id, text}. dense_map/lexical_map: id -> score.
    Returns ranked (id, ce_score, signals) for explain_recall."""
    if not candidates:
        return []
    ids = [c["id"] for c in candidates]
    text = {c["id"]: c["text"] for c in candidates}
    dense_order = sorted(ids, key=lambda i: -dense_map.get(i, float("-inf")))
    lex_order = sorted(ids, key=lambda i: -lexical_map.get(i, 0.0))
    fused = rrf([dense_order[:topc], lex_order[:topc]])
    cand = sorted(fused, key=lambda i: -fused[i])[:topc]

    ce = reranker(query, [text[i] for i in cand])
    if collapse_keys is None:
        order = list(np.argsort(-ce))
    else:
        order = sorted(
            range(len(cand)),
            key=lambda oi: (
                -float(ce[oi]),
                (precedence or {}).get(cand[oi], 2),
                str(cand[oi]),
            ),
        )
    ranked = []
    seen_collapse_keys = {}
    for oi in order:
        i = cand[oi]
        collapse_key = collapse_keys.get(i) if collapse_keys is not None else None
        if collapse_key is not None and collapse_key in seen_collapse_keys:
            kept_id, kept_signals = seen_collapse_keys[collapse_key]
            collapse_signal = kept_signals.setdefault("duplicate_collapse", {
                "reason": "mirror-family-source-key",
                "collapse_key": collapse_key,
                "kept_id": kept_id,
                "collapsed_ids": [],
            })
            collapse_signal["collapsed_ids"].append(i)
            continue
        signals = {
            "dense_sim": round(float(dense_map.get(i, 0.0)), 4),
            "bm25": round(float(lexical_map.get(i, 0.0)), 4),
            "rrf": round(float(fused[i]), 4),
            "rerank_score": round(float(ce[oi]), 4),
            "final_rank": len(ranked),
        }
        if collapse_key is not None:
            seen_collapse_keys[collapse_key] = (i, signals)
        ranked.append((i, float(ce[oi]), signals))
        if len(ranked) == k:
            break
    return ranked
