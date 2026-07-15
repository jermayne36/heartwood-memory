#!/usr/bin/env python3
"""Fail-safe Heartwood warm-recall client example.

This is intentionally dependency-free. It treats Heartwood recall as progressive
enhancement: if the service is disabled, down, slow, unauthorized, or returns an
unexpected JSON shape, the caller gets deterministic keyword results from local
Markdown instead of an exception.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "for",
    "from",
    "how",
    "in",
    "is",
    "it",
    "of",
    "on",
    "or",
    "that",
    "the",
    "this",
    "to",
    "what",
    "with",
}


def tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    seen: set[str] = set()
    for token in re.findall(r"[a-z0-9]+", text.lower()):
        if len(token) < 2 or token in STOPWORDS or token in seen:
            continue
        seen.add(token)
        tokens.append(token)
    return tokens


def read_token(token_file: str | None) -> str:
    path = token_file or os.environ.get("HEARTWOOD_RECALL_TOKEN_FILE")
    if path:
        try:
            token = Path(path).read_text(encoding="utf-8").strip()
            if token:
                return token
        except OSError:
            return ""
    return os.environ.get("HEARTWOOD_RECALL_TOKEN", "").strip()


def source_from_result(result: dict[str, Any]) -> str:
    provenance = result.get("provenance")
    provenance = provenance if isinstance(provenance, dict) else {}
    source = provenance.get("source")
    source = source if isinstance(source, dict) else {}
    candidates = [
        source.get("path"),
        source.get("uri"),
        *((result.get("source_ids") or []) if isinstance(result.get("source_ids"), list) else []),
    ]
    for candidate in candidates:
        if candidate:
            return str(candidate)
    return str(result.get("id") or "")


def safe_recall(
    *,
    url: str,
    token: str,
    tenant: str,
    principal_id: str,
    query: str,
    k: int,
    timeout: float,
) -> list[dict[str, Any]]:
    if not url:
        return []
    endpoint = url.rstrip("/") + "/recall"
    payload = json.dumps(
        {
            "tenant": tenant,
            "principal_id": principal_id,
            "query": query,
            "k": k,
        }
    ).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(endpoint, data=payload, method="POST", headers=headers)

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8") or "{}")
    except (
        OSError,
        TimeoutError,
        urllib.error.URLError,
        urllib.error.HTTPError,
        json.JSONDecodeError,
    ):
        return []

    if not isinstance(data, dict) or not data.get("ok", False):
        return []
    results = data.get("results", [])
    if not isinstance(results, list):
        return []

    ranked: list[dict[str, Any]] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        try:
            score = round(float(result.get("score", 0)), 4)
        except (TypeError, ValueError):
            score = 0
        source = source_from_result(result)
        content = str(result.get("content") or "")[:500]
        if not source and not content:
            continue
        ranked.append(
            {
                "source": source,
                "score": score,
                "content": content,
            }
        )
        if len(ranked) >= k:
            break
    return ranked


def keyword_fallback(query: str, roots: list[Path], *, k: int) -> list[dict[str, Any]]:
    keywords = tokenize(query)
    if not keywords:
        return []

    ranked: list[tuple[int, Path, str]] = []
    for root in roots:
        if root.is_file() and root.suffix.lower() == ".md":
            files = [root]
        elif root.is_dir():
            files = sorted(root.rglob("*.md"))
        else:
            continue
        for path in files:
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            lowered = text.lower()
            score = sum(min(lowered.count(keyword), 10) for keyword in keywords)
            if score <= 0:
                continue
            snippet = " ".join(text.split())[:500]
            ranked.append((score, path, snippet))

    ranked.sort(key=lambda item: (-item[0], str(item[1]).lower()))
    return [
        {"source": str(path), "score": score, "content": snippet}
        for score, path, snippet in ranked[:k]
    ]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fail-safe Heartwood recall client.")
    parser.add_argument("--query", required=True)
    parser.add_argument("--memory-root", action="append", type=Path, default=[])
    parser.add_argument("--url", default=os.environ.get("HEARTWOOD_RECALL_URL", "http://127.0.0.1:8765"))
    parser.add_argument("--tenant", default=os.environ.get("HEARTWOOD_TENANT", "tenant:ops"))
    parser.add_argument("--principal-id", default="agent:app")
    parser.add_argument("--token-file")
    parser.add_argument("--k", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=1.5)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    token = read_token(args.token_file)
    heartwood_results = safe_recall(
        url=args.url,
        token=token,
        tenant=args.tenant,
        principal_id=args.principal_id,
        query=args.query,
        k=max(1, args.k),
        timeout=max(0.1, args.timeout),
    )
    if heartwood_results:
        json.dump({"source": "heartwood", "results": heartwood_results}, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    fallback_results = keyword_fallback(args.query, args.memory_root, k=max(1, args.k))
    json.dump({"source": "keyword_fallback", "results": fallback_results}, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
