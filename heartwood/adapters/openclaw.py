"""OpenClaw-style memory_search / memory_get example adapter.

This module does not claim a verified dependency on a specific OpenClaw package.
It presents a representative Markdown-memory tool shape while storing content in
Heartwood with policy, provenance, and erasure.
"""
from __future__ import annotations

import posixpath
from typing import Any

from ..client import Heartwood
from ..envelope import Policy
from ..policy import Principal


def _normalize_path(path: str) -> str:
    if not isinstance(path, str) or not path.strip():
        raise ValueError("path required")
    raw = path.replace("\\", "/").strip()
    if "%2e" in raw.lower() or ".." in raw.split("/"):
        raise ValueError(f"illegal path {path}")
    if raw.startswith("/memories/"):
        norm = posixpath.normpath(raw)
    else:
        norm = posixpath.normpath("/memories/" + raw.lstrip("/"))
    if norm != "/memories" and not norm.startswith("/memories/"):
        raise ValueError(f"path {path} is outside /memories")
    return norm


class HeartwoodOpenClawMemoryRuntime:
    """Minimal OpenClaw-style memory runtime compatible by tool shape."""

    def __init__(self, db: Heartwood, *, created_by: str = "agent:openclaw"):
        self.db = db
        self.created_by = created_by
        self.index: dict[str, str] = {}
        self._rebuild_index()

    def remember_markdown(
        self,
        path: str,
        text: str,
        *,
        subject: str = "openclaw-memory",
        classification: str = "internal",
        roles: tuple[str, ...] = (),
    ) -> str:
        norm = _normalize_path(path)
        mem_id = self.db.remember(
            text,
            subject=subject,
            created_by=self.created_by,
            kind="working",
            epistemic="imported-source",
            source={"kind": "openclaw-memory", "uri": norm},
            policy=Policy(classification=classification, roles=roles),
            model_version="openclaw-memory-runtime",
        )
        self.index[norm] = mem_id
        return mem_id

    def memory_search(
        self,
        query: str,
        *,
        principal_id: str = "agent:openclaw",
        roles: tuple[str, ...] = ("support",),
        clearance: str = "internal",
        max_results: int = 6,
    ) -> dict[str, Any]:
        principal = Principal(
            id=principal_id,
            tenant=self.db.tenant,
            roles=roles,
            clearance=clearance,
        )
        out = self.db.recall(query, principal=principal, k=max_results, topc=50)
        results = []
        for result in out["results"]:
            provenance = result["provenance"]
            source = provenance.get("source", {})
            path = source.get("uri", f"heartwood://{result['id']}")
            text = result["content"]
            line_count = max(1, len(text.splitlines()))
            results.append(
                {
                    "text": text[:700],
                    "path": path,
                    "line_start": 1,
                    "line_end": line_count,
                    "score": result["score"],
                    "provider": self.db.embedder_name,
                    "model": self.db.reranker_name,
                    "provenance_valid": provenance.get("signature_valid"),
                }
            )
        return {"results": results, "recall_id": out["recall_id"], "index_lag": out["index_lag"]}

    def memory_get(
        self,
        path: str,
        *,
        line_start: int | None = None,
        line_end: int | None = None,
    ) -> dict[str, Any]:
        try:
            norm = _normalize_path(path)
        except ValueError as exc:
            return {"text": "", "path": path, "error": str(exc)}
        mem_id = self.index.get(norm)
        if not mem_id:
            return {"text": "", "path": path}
        text = self.db.read_content(mem_id) or ""
        if line_start is not None or line_end is not None:
            start = max(1, int(line_start or 1))
            end = max(start, int(line_end or len(text.splitlines()) or 1))
            lines = text.splitlines()
            text = "\n".join(lines[start - 1:end])
        return {"text": text, "path": path}

    def delete_path(self, path: str) -> dict[str, Any]:
        norm = _normalize_path(path)
        targets = [p for p in self.index if p == norm or p.startswith(norm.rstrip("/") + "/")]
        for target in targets:
            self.db.purge(self.index.pop(target), actor=self.created_by)
        return {"path": path, "deleted": len(targets)}

    def _rebuild_index(self) -> None:
        latest: dict[str, float] = {}
        for row in self.db.store.candidates(self.db.tenant):
            source = row.get("source") or {}
            if source.get("kind") != "openclaw-memory":
                continue
            uri = source.get("uri")
            if uri and row["created_at"] >= latest.get(uri, -1):
                latest[uri] = row["created_at"]
                self.index[uri] = row["id"]
