"""Import provenance/graph edges into a Heartwood store.

The markdown memory importer projects source files into `memories`. This module
adds the graph face: directed relationships between those existing memories.
It is deliberately additive and idempotent; unresolved links are reported but
never create synthetic memory rows.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from .markdown import load_markdown_documents
from ..store import Store

_WIKILINK_RE = re.compile(r"(?<!!)\[\[([^\]\n]+)\]\]")


def import_edges(
    *,
    db_path: str | Path,
    sources: Iterable[str | Path] = (),
    proposal_jsonl: str | Path | None = None,
    tenant: str = "tenant:ops",
    wikilink_kind: str = "links_to",
    stop_on_error: bool = False,
) -> dict[str, Any]:
    """Import directed edges from proposal JSONL and/or markdown wikilinks."""
    store = Store(str(db_path))
    try:
        edge_count_before = _edge_count(store)
        index = _memory_index(store, tenant)
        report: dict[str, Any] = {
            "ok": True,
            "db_path": str(db_path),
            "tenant": tenant,
            "edge_count_before": edge_count_before,
            "proposal": _empty_proposal_report(),
            "wikilinks": _empty_wikilink_report(),
            "inserted_count": 0,
            "duplicate_count": 0,
            "failed_count": 0,
            "errors": [],
        }

        if proposal_jsonl is not None:
            _import_proposal_edges(
                store,
                Path(proposal_jsonl),
                index["ids"],
                report,
                stop_on_error=stop_on_error,
            )
        if sources:
            _import_wikilink_edges(
                store,
                [Path(source) for source in sources],
                index,
                report,
                wikilink_kind=wikilink_kind,
            )

        store.conn.commit()
        edge_count_after = _edge_count(store)
        report["edge_count_after"] = edge_count_after
        report["edge_count_delta"] = edge_count_after - edge_count_before
        report["ok"] = report["failed_count"] == 0
        return report
    finally:
        store.close()


def _empty_proposal_report() -> dict[str, Any]:
    return {
        "path": None,
        "row_count": 0,
        "inserted_count": 0,
        "duplicate_count": 0,
        "skipped_missing_count": 0,
        "kind_counts": {},
        "missing_examples": [],
    }


def _empty_wikilink_report() -> dict[str, Any]:
    return {
        "source_count": 0,
        "link_count": 0,
        "inserted_count": 0,
        "duplicate_count": 0,
        "dangling_count": 0,
        "ambiguous_count": 0,
        "missing_source_count": 0,
        "dangling_examples": [],
        "ambiguous_examples": [],
        "missing_source_examples": [],
    }


def _memory_index(store: Store, tenant: str) -> dict[str, Any]:
    rows = store.conn.execute(
        "SELECT id, subject, source_json FROM memories WHERE tenant=?",
        (tenant,),
    ).fetchall()
    ids = {str(row["id"]) for row in rows}
    path_to_ids: dict[str, set[str]] = {}
    aliases: dict[str, set[str]] = {}
    for row in rows:
        mem_id = str(row["id"])
        source = _loads_object(row["source_json"])
        path = str(source.get("path") or "")
        uri = str(source.get("uri") or "")
        subject = str(row["subject"] or "")
        if path:
            path_to_ids.setdefault(path, set()).add(mem_id)
        for alias in _aliases_for_memory(mem_id, path, uri, subject):
            aliases.setdefault(_normalize_link_target(alias), set()).add(mem_id)
    return {"ids": ids, "path_to_ids": path_to_ids, "aliases": aliases}


def _aliases_for_memory(mem_id: str, path: str, uri: str, subject: str) -> set[str]:
    aliases = {mem_id}
    if subject:
        aliases.add(subject)
        aliases.add(subject.rsplit(":", 1)[-1])
    if uri:
        aliases.add(uri)
        if uri.startswith("markdown://"):
            aliases.add(uri.removeprefix("markdown://"))
    if path:
        path_obj = Path(path)
        aliases.update(
            {
                path,
                path.removesuffix(".md"),
                path_obj.name,
                path_obj.stem,
            }
        )
    return {alias for alias in aliases if alias}


def _import_proposal_edges(
    store: Store,
    proposal_jsonl: Path,
    memory_ids: set[str],
    report: dict[str, Any],
    *,
    stop_on_error: bool,
) -> None:
    proposal = report["proposal"]
    proposal["path"] = str(proposal_jsonl)
    kind_counts: Counter[str] = Counter()
    with proposal_jsonl.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            proposal["row_count"] += 1
            try:
                row = json.loads(line)
                child = str(row.get("src_id") or row.get("child") or "")
                parent = str(row.get("dst_id") or row.get("parent") or "")
                kind = str(row.get("type") or row.get("kind") or "related_to")
                if not child or not parent:
                    raise ValueError("proposal edge missing src_id/dst_id")
            except Exception as exc:  # noqa: BLE001
                _record_error(report, line_number, str(exc), stop_on_error=stop_on_error)
                continue
            kind_counts[kind] += 1
            missing = [mem_id for mem_id in (child, parent) if mem_id not in memory_ids]
            if missing:
                proposal["skipped_missing_count"] += 1
                _append_example(
                    proposal["missing_examples"],
                    {
                        "line": line_number,
                        "missing": missing,
                        "src_id": child,
                        "dst_id": parent,
                        "kind": kind,
                    },
                )
                continue
            inserted = _insert_edge(store, child, parent, kind)
            _count_insert(report, proposal, inserted)
    proposal["kind_counts"] = dict(sorted(kind_counts.items()))


def _import_wikilink_edges(
    store: Store,
    sources: list[Path],
    index: dict[str, Any],
    report: dict[str, Any],
    *,
    wikilink_kind: str,
) -> None:
    documents = load_markdown_documents(sources)
    wikilinks = report["wikilinks"]
    wikilinks["source_count"] = len(documents)
    for document in documents:
        source_ids = index["path_to_ids"].get(document.relative_path, set())
        if len(source_ids) != 1:
            wikilinks["missing_source_count"] += 1
            _append_example(
                wikilinks["missing_source_examples"],
                {
                    "path": document.relative_path,
                    "candidate_count": len(source_ids),
                },
            )
            continue
        child = next(iter(source_ids))
        for raw_target, target in _wikilinks(document.content):
            wikilinks["link_count"] += 1
            matches = index["aliases"].get(_normalize_link_target(target), set())
            if not matches:
                wikilinks["dangling_count"] += 1
                _append_example(
                    wikilinks["dangling_examples"],
                    {
                        "path": document.relative_path,
                        "link": raw_target,
                        "target": target,
                    },
                )
                continue
            if len(matches) > 1:
                wikilinks["ambiguous_count"] += 1
                _append_example(
                    wikilinks["ambiguous_examples"],
                    {
                        "path": document.relative_path,
                        "link": raw_target,
                        "target": target,
                        "candidate_ids": sorted(matches)[:5],
                    },
                )
                continue
            parent = next(iter(matches))
            if child == parent:
                continue
            inserted = _insert_edge(store, child, parent, wikilink_kind)
            _count_insert(report, wikilinks, inserted)


def _insert_edge(store: Store, child: str, parent: str, kind: str) -> bool:
    cursor = store.conn.execute(
        "INSERT OR IGNORE INTO prov_edges (child, parent, kind) VALUES (?,?,?)",
        (child, parent, kind),
    )
    return cursor.rowcount == 1


def _count_insert(
    report: dict[str, Any],
    section: dict[str, Any],
    inserted: bool,
) -> None:
    key = "inserted_count" if inserted else "duplicate_count"
    report[key] += 1
    section[key] += 1


def _record_error(
    report: dict[str, Any],
    line_number: int,
    error: str,
    *,
    stop_on_error: bool,
) -> None:
    report["failed_count"] += 1
    report["errors"].append({"line": line_number, "error": error})
    if stop_on_error:
        raise ValueError(f"line {line_number}: {error}")


def _wikilinks(content: str) -> Iterable[tuple[str, str]]:
    for match in _WIKILINK_RE.finditer(content):
        raw = match.group(1).strip()
        target = raw.split("|", 1)[0].split("#", 1)[0].strip()
        if target:
            yield raw, target


def _normalize_link_target(value: str) -> str:
    normalized = value.strip().lower().replace("\\", "/")
    normalized = re.sub(r"\s+", "_", normalized)
    if normalized.startswith("markdown://"):
        normalized = normalized.removeprefix("markdown://")
    return normalized.removesuffix(".md")


def _loads_object(raw: str | bytes | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _append_example(examples: list[dict[str, Any]], value: dict[str, Any]) -> None:
    if len(examples) < 10:
        examples.append(value)


def _edge_count(store: Store) -> int:
    return int(store.conn.execute("SELECT COUNT(*) FROM prov_edges").fetchone()[0])
