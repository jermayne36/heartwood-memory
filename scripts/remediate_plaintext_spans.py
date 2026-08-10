#!/usr/bin/env python3
"""Remove byte-identical plaintext source spans and erase SQLite residue."""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path


def _hash_content(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _raw_field_hits(paths: list[Path]) -> list[str]:
    marker = b'"text": '
    hits = []
    for path in paths:
        if not path.exists() or path.stat().st_size == 0:
            continue
        tail = b""
        with path.open("rb") as raw_file:
            while chunk := raw_file.read(1024 * 1024):
                payload = tail + chunk
                if marker in payload:
                    hits.append(path.name)
                    break
                tail = payload[-(len(marker) - 1) :]
    return hits


def remediate(path: Path) -> dict[str, object]:
    connection = sqlite3.connect(path, timeout=30.0)
    connection.execute("PRAGMA busy_timeout=30000")
    connection.execute("PRAGMA secure_delete=ON")
    columns = {
        str(row[1]) for row in connection.execute("PRAGMA table_info(memories)")
    }
    required = {"id", "content_hash", "source_spans_json"}
    if not required <= columns:
        raise RuntimeError(f"{path} is missing columns: {sorted(required - columns)}")

    rewritten_rows = 0
    verified_spans = 0
    connection.execute("BEGIN IMMEDIATE")
    try:
        rows = connection.execute(
            "SELECT id, content_hash, source_spans_json FROM memories ORDER BY id"
        ).fetchall()
        for memory_id, content_hash, source_spans_json in rows:
            spans = json.loads(source_spans_json or "[]")
            if not isinstance(spans, list):
                raise RuntimeError(f"{memory_id}: source_spans_json is not an array")
            changed = False
            for span in spans:
                if "text" not in span:
                    continue
                text = span["text"]
                if not isinstance(text, str):
                    raise RuntimeError(f"{memory_id}: span text is not a string")
                if span.get("content_hash") != content_hash:
                    raise RuntimeError(f"{memory_id}: span hash differs from row hash")
                if _hash_content(text) != content_hash:
                    raise RuntimeError(f"{memory_id}: span text fails its content hash")
                span.pop("text")
                span["text_ref"] = "self"
                changed = True
                verified_spans += 1
            if changed:
                connection.execute(
                    "UPDATE memories SET source_spans_json=? WHERE id=?",
                    (json.dumps(spans), memory_id),
                )
                rewritten_rows += 1
        connection.commit()
    except Exception:
        connection.rollback()
        connection.close()
        raise

    remaining_text_spans = 0
    self_ref_spans = 0
    for (source_spans_json,) in connection.execute(
        "SELECT source_spans_json FROM memories"
    ):
        spans = json.loads(source_spans_json or "[]")
        remaining_text_spans += sum("text" in span for span in spans)
        self_ref_spans += sum(span.get("text_ref") == "self" for span in spans)
    if remaining_text_spans:
        connection.close()
        raise RuntimeError(f"{path}: {remaining_text_spans} plaintext spans remain")

    connection.execute("VACUUM")
    checkpoint = tuple(
        int(value)
        for value in connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    )
    if checkpoint[0] != 0:
        connection.close()
        raise RuntimeError(f"{path}: WAL checkpoint remained busy: {checkpoint}")
    connection.close()

    wal_path = Path(f"{path}-wal")
    raw_hits = _raw_field_hits([path, wal_path])
    if raw_hits:
        raise RuntimeError(f"{path}: plaintext source-span residue in {raw_hits}")
    return {
        "path": str(path),
        "rows": len(rows),
        "rewritten_rows": rewritten_rows,
        "verified_spans": verified_spans,
        "remaining_text_spans": remaining_text_spans,
        "self_ref_spans": self_ref_spans,
        "vacuum": "ok",
        "checkpoint": checkpoint,
        "wal_bytes": wal_path.stat().st_size if wal_path.exists() else 0,
        "raw_plaintext_field_hits": raw_hits,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", nargs="+", type=Path)
    args = parser.parse_args()
    for database in args.database:
        if not database.is_file():
            raise SystemExit(f"database does not exist: {database}")
        print(json.dumps(remediate(database), sort_keys=True))


if __name__ == "__main__":
    main()
