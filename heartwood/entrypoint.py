"""Dependency-light console dispatcher for offline receipt commands."""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path


_OFFLINE_COMMANDS = {
    "export-principal-keys",
    "verify-recall-receipt",
    "verify-erasure-receipt",
    "verify-erasure",
}


def _roots(values: list[str] | None) -> list[str]:
    supplied = values or []
    if not supplied and os.environ.get("HEARTWOOD_ANCHOR_ROOT_FINGERPRINT"):
        supplied = [os.environ["HEARTWOOD_ANCHOR_ROOT_FINGERPRINT"]]
    return [item.strip() for value in supplied for item in value.split(",") if item.strip()]


def _write(payload: dict, output: Path | None) -> None:
    text = json.dumps(payload, indent=2)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
    print(text)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Heartwood offline receipt verifier.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    export = subparsers.add_parser("export-principal-keys")
    export.add_argument("--db", type=Path, required=True)
    export.add_argument("--tenant", required=True)
    export.add_argument("--output", type=Path)
    for command in ("verify-recall-receipt", "verify-erasure-receipt", "verify-erasure"):
        verify = subparsers.add_parser(command)
        verify.add_argument("--receipt", type=Path, required=True)
        verify.add_argument("--audit-bundle", type=Path, required=True)
        verify.add_argument("--anchor-root-fingerprint", action="append")
        verify.add_argument("--expected-latest-anchor-id", required=True)
        if command == "verify-recall-receipt":
            verify.add_argument("--results", type=Path, required=True)
        if command == "verify-erasure":
            verify.add_argument("--db", type=Path, required=True)
            verify.add_argument("--root-present", choices=("true", "false"))
        verify.add_argument("--explain", action="store_true")
        verify.add_argument("--output", type=Path)
    return parser


def _export_keys(args) -> dict:
    from .receipts import b64e

    connection = sqlite3.connect(f"file:{args.db.resolve()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only=ON")
        keys, seen = [], set()
        for row in connection.execute(
            "SELECT principal_id,algorithm,public_key FROM principal_keys WHERE tenant=? "
            "UNION ALL SELECT principal_id,algorithm,public_key FROM principal_key_aliases "
            "WHERE tenant=? ORDER BY principal_id,public_key",
            (args.tenant, args.tenant),
        ):
            identity = (row["principal_id"], row["algorithm"], bytes(row["public_key"]))
            if identity in seen:
                continue
            seen.add(identity)
            keys.append({
                "principal_id": row["principal_id"], "algorithm": row["algorithm"],
                "public_key_b64": b64e(bytes(row["public_key"])),
            })
    finally:
        connection.close()
    return {"schema": "heartwood.principal-keys.v1", "tenant": args.tenant, "keys": keys}


def _verify(args) -> dict:
    from .receipts import (
        EXPLAIN_BLOCKS,
        load_json_strict,
        verify_erasure_against_store,
        verify_erasure_receipt,
        verify_recall_receipt,
    )

    receipt = load_json_strict(args.receipt)
    common = {
        "trusted_root_fingerprints": _roots(args.anchor_root_fingerprint),
        "audit_bundle": str(args.audit_bundle),
        "expected_latest_anchor_id": args.expected_latest_anchor_id,
    }
    if args.command == "verify-recall-receipt":
        result_bytes = json.loads(args.results.read_text(encoding="utf-8"))
        if isinstance(result_bytes, dict):
            result_bytes = result_bytes.get("results")
        result = verify_recall_receipt(receipt, results=result_bytes, **common)
        kind = "recall"
    elif args.command == "verify-erasure-receipt":
        result = verify_erasure_receipt(receipt, **common)
        kind = "erasure"
    else:
        root_present = None if args.root_present is None else args.root_present == "true"
        result = verify_erasure_against_store(
            receipt, db_path=args.db, root_present=root_present, **common,
        )
        kind = "erasure"
    if args.explain:
        result.update(EXPLAIN_BLOCKS[kind])
    return result


def offline_main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    try:
        payload = _export_keys(args) if args.command == "export-principal-keys" else _verify(args)
    except Exception as exc:
        print(f"heartwood error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    _write(payload, args.output)
    if args.command != "export-principal-keys" and payload.get("ok") is not True:
        raise SystemExit(2)


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] in _OFFLINE_COMMANDS:
        offline_main(sys.argv[1:])
        return
    from .cli import main as full_main

    full_main()


if __name__ == "__main__":
    main()
