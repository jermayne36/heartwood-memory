"""Run receipt privacy positive controls on disposable public-source copies.

No committed source or fixture is mutated in place. Each mutant must make its
named test fail; subprocess output is saved for inspection in the output folder.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

MODULE = "tests/test_recall_receipt_v2.py"
MUTANTS = [
    ("M1", "heartwood/client.py", [
        ('                "visible": len(visible),\n                "returned": len(results),',
         '                "visible": len(visible),\n                "denied_count": len(denied),\n                "returned": len(results),'),
    ], "test_client_and_mcp_differential"),
    ("M2", "heartwood/client.py", [
        ('                    "blind": secrets.token_hex(32),\n', ''),
    ], "test_row_hash_guessing_and_blind_hygiene"),
    ("M3", "heartwood/client.py", [
        ('            and self.enforcer.visible(principal, m)[0]\n', ''),
    ], "test_client_and_mcp_differential"),
    ("M4", "heartwood/receipts.py", [
        ('if receipt["schema"] == RECALL_SCHEMA_V1:\n            policy_fields.add("denied_count")',
         'if "denied_count" in receipt["policy"]:\n            policy_fields.add("denied_count")'),
    ], "test_v2_receipt_tampering[add-denied-policy_fields_invalid]"),
    ("M5", "heartwood/receipts.py", [
        ('    if row_detail != expected_detail:', '    if not recall_v2 and row_detail != expected_detail:'),
    ], "test_v2_receipt_tampering[visible-audit_binding_mismatch]"),
    ("M6", "heartwood/receipts.py", [
        ('set(row_detail) != set(expected_detail) | {"denied", "blind"}',
         'set(row_detail) | {"blind"} != set(expected_detail) | {"denied", "blind"}'),
        ('denied, blind = row_detail["denied"], row_detail["blind"]',
         'denied, blind = row_detail["denied"], row_detail.get("blind", "0" * 64)'),
    ], "test_v2_row_refusals[blind-None-audit_binding_mismatch]"),
    ("M7-reused", "heartwood/client.py", [
        ('"blind": secrets.token_hex(32)', '"blind": "0" * 64'),
    ], "test_row_hash_guessing_and_blind_hygiene"),
    ("M7-derived", "heartwood/client.py", [
        ('"blind": secrets.token_hex(32)', '"blind": sha256_prefixed(canonical_bytes(commitment))[7:]'),
    ], "test_row_hash_guessing_and_blind_hygiene"),
    ("M8-response", "heartwood/client.py", [
        ('"blind": secrets.token_hex(32)', '"blind": holder.setdefault("blind", secrets.token_hex(32))'),
        ('                self._cache_receipt(principal.id, recall_id, receipt)',
         '                receipt["blind"] = holder["blind"]\n                self._cache_receipt(principal.id, recall_id, receipt)'),
    ], "test_row_hash_guessing_and_blind_hygiene"),
    ("M8-log", "heartwood/client.py", [
        ('"blind": secrets.token_hex(32)', '"blind": holder.setdefault("blind", secrets.token_hex(32))'),
        ('                self._cache_receipt(principal.id, recall_id, receipt)',
         '                print(holder["blind"])\n                self._cache_receipt(principal.id, recall_id, receipt)'),
    ], "test_row_hash_guessing_and_blind_hygiene"),
    ("M9-reject", "heartwood/receipts.py", [
        ('RECALL_SCHEMAS = (RECALL_SCHEMA_V1, RECALL_SCHEMA)', 'RECALL_SCHEMAS = (RECALL_SCHEMA,)'),
    ], "test_v1_source_vector_passes"),
    ("M9-row-count", "heartwood/receipts.py", [
        ('    if row_detail != expected_detail:',
         '    if not recall_v2 and isinstance(row_detail, dict) and "denied" in expected_detail:\n'
         '        expected_detail["denied"] = row_detail.get("denied")\n'
         '    if row_detail != expected_detail:'),
    ], "test_v1_resigned_count_is_still_bound"),
    ("M13", "heartwood/client.py", [
        ('"schema": RECALL_SCHEMA, "receipt_id": receipt_id',
         '"schema": ("heartwood.recall-receipt.v1" if os.environ.get("HEARTWOOD_RECALL_RECEIPT_VERSION") == "v1" else RECALL_SCHEMA), "receipt_id": receipt_id'),
    ], "test_writer_has_no_v1_switch"),
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).resolve().parents[1]
    records = []
    for name, source, edits, test in MUTANTS:
        with tempfile.TemporaryDirectory(prefix="receipt-mutant-") as directory:
            scratch = Path(directory)
            for part in ("heartwood", "tests"):
                shutil.copytree(root / part, scratch / part, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
            shutil.copyfile(root / "pyproject.toml", scratch / "pyproject.toml")
            path = scratch / source
            text = path.read_text()
            for before, after in edits:
                if text.count(before) != 1:
                    raise RuntimeError(f"{name}: mutation target is not unique")
                text = text.replace(before, after)
            path.write_text(text)
            result = subprocess.run(
                [sys.executable, "-m", "pytest", f"{MODULE}::{test}", "-q", "--tb=short"],
                cwd=scratch, capture_output=True, text=True, timeout=60,
            )
            (args.output_dir / f"{name}.txt").write_text(result.stdout + result.stderr)
            killed = result.returncode == 1 and "FAILED" in result.stdout and "ERROR collecting" not in result.stdout
            records.append({"mutant": name, "test": test, "killed": killed, "exit": result.returncode})
            print(json.dumps(records[-1]), flush=True)
    (args.output_dir / "summary.json").write_text(json.dumps(records, indent=2) + "\n")
    return 0 if all(row["killed"] for row in records) else 1


if __name__ == "__main__":
    sys.exit(main())
