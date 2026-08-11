"""Clone-runnable proof of the hard-erasure mechanism at initiation time."""
from __future__ import annotations

from datetime import datetime, timezone
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Heartwood, LocalKmsCustodian  # noqa: E402
from heartwood.importers.markdown import dev_models  # noqa: E402


TENANT = "tenant:erasure-mechanism"
SUBJECT = "customer:erasure-mechanism"
RETENTION_FLOOR_SECONDS = 0


def _run_erasure_mechanism(*, initiate_shred: bool) -> None:
    with tempfile.TemporaryDirectory(prefix="heartwood-erasure-mechanism-") as temp_dir:
        embedder, reranker = dev_models()
        custodian = LocalKmsCustodian(
            bytes([73]) * 32,
            key_id="erasure-mechanism-root-v1",
            retention_floor_seconds=RETENTION_FLOOR_SECONDS,
        )
        db = Heartwood(
            path=Path(temp_dir) / "heartwood.db",
            tenant=TENANT,
            embedder=embedder,
            reranker=reranker,
            key_custodian=custodian,
        )
        try:
            db.remember(
                "This content must become inaccessible when erasure initiates.",
                subject=SUBJECT,
                created_by="agent:test",
                source={"uri": "test://erasure-mechanism"},
            )

            events: list[tuple[str, datetime]] = []
            real_shred = db.keys.shred
            real_delete_memory = db.store.delete_memory

            def observed_shred(tenant: str, subject: str) -> None:
                events.append(("shred", datetime.now(timezone.utc)))
                if initiate_shred:
                    real_shred(tenant, subject)

            def observed_delete_memory(memory_id: str) -> None:
                events.append(("purge", datetime.now(timezone.utc)))
                real_delete_memory(memory_id)

            db.keys.shred = observed_shred
            db.store.delete_memory = observed_delete_memory

            started_at = datetime.now(timezone.utc)
            receipt = db.forget(
                SUBJECT,
                mode="hard",
                actor="agent:test",
                reason="public erasure mechanism gate",
            )
            returned_at = datetime.now(timezone.utc)

            initiated_at = datetime.fromisoformat(receipt["erasure_initiated_at"])
            failures = []
            if not (started_at <= initiated_at <= returned_at):
                failures.append("shred initiation was not recorded at operation entry")
            if not events or events[0][0] != "shred":
                failures.append("shred did not initiate before purge")
            elif initiated_at > events[0][1]:
                failures.append("receipt timestamp followed the shred request")
            if receipt["key_shred_requested"] is not True:
                failures.append("receipt did not record the key-shred request")
            if db.keys.get(TENANT, SUBJECT) is not None:
                failures.append("subject key remains usable after erasure initiation")
            try:
                db.keys.get_or_create(TENANT, SUBJECT)
                failures.append("erased subject accepted a new usable key")
            except KeyError:
                pass
            if (
                receipt["purge_requested"] is not True
                or not any(event == "purge" for event, _ in events)
            ):
                failures.append("derived-artifact purge was not requested")
            if receipt["custody_backend"] != custodian.name:
                failures.append("receipt did not identify the custody backend")
            if (
                receipt["custody_retention_floor_seconds"]
                != RETENTION_FLOOR_SECONDS
            ):
                failures.append("receipt did not record the declared retention floor")

            # @fail-closed(erasure-mechanism-t0)
            assert not failures, "; ".join(failures)
        finally:
            db.close()


def test_erasure_mechanism_is_proved_at_initiation_time():
    _run_erasure_mechanism(initiate_shred=True)


# @positive-control(erasure-mechanism-t0)
def test_erasure_mechanism_gate_fires_when_shred_does_not_initiate():
    with pytest.raises(
        RuntimeError,
        match="hard erasure did not make the subject key unusable",
    ):
        _run_erasure_mechanism(initiate_shred=False)
