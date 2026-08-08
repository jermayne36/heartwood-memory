import copy
import hashlib
import json
import re

from heartwood import audit_epochs
from heartwood.audit import AuditLog
from heartwood.audit_bundle import _BundleStore


class _RowsStore:
    def __init__(self, chain_id, rows):
        self._chain_id = chain_id
        self._rows = rows

    def chain_id(self):
        return self._chain_id

    def iter_audit(self):
        yield from self._rows


class _BrokenChainIdStore(_RowsStore):
    def chain_id(self):
        raise RuntimeError("missing chain identity")


def _hash(prev_hash, body, ts):
    return hashlib.sha256((prev_hash + body + repr(ts)).encode()).hexdigest()


def _current_row():
    displayed = {
        "tenant": "tenant:test",
        "principal": "agent:test",
        "action": "remember",
        "target": "mem_test",
    }
    body = json.dumps(
        {**displayed, "detail": {"kind": "fact"}},
        sort_keys=True,
        separators=(",", ":"),
    )
    ts = 1.25
    return {"seq": 1, "ts": ts, **displayed, "body": body,
            "prev_hash": "genesis", "row_hash": _hash("genesis", body, ts)}


def _legacy_row(monkeypatch):
    chain_id = "chain_test_legacy"
    displayed = {
        "tenant": "tenant:test",
        "principal": "agent:migration",
        "action": "classify",
        "target": "mem_legacy",
    }
    body = json.dumps(
        {"from": "internal", "operation": "classification_update",
         "source_ids_json": "[]", "task_id": 1, "to": "confidential"},
        sort_keys=True,
        separators=(",", ":"),
    )
    ts = 1.5
    row = {"seq": 7, "ts": ts, **displayed, "body": body,
           "prev_hash": "genesis", "row_hash": _hash("genesis", body, ts)}
    display_hash = hashlib.sha256(
        json.dumps(displayed, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    monkeypatch.setitem(
        audit_epochs._DISPLAY_BINDING_COMMITMENTS,
        chain_id,
        {row["seq"]: (row["row_hash"], display_hash)},
    )
    return chain_id, row


def _recommit_legacy_row(chain_id, row):
    display_hash = audit_epochs._DISPLAY_BINDING_COMMITMENTS[chain_id][row["seq"]][1]
    audit_epochs._DISPLAY_BINDING_COMMITMENTS[chain_id][row["seq"]] = (
        row["row_hash"], display_hash
    )


def test_current_epoch_tampering_fails_closed():
    # @positive-control(audit-display-binding) current body/display controls
    genuine = _current_row()
    assert AuditLog(_RowsStore("chain_current", [genuine])).verify_chain() is True

    body_tampered = copy.deepcopy(genuine)
    body_tampered["body"] = body_tampered["body"].replace("fact", "opinion")
    assert AuditLog(_RowsStore("chain_current", [body_tampered])).verify_chain() is False

    display_tampered = copy.deepcopy(genuine)
    display_tampered["target"] = "mem_substituted"
    assert AuditLog(_RowsStore("chain_current", [display_tampered])).verify_chain() is False


def test_legacy_epoch_tampering_fails_closed(monkeypatch):
    # @positive-control(audit-display-binding) legacy body/display controls
    chain_id, genuine = _legacy_row(monkeypatch)
    assert AuditLog(_RowsStore(chain_id, [genuine])).verify_chain() is True

    body_tampered = copy.deepcopy(genuine)
    body_tampered["body"] = body_tampered["body"].replace("internal", "public")
    assert AuditLog(_RowsStore(chain_id, [body_tampered])).verify_chain() is False

    display_tampered = copy.deepcopy(genuine)
    display_tampered["target"] = "mem_substituted"
    assert AuditLog(_RowsStore(chain_id, [display_tampered])).verify_chain() is False


def test_uncommitted_legacy_shape_is_rejected(monkeypatch):
    chain_id, row = _legacy_row(monkeypatch)
    row["seq"] += 1
    assert AuditLog(_RowsStore(chain_id, [row])).verify_chain() is False


def test_legacy_row_hash_pin_rejects_a_different_committed_hash(monkeypatch):
    chain_id, row = _legacy_row(monkeypatch)
    _, display_hash = audit_epochs._DISPLAY_BINDING_COMMITMENTS[chain_id][row["seq"]]
    audit_epochs._DISPLAY_BINDING_COMMITMENTS[chain_id][row["seq"]] = (
        "0" * 64, display_hash
    )
    assert AuditLog(_RowsStore(chain_id, [row])).verify_chain() is False


def test_legacy_body_key_set_pin_rejects_an_extra_key(monkeypatch):
    chain_id, row = _legacy_row(monkeypatch)
    payload = json.loads(row["body"])
    payload["unexpected"] = True
    row["body"] = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    row["row_hash"] = _hash(row["prev_hash"], row["body"], row["ts"])
    _recommit_legacy_row(chain_id, row)
    assert AuditLog(_RowsStore(chain_id, [row])).verify_chain() is False


def test_legacy_operation_pin_rejects_a_different_operation(monkeypatch):
    chain_id, row = _legacy_row(monkeypatch)
    payload = json.loads(row["body"])
    payload["operation"] = "classification_replay"
    row["body"] = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    row["row_hash"] = _hash(row["prev_hash"], row["body"], row["ts"])
    _recommit_legacy_row(chain_id, row)
    assert AuditLog(_RowsStore(chain_id, [row])).verify_chain() is False


def test_chain_id_lookup_failure_returns_false_for_legacy_rows(monkeypatch):
    _, row = _legacy_row(monkeypatch)
    assert AuditLog(_BrokenChainIdStore("ignored", [row])).verify_chain() is False


def test_null_display_legacy_shape_is_intentionally_rejected():
    body = json.dumps({"detail": {}}, sort_keys=True, separators=(",", ":"))
    ts = 2.5
    row = {
        "seq": 1,
        "ts": ts,
        "tenant": None,
        "principal": None,
        "action": None,
        "target": None,
        "body": body,
        "prev_hash": "genesis",
        "row_hash": _hash("genesis", body, ts),
    }
    assert AuditLog(_RowsStore("chain_null", [row])).verify_chain() is False


def test_shipped_legacy_commitments_are_well_formed():
    assert len(audit_epochs._DISPLAY_BINDING_COMMITMENTS) == 1
    commitments = next(iter(audit_epochs._DISPLAY_BINDING_COMMITMENTS.values()))
    assert list(commitments) == list(range(13840, 13871))
    assert all(
        re.fullmatch(r"[0-9a-f]{64}", digest)
        for pair in commitments.values()
        for digest in pair
    )


def test_bundle_store_uses_the_same_legacy_epoch_verifier(monkeypatch):
    chain_id, row = _legacy_row(monkeypatch)
    store = _BundleStore(
        chain_id=chain_id,
        rows=[row],
        sink_id="test-sink",
        sink_head="sha256:" + "0" * 64,
    )
    assert AuditLog(store).verify_chain() is True

    row["target"] = "mem_substituted"
    assert AuditLog(store).verify_chain() is False
