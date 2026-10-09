"""Caller-visible receipt privacy, audit binding, and legacy compatibility."""
from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import re
import threading
from http.server import HTTPServer
from pathlib import Path
from urllib import error, request

import pytest

from heartwood import Policy, Principal
from heartwood.adapters.mcp_server import MCPMemoryAPI, build_server
from heartwood.cli import main as cli_main
from heartwood.receipts import (
    RECALL_SCHEMA, RECALL_SCHEMA_V1, canonical_bytes, finalize_receipt,
    main as receipt_main, receipt_commitment, sha256_prefixed, verify_recall_receipt,
)
from heartwood.recall_service import RecallEngine, build_handler
from test_receipts import _bundle, _db, _resign

VOLATILE = {
    "recall_id", "receipt_id", "issued_at_utc", "audit_seq", "audit_row_hash",
    "receipt_hash", "signature", "latency_ms",
}
FILTERS = [{}, {"subject": "subject:hidden"}, {"allowed_classifications": ["confidential"]}]


def stable(value, *, explanation=False):
    if isinstance(value, dict):
        return {
            key: stable(item, explanation=explanation)
            for key, item in value.items()
            if key not in VOLATILE and not (explanation and key == "effective_at")
        }
    if isinstance(value, (list, tuple)):
        return [stable(item, explanation=explanation) for item in value]
    return value


@pytest.fixture()
def receipted(tmp_path):
    db, path, anchors, pin = _db(tmp_path)
    try:
        for i in range(3):
            db.remember(
                f"Recall evidence visible {i}", subject="subject:visible",
                created_by="fixture:writer", policy=Policy(),
            )
        yield db, path, anchors, pin
    finally:
        db.close()


def add_hidden(db, *, indexed, count):
    for i in range(count):
        db.remember(
            f"Recall evidence restricted {indexed} {i}", subject="subject:hidden",
            created_by="fixture:writer", indexed=indexed,
            policy=Policy(classification="confidential"),
        )


def audit_row(db, receipt):
    return dict(db.store.conn.execute(
        "SELECT * FROM audit_log WHERE seq=?", (receipt["audit_seq"],),
    ).fetchone())


def verify_args(receipted, tmp_path, response):
    db, path, anchors, pin = receipted
    bundle, checkpoint = _bundle(db, path, anchors, pin, tmp_path)
    return {
        "trusted_root_fingerprints": [pin], "results": response["results"],
        "audit_bundle": str(bundle), "expected_latest_anchor_id": checkpoint,
    }


@pytest.mark.parametrize("filters", FILTERS, ids=["plain", "subject", "classification"])
def test_client_and_mcp_differential(receipted, filters, caplog, capsys):
    db, _, _, _ = receipted
    caller = Principal("fixture:reader", db.tenant, clearance="internal")
    api = MCPMemoryAPI(db)

    def observe():
        response = db.recall("Recall evidence", principal=caller, filters=filters, k=2)
        assert response["receipt"]["schema"] == RECALL_SCHEMA
        assert set(response["receipt"]["policy"]) == {"strict_mode", "visible", "returned"}
        fetched = db.recall_receipt(caller.id, response["recall_id"])
        explanation = db.explain_recall(response["recall_id"])
        mcp = api.recall("Recall evidence", principal_id=caller.id, filters=filters, k=2)
        mcp_explain = api.explain_recall(mcp["recall_id"])
        surfaces = [response, fetched, explanation, mcp, mcp_explain]
        for value in surfaces:
            assert "denied" not in json.dumps(value).lower()
        # The row's blind must stay out of all caller surfaces and captured logs.
        for item in (response, mcp):
            blind = json.loads(audit_row(db, item["receipt"])["body"])["detail"]["blind"]
            assert blind not in json.dumps(surfaces)
            assert blind not in caplog.text + capsys.readouterr().out
        return [stable(value, explanation=i in (2, 4)) for i, value in enumerate(surfaces)]

    baseline = observe()
    assert baseline[0]["index_lag"] == 0
    add_hidden(db, indexed=True, count=5)
    assert observe() == baseline
    add_hidden(db, indexed=False, count=4)
    assert observe() == baseline
    assert db.store.index_lag(db.tenant) == 4
    assert db.flush_index()["index_lag"] == 4


def http_json(url, path, *, payload=None, token):
    data = None if payload is None else json.dumps(payload).encode()
    req = request.Request(
        url + path, data=data,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with request.urlopen(req, timeout=5) as response:
        return json.load(response)


@pytest.mark.parametrize("filters", FILTERS, ids=["plain", "subject", "classification"])
def test_http_differential_and_other_principal_404(receipted, tmp_path, filters):
    db, path, _, _ = receipted
    engine = RecallEngine(db_path=path, default_tenant=db.tenant, dev_models=True)
    engine.clients[db.tenant] = db
    credentials = tmp_path / "credentials.json"
    credentials.write_text(json.dumps({"credentials": [
        {"token": token, "tenant": db.tenant, "principal_id": principal,
         "clearance": "internal"}
        for token, principal in [("fixture-reader", "fixture:reader"), ("fixture-other", "fixture:other")]
    ]}))
    server = HTTPServer(("127.0.0.1", 0), build_handler(engine, token_file=credentials))
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    url = f"http://127.0.0.1:{server.server_port}"
    payload = {"query": "Recall evidence", "filters": filters, "k": 2}

    def observe():
        response = http_json(url, "/recall", payload=payload, token="fixture-reader")
        assert response["receipt"]["schema"] == RECALL_SCHEMA
        path = f'/recall/{response["recall_id"]}/receipt'
        fetched = http_json(url, path, token="fixture-reader")
        assert fetched["receipt"] == response["receipt"]
        with pytest.raises(error.HTTPError) as denied:
            http_json(url, path, token="fixture-other")
        assert denied.value.code == 404
        assert json.load(denied.value)["error"] == "not_found"
        explanation = http_json(url, "/explain-recall", payload=payload, token="fixture-reader")
        values = [response, fetched, explanation]
        for value in values:
            assert "denied" not in json.dumps(value).lower()
        blind = json.loads(audit_row(db, response["receipt"])["body"])["detail"]["blind"]
        assert blind not in json.dumps(values)
        return [stable(value, explanation=i == 2) for i, value in enumerate(values)]

    try:
        baseline = observe()
        add_hidden(db, indexed=True, count=5)
        assert observe() == baseline
        add_hidden(db, indexed=False, count=4)
        assert observe() == baseline
    finally:
        server.shutdown()
        worker.join(timeout=5)
        server.server_close()


# @positive-control(recall-v2-audit-counts)
def test_v2_pass_and_operator_audit(receipted, tmp_path, capsys):
    db, _, _, _ = receipted
    add_hidden(db, indexed=True, count=5)
    response = db.recall("Recall evidence", principal=db.principal("fixture:reader"), k=2)
    receipt = response["receipt"]
    detail = json.loads(audit_row(db, receipt)["body"])["detail"]
    assert detail["denied"] == 5
    assert re.fullmatch("[0-9a-f]{64}", detail["blind"])
    assert set(detail) == {"receipt_hash", "result_count", "strict_mode", "visible", "returned", "denied", "blind"}
    kwargs = verify_args(receipted, tmp_path, response)
    result = verify_recall_receipt(receipt, **kwargs)
    assert result["status"] == "PASS"
    assert str(detail["blind"]) not in json.dumps(result)
    assert "denied" not in json.dumps(result)
    assert verify_recall_receipt(receipt, **{**kwargs, "audit_bundle": None})["status"] == "AUDIT_UNBOUND"
    receipt_path, results_path = tmp_path / "receipt.json", tmp_path / "results.json"
    receipt_path.write_text(json.dumps(receipt))
    results_path.write_text(json.dumps(response["results"]))
    common = ["--results", str(results_path), "--audit-bundle", kwargs["audit_bundle"],
              "--expected-latest-anchor-id", kwargs["expected_latest_anchor_id"], "--explain"]
    assert receipt_main(["verify", str(receipt_path), "--root", kwargs["trusted_root_fingerprints"][0], *common]) == 0
    module_output = json.loads(capsys.readouterr().out)
    cli_main(["verify-recall-receipt", "--receipt", str(receipt_path),
              "--anchor-root-fingerprint", kwargs["trusted_root_fingerprints"][0], *common])
    cli_output = json.loads(capsys.readouterr().out)
    assert module_output == cli_output
    assert "not part of the receipt" in " ".join(module_output["proves"])
    assert '"denied":' not in json.dumps(module_output)


# @positive-control(recall-v2-policy-fields)
# @positive-control(recall-v2-audit-counts)
@pytest.mark.parametrize("tamper,reason", [
    ("relabel", "receipt_hash_mismatch"),
    ("relabel-resigned", "policy_fields_invalid"),
    ("add-denied", "policy_fields_invalid"),
    ("visible", "audit_binding_mismatch"),
    ("returned", "audit_binding_mismatch"),
])
def test_v2_receipt_tampering(receipted, tmp_path, tamper, reason):
    db, _, _, _ = receipted
    response = db.recall("Recall evidence", principal=db.principal("fixture:reader"), k=2)
    kwargs = verify_args(receipted, tmp_path, response)
    assert verify_recall_receipt(response["receipt"], **kwargs)["status"] == "PASS"
    changed = copy.deepcopy(response["receipt"])
    if tamper.startswith("relabel"):
        changed["schema"] = RECALL_SCHEMA_V1
    elif tamper == "add-denied":
        changed["policy"]["denied_count"] = 0
    else:
        changed["policy"][tamper] += 1
    if tamper != "relabel":
        changed = _resign(changed, db._anchor_writer, "recall")
    assert verify_recall_receipt(changed, **kwargs)["first_failure"] == reason


# @positive-control(recall-v2-audit-fields)
# @positive-control(recall-v2-audit-denied)
# @positive-control(recall-v2-audit-blind)
@pytest.mark.parametrize("field,value,reason", [
    ("denied", -1, "audit_binding_mismatch"),
    ("denied", True, "audit_binding_mismatch"),
    ("denied", None, "audit_binding_mismatch"),
    ("blind", None, "audit_binding_mismatch"),
    ("blind", "0" * 63, "audit_row_unblinded"),
    ("blind", "g" * 64, "audit_row_unblinded"),
    ("blind", "A" * 64, "audit_row_unblinded"),
    ("extra", 0, "audit_binding_mismatch"),
])
def test_v2_row_refusals(receipted, tmp_path, monkeypatch, field, value, reason):
    db, _, _, _ = receipted
    caller = db.principal("fixture:reader")
    good = db.recall("Recall evidence", principal=caller, k=2)
    append = db.audit.append_bound

    def changed_append(tenant, principal, action, target, builder):
        def malformed(seq):
            detail = builder(seq)
            if value is None:
                detail.pop(field)
            else:
                detail[field] = value
            return detail
        return append(tenant, principal, action, target, malformed)

    # Malformed fixture row is genuinely hash-bound and signed, so failure is
    # the new receipt constraint, not a corrupted chain or a stale anchor.
    monkeypatch.setattr(db.audit, "append_bound", changed_append)
    bad = db.recall("Recall evidence", principal=caller, k=2)
    kwargs = verify_args(receipted, tmp_path, bad)
    assert verify_recall_receipt(good["receipt"], **kwargs)["status"] == "PASS"
    assert verify_recall_receipt(bad["receipt"], **kwargs)["first_failure"] == reason


def test_v1_source_vector_passes():
    folder = Path(__file__).parent / "fixtures" / "recall-v1"
    vector = json.loads((folder / "vector.json").read_text())
    assert "62372e931ce0c5f012451779327f9551911fab84" in (folder / "PROVENANCE.txt").read_text()
    assert vector["receipt"]["schema"] == RECALL_SCHEMA_V1
    assert verify_recall_receipt(
        vector["receipt"], trusted_root_fingerprints=[vector["root_fingerprint"]],
        results=vector["results"], audit_bundle=str(folder / "audit-bundle.tar.gz"),
        expected_latest_anchor_id=vector["latest_anchor_id"],
    )["status"] == "PASS"


# @positive-control(recall-v1-audit-count)
def test_v1_resigned_count_is_still_bound(receipted, tmp_path):
    db, _, _, _ = receipted
    response = db.recall("Recall evidence", principal=db.principal("fixture:reader"), k=2)
    commitment = receipt_commitment(response["receipt"])
    commitment["schema"] = RECALL_SCHEMA_V1
    commitment["policy"]["denied_count"] = 0

    def v1_detail(seq):
        commitment["audit_seq"] = seq
        return {"receipt_hash": sha256_prefixed(canonical_bytes(commitment)),
                "result_count": len(commitment["results"]),
                **{key: commitment["policy"][key] for key in ("strict_mode", "visible", "returned")},
                "denied": commitment["policy"]["denied_count"]}

    row = db.audit.append_bound(db.tenant, commitment["principal_id"], "recall", commitment["recall_id"], v1_detail)
    receipt = finalize_receipt(commitment, audit_row_hash=row["row_hash"], anchor_writer=db._anchor_writer, kind="recall")
    kwargs = verify_args(receipted, tmp_path, response)
    assert verify_recall_receipt(receipt, **kwargs)["status"] == "PASS"
    receipt["policy"]["denied_count"] += 1
    changed = _resign(receipt, db._anchor_writer, "recall")
    assert verify_recall_receipt(changed, **kwargs)["first_failure"] == "audit_binding_mismatch"
    # A deployment-signed v1 receipt whose count disagrees with a genuinely
    # bound audit row must fail even when its receipt hash matches the row.
    def mismatched_v1_detail(seq):
        detail = v1_detail(seq)
        detail["denied"] = 0
        return detail

    row = db.audit.append_bound(db.tenant, commitment["principal_id"], "recall", commitment["recall_id"], mismatched_v1_detail)
    mismatched = finalize_receipt(commitment, audit_row_hash=row["row_hash"], anchor_writer=db._anchor_writer, kind="recall")
    mismatch_kwargs = verify_args(receipted, tmp_path, response)
    assert verify_recall_receipt(mismatched, **mismatch_kwargs)["first_failure"] == "audit_binding_mismatch"


def test_row_hash_guessing_and_blind_hygiene(receipted, monkeypatch, caplog, capsys):
    import heartwood.client as client_module

    db, _, _, _ = receipted
    add_hidden(db, indexed=True, count=5)
    random = client_module.secrets.token_hex
    draws = []

    def observed_random(n):
        value = random(n)
        if n == 32:
            draws.append(value)
        return value

    monkeypatch.setattr(client_module.secrets, "token_hex", observed_random)
    caller = db.principal("fixture:reader")
    first = db.recall("Recall evidence", principal=caller, k=2)
    second = db.recall("Recall evidence", principal=caller, k=2)
    row = audit_row(db, second["receipt"])
    assert second["receipt"]["audit_seq"] == first["receipt"]["audit_seq"] + 1
    assert row["prev_hash"] == first["receipt"]["audit_row_hash"]
    detail = json.loads(row["body"])["detail"]
    # Attacker gets both adjacent receipts AND the row's true timestamp.
    receipt = second["receipt"]
    known_detail = {"receipt_hash": receipt["receipt_hash"], "result_count": len(receipt["results"]),
                    **{key: receipt["policy"][key] for key in ("strict_mode", "visible", "returned")}}

    def guess_hash(guessed_detail):
        body = json.dumps({"tenant": receipt["tenant"], "principal": receipt["principal_id"],
                           "action": "recall", "target": receipt["recall_id"], "detail": guessed_detail},
                          sort_keys=True, separators=(",", ":"))
        return hashlib.sha256((row["prev_hash"] + body + repr(row["ts"])).encode()).hexdigest()

    assert all(guess_hash({**known_detail, "denied": guess}) != receipt["audit_row_hash"] for guess in range(65))
    first_blind = json.loads(audit_row(db, first["receipt"])["body"])["detail"]["blind"]
    assert detail["denied"] == 5
    assert detail["blind"] in draws and first_blind in draws
    assert detail["blind"] != first_blind
    surfaces = [first, second, db.recall_receipt(caller.id, second["recall_id"]),
                db.explain_recall(second["recall_id"]), list(db._receipt_cache.values())]
    captured = capsys.readouterr()
    for blind in (first_blind, detail["blind"]):
        assert blind not in json.dumps(surfaces)
        assert blind not in caplog.text + captured.out + captured.err
    # @positive-control(recall-v2-row-hash-blind): true row-only inputs reproduce it.
    assert guess_hash({**known_detail, "denied": detail["denied"], "blind": detail["blind"]}) == receipt["audit_row_hash"]


@pytest.mark.parametrize("filters", [*FILTERS, {"review_states": ["rejected"]}, {"include_expired": False}])
def test_pending_count_uses_policy_not_filters(receipted, filters):
    db, _, _, _ = receipted
    db.remember("Pending visible", subject="subject:pending", created_by="fixture:writer", indexed=False)
    for policy in (
        Policy(classification="confidential"), Policy(roles=("finance",)),
        Policy(attrs=(("department", "finance"),)), Policy(visibility="private"),
    ):
        db.remember("Pending hidden", subject="subject:hidden", created_by="fixture:writer", indexed=False, policy=policy)
    db.remember("Pending capability", subject="subject:contract", created_by="fixture:writer", indexed=False,
                kind="capability-contract", policy_scope="continuity-privileged")
    caller = db.principal("fixture:reader")
    result = db.recall("Recall evidence", principal=caller, filters=filters)
    assert result["index_lag"] == 1
    assert db.explain_recall(result["recall_id"])["index_lag"] == 1
    assert db.store.index_lag(db.tenant) == 5


def test_writer_has_no_v1_switch(receipted, monkeypatch):
    import ast
    import inspect
    import textwrap
    from heartwood import Heartwood

    db, _, _, _ = receipted
    monkeypatch.setenv("HEARTWOOD_RECALL_RECEIPT_VERSION", "v1")
    result = db.recall("Recall evidence", principal=db.principal("fixture:reader"))
    assert result["receipt"]["schema"] == RECALL_SCHEMA == "heartwood.recall-receipt.v2"
    # Schema assignment is unconditional; no flag/argument/env-expression selects v1.
    tree = ast.parse(textwrap.dedent(inspect.getsource(Heartwood.recall)))
    assignments = [value for node in ast.walk(tree) if isinstance(node, ast.Dict)
                   for key, value in zip(node.keys, node.values)
                   if isinstance(key, ast.Constant) and key.value == "schema"]
    assert len(assignments) == 1
    assert isinstance(assignments[0], ast.Name) and assignments[0].id == "RECALL_SCHEMA"


@pytest.mark.parametrize("subject", ["", "subject:hidden"])
def test_registered_mcp_tools_differential(receipted, subject):
    db, _, _, _ = receipted
    server, _db, _backend = build_server(db, principal=Principal("fixture:reader", db.tenant))

    def call(name, arguments):
        output = asyncio.run(server.call_tool(name, arguments))
        if isinstance(output, dict):
            return output
        if isinstance(output, tuple):
            return output[1]
        return json.loads(output[0].text)

    def observe():
        response = call("recall", {"cue": "Recall evidence", "subject": subject, "k": 2})
        assert response["receipt"]["schema"] == RECALL_SCHEMA
        explanation = call("explain_recall", {"recall_id": response["recall_id"]})
        assert "denied" not in json.dumps([response, explanation]).lower()
        blind = json.loads(audit_row(db, response["receipt"])["body"])["detail"]["blind"]
        assert blind not in json.dumps([response, explanation])
        return [stable(response), stable(explanation, explanation=True)]

    baseline = observe()
    add_hidden(db, indexed=True, count=5)
    assert observe() == baseline
    add_hidden(db, indexed=False, count=4)
    assert observe() == baseline
