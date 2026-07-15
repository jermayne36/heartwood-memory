"""End-to-end smoke test for the Heartwood Phase 0 wedge.

Demonstrates: remember -> hybrid recall -> policy-enforced visibility (incl. hard
tenant partition) -> explainRecall (provenance + ranking signals + policy
decisions) -> tamper-evident provenance chain -> trust ceiling -> approve ->
crypto-shred erasure -> audit chain integrity.

Run:  python tests/smoke_test.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Heartwood, Principal, Policy  # noqa: E402

TENANT = "tenant:acme"


def main():
    db = Heartwood(path=":memory:", tenant=TENANT)
    print("info:", db.info())

    # --- remember a mix of classifications/subjects ---------------------- #
    m1 = db.remember("User Jane prefers concise, technical answers.",
                     subject="user:jane", created_by="agent:asst", kind="semantic",
                     epistemic="user-stated", policy=Policy(classification="internal"))
    m2 = db.remember("Jane's bank account number is 99887766; she lives in Berlin.",
                     subject="user:jane", created_by="agent:asst", kind="episodic",
                     epistemic="observed-fact",
                     policy=Policy(classification="restricted", pii=True, roles=("billing",)))
    m3 = db.remember("Jane hinted she is evaluating a competitor product.",
                     subject="user:jane", created_by="agent:asst", kind="episodic",
                     epistemic="inferred-belief",
                     policy=Policy(classification="confidential", roles=("sales",)))
    # a consolidated, model-generated memory that CITES m1 (provenance chain)
    m4 = db.remember("Jane is a technical user who values brevity.",
                     subject="user:jane", created_by="agent:consolidator", kind="semantic",
                     epistemic="model-generated", model_version="gen:claude-x",
                     derived_from=[m1])

    support = Principal(id="agent:asst", tenant=TENANT, roles=("support",), clearance="internal")
    billing = Principal(id="agent:billing", tenant=TENANT, roles=("billing",), clearance="restricted")
    outsider = Principal(id="agent:x", tenant="tenant:evil", roles=("support",), clearance="restricted")

    # --- 1. authorized support recall: sees internal/model-gen, NOT restricted/confidential
    out = db.recall("how should I communicate with Jane?", principal=support,
                    filters={"subject": "user:jane"}, k=5)
    ids = {r["id"] for r in out["results"]}
    assert m1 in ids, "support should see internal memory"
    assert m4 in ids, "support should see model-generated internal memory"
    assert m2 not in ids, "restricted PII must NOT leak to support"
    assert m3 not in ids, "confidential (sales-only) must NOT leak to support"
    print(f"[1] support sees {sorted(ids)} (restricted/confidential correctly hidden)")

    # --- 2. billing has clearance+role for the restricted memory
    out_b = db.recall("what is Jane's account number?", principal=billing,
                      filters={"subject": "user:jane"}, k=5)
    ids_b = {r["id"] for r in out_b["results"]}
    assert m2 in ids_b, "billing should see the restricted memory it is cleared for"
    print(f"[2] billing sees {sorted(ids_b)} (restricted memory authorized)")

    # --- 3. hard tenant partition: outsider sees nothing
    out_o = db.recall("Jane account number", principal=outsider, k=5)
    assert out_o["results"] == [], "cross-tenant recall must return nothing"
    print("[3] cross-tenant recall returned 0 results (hard partition)")

    # --- 4. explainRecall: policy decisions + ranking signals + index freshness
    ex = db.explain_recall(out["recall_id"])
    assert "denied" not in ex and "denied_reasons" not in ex, "public explain must not leak denied counts"
    assert ex["index_lag"] == 0, "synchronous indexing => read-your-writes"
    print(f"[4] explain: considered={ex['candidates_considered']} visible={ex['visible']} "
          f"index_lag={ex['index_lag']}")

    # --- 5. tamper-evident provenance: m4 -> m1, signature valid
    prov = next(r["provenance"] for r in out["results"] if r["id"] == m4)
    assert prov["signature_valid"] is True, "producer signature must verify"
    assert any(p["id"] == m1 for p in prov["derived_from"]), "m4 must cite m1"
    print(f"[5] provenance(m4): epistemic={prov['epistemic']} sig_valid={prov['signature_valid']} "
          f"derived_from={[p['id'] for p in prov['derived_from']]}")

    # --- 6. trust ceiling: cannot self-assert approved-canonical
    try:
        db.remember("x", subject="user:jane", created_by="agent:asst",
                    epistemic="approved-canonical")
        assert False, "approved-canonical via remember must be blocked"
    except PermissionError:
        print("[6] approved-canonical correctly blocked in remember() (requires approve())")

    # approve m1 via an authorized approver
    approver = Principal(id="agent:lead", tenant=TENANT, roles=("approver",), clearance="internal")
    db.approve(m1, approver)
    assert db.store.get_meta(m1)["epistemic"] == "approved-canonical"
    approved = db.recall("concise technical", principal=support,
                         filters={"subject": "user:jane"}, k=5)
    approved_prov = next(r["provenance"] for r in approved["results"] if r["id"] == m1)
    assert approved_prov["signature_valid"] is True, "approval must re-sign the new epistemic class"
    print("[6b] m1 promoted to approved-canonical by approver (audited)")

    # --- 7. crypto-shred erasure (GDPR Art.17): purge + key destruction
    rcpt = db.forget("user:jane", mode="hard", actor="dpo", reason="DSAR",
                     legal_basis="GDPR Art.17")
    assert rcpt["purged"] >= 4 and rcpt["key_shredded"], "erasure must purge + shred key"
    after = db.recall("Jane account number", principal=billing,
                      filters={"subject": "user:jane"}, k=5)
    assert after["results"] == [], "no data may survive erasure"
    key, state = db.store.get_key(TENANT, "user:jane")
    assert state == "shredded" and key is None, "DEK must be destroyed"
    print(f"[7] forget(hard): purged={rcpt['purged']} key_shredded={rcpt['key_shredded']} "
          f"post-erasure recall=0, DEK state={state}")

    # --- 8. audit chain integrity (the erasure event is retained)
    assert db.verify_audit() is True, "audit hash-chain must verify"
    events = [(r["action"], r["target"]) for r in db.store.iter_audit()]
    assert any(a == "forget" for a, _ in events), "erasure event retained in audit"
    print(f"[8] audit chain verified; {len(events)} events (forget event retained)")

    print("\nALL SMOKE TESTS PASSED")


if __name__ == "__main__":
    main()
