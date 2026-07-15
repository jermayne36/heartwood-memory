"""Role-AND inheritance: a memory derived from multiple restricted sources must
require ALL of their role gates (conjunction), not just one.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Policy, Principal, Heartwood          # noqa: E402
from heartwood.policy import PolicyEnforcer              # noqa: E402

T = "tenant:acme"


def main():
    db = Heartwood(path=":memory:", tenant=T)
    enf = PolicyEnforcer()

    a = db.remember("clinical source: atrial fibrillation", subject="s:a", created_by="ag",
                    policy=Policy(classification="restricted", roles=("clinical",)))
    b = db.remember("billing source: invoice 8841", subject="s:b", created_by="ag",
                    policy=Policy(classification="confidential", roles=("billing",)))

    # derived from BOTH -> must require clinical AND billing, classification = restricted
    c = db.remember("synthesis combining the clinical and billing sources",
                    subject="ticket:1", created_by="ag", epistemic="model-generated",
                    derived_from=[a, b])
    mc = db.store.get_meta(c)
    assert mc["classification"] == "restricted", mc["classification"]
    assert set(mc["role_groups"]) == {("billing",), ("clinical",)}, mc["role_groups"]

    both = Principal("p:both", T, roles=("clinical", "billing"), clearance="restricted")
    only_c = Principal("p:c", T, roles=("clinical",), clearance="restricted")
    only_b = Principal("p:b", T, roles=("billing",), clearance="restricted")

    assert enf.visible(both, mc)[0] is True, "principal with both roles must see it"
    assert enf.visible(only_c, mc)[0] is False, "clinical-only must be denied (needs billing too)"
    assert enf.visible(only_b, mc)[0] is False, "billing-only must be denied (needs clinical too)"
    print("[1] AND across parents: both-roles allowed; clinical-only and billing-only denied")

    # derived from ONE source -> single gate still works
    d = db.remember("note derived only from the clinical source", subject="ticket:2",
                    created_by="ag", epistemic="model-generated", derived_from=[a])
    md = db.store.get_meta(d)
    assert set(md["role_groups"]) == {("clinical",)} and md["classification"] == "restricted"
    assert enf.visible(only_c, md)[0] is True and enf.visible(only_b, md)[0] is False
    print("[2] single-parent inheritance unchanged (clinical gate only)")

    # recall respects it: only_c must not retrieve the dual-gated synthesis
    out = db.recall("synthesis clinical billing", principal=only_c, k=20)
    assert all(r["id"] != c for r in out["results"]), "dual-gated memory leaked to clinical-only"
    out2 = db.recall("synthesis clinical billing", principal=both, k=20)
    assert any(r["id"] == c for r in out2["results"]), "both-roles should retrieve it"
    print("[3] recall enforces AND gate (clinical-only excluded, both-roles included)")

    print("\nROLE-AND INHERITANCE TESTS PASSED")


if __name__ == "__main__":
    main()
