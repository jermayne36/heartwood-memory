"""Regulated Support Agent demo on governed memory.

Ingest -> handle a ticket under two clearances (provenance-cited answers,
access-governed) -> run a compliance audit -> emit COMPLIANCE_REPORT.md.

Run:  python examples/regulated-support/run_demo.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))  # repo root
sys.path.insert(0, HERE)

from heartwood import Heartwood                          # noqa: E402
from heartwood.envelope import Policy                # noqa: E402
from heartwood.policy import Principal               # noqa: E402

from corpus import corpus                        # noqa: E402
from agent import handle_ticket                  # noqa: E402
from audit import run_compliance_audit           # noqa: E402

TENANT = "tenant:northstar-health"
QUERY = ("Is Jane Doe's recent emergency room visit for chest pain covered, "
         "and are there clinical considerations I should know about?")


def main():
    db = Heartwood(path=":memory:", tenant=TENANT, index=os.environ.get("HEARTWOOD_INDEX", "numpy"))
    print("Engine:", db.info())

    # --- ingest the governed knowledge base ----------------------------- #
    ids = {}
    by_class = {}
    for rec in corpus():
        ids[rec.label] = db.remember(
            rec.content, subject=rec.subject, created_by=rec.created_by, kind=rec.kind,
            epistemic=rec.epistemic, source=rec.source,
            policy=Policy(classification=rec.classification, roles=rec.roles, pii=rec.pii))
        by_class[rec.classification] = by_class.get(rec.classification, 0) + 1
    print(f"\nIngested {len(ids)} governed memories: {by_class}")

    # --- principals ----------------------------------------------------- #
    nurse = Principal(id="agent:nurse", tenant=TENANT, roles=("support", "clinical"),
                      clearance="restricted")
    intern = Principal(id="agent:intern", tenant=TENANT, roles=("support",),
                       clearance="confidential")
    dpo = Principal(id="officer:dpo", tenant=TENANT, roles=("approver",), clearance="restricted")

    # --- handle the same ticket under two clearances -------------------- #
    nurse_res = handle_ticket(db, nurse, "4471", QUERY)
    intern_res = handle_ticket(db, intern, "4471-review", QUERY)

    print("\n--- agent:nurse (clinical) answer ---")
    print(nurse_res["answer_text"])
    print(f"   restricted records used: {len(nurse_res['restricted_used'])}")
    print("\n--- agent:intern (support) answer ---")
    print(intern_res["answer_text"])
    print(f"   restricted records used: {len(intern_res['restricted_used'])}  "
          f"(clinical record correctly withheld)")

    # --- compliance audit (runs erasure last) --------------------------- #
    checks, report = run_compliance_audit(db, ids, nurse_res, intern_res, nurse, intern, dpo)
    print("\n=== COMPLIANCE CHECKS ===")
    for i, (name, ok, detail) in enumerate(checks, 1):
        print(f"  [{ 'PASS' if ok else 'FAIL'}] {i}. {name} — {detail}")

    out_path = os.path.join(HERE, "COMPLIANCE_REPORT.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report)
    passed = sum(1 for _, ok, _ in checks)
    print(f"\nResult: {passed}/{len(checks)} checks passed.")
    print(f"Report written to: {out_path}")
    if passed != len(checks):
        raise SystemExit("DEMO FAILED — not audit-ready")
    print("\nREGULATED SUPPORT AGENT DEMO PASSED — audit-ready.")


if __name__ == "__main__":
    main()
