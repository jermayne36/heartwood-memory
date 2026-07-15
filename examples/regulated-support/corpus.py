"""A small regulated knowledge base + member records for the demo.

Scenario: a health-plan member-support agent. The corpus mixes:
  - policy documents (imported-source, internal/public) — citable knowledge
  - member PII records (observed-fact, confidential) — access-controlled
  - one clinical record (restricted, clinical-role only) — the sensitive one

Each record has a `label` so the demo/audit can assert on specific memories.
Keywords are deliberately distinct so retrieval works even with the
dependency-free fallback embedder.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Record:
    label: str
    content: str
    subject: str
    created_by: str
    kind: str
    epistemic: str
    classification: str
    roles: tuple = ()
    pii: bool = False
    source: dict = None


def corpus() -> list[Record]:
    POL = "ingest:policy-loader"
    INTAKE = "ingest:claims-intake"
    CLIN = "ingest:clinical-feed"

    def src(uri):
        return {"kind": "document", "uri": uri}

    return [
        # --- policies (citable knowledge) ------------------------------- #
        Record("POLICY_ER",
               "Emergency room visits for chest pain are covered when medically necessary; "
               "prior authorization is waived for true emergencies.",
               "kb:coverage", POL, "semantic", "imported-source", "public", (),
               False, src("policy://coverage/emergency-v3#sec2")),
        Record("POLICY_APPEAL",
               "Members may appeal a denied or pending claim within 60 days by submitting form A-12.",
               "kb:coverage", POL, "semantic", "imported-source", "public", (),
               False, src("policy://appeals/process-v2#sec1")),
        Record("POLICY_OON",
               "Out-of-network provider coverage requires prior authorization except for emergencies.",
               "kb:coverage", POL, "semantic", "imported-source", "internal", (),
               False, src("policy://coverage/out-of-network-v1")),
        Record("POLICY_REFUND",
               "Overpayment refunds are issued to the original payment method within 14 business days.",
               "kb:billing", POL, "semantic", "imported-source", "internal", (),
               False, src("policy://billing/refunds-v4")),

        # --- member Jane Doe (PII) -------------------------------------- #
        Record("JANE_PROFILE",
               "Member Jane Doe, plan Gold-PPO, member id M-77310, effective 2025-01-01.",
               "member:jane", INTAKE, "episodic", "observed-fact", "confidential",
               ("support",), True, src("record://members/M-77310/profile")),
        Record("JANE_CLAIM",
               "Jane Doe emergency room claim C-99812 on 2026-05-20 for chest pain, "
               "billed $3,400, status: pending review.",
               "member:jane", INTAKE, "episodic", "observed-fact", "confidential",
               ("support",), True, src("record://members/M-77310/claims/C-99812")),
        Record("JANE_DX",
               "Clinical note: Jane Doe diagnosed with atrial fibrillation; currently on "
               "anticoagulant therapy (warfarin). Monitor for drug interactions.",
               "member:jane", CLIN, "episodic", "observed-fact", "restricted",
               ("clinical",), True, src("record://members/M-77310/clinical/note-5571")),

        # --- another member (distractor + erasure-isolation check) ------ #
        Record("BOB_PROFILE",
               "Member Bob Stone, plan Silver-HMO, member id M-44120, effective 2024-07-01.",
               "member:bob", INTAKE, "episodic", "observed-fact", "confidential",
               ("support",), True, src("record://members/M-44120/profile")),
    ]
