"""The five ratified probe classes for the trust-receipts benchmark.

Each probe returns a ProbeResult. Guarantee/positive-control cases must match
their documented contract or the probe FAILs (a real defect to report, never to
fix here). Boundary cases publish Heartwood's own documented limits and never
fail the probe — they are the "publish our own boundaries too" posture.

All measurement is against the installed release through the adapter interface;
no probe reaches into Heartwood internals except through the adapter's declared
adversary operations (which simulate an at-rest / database-write attacker).
"""
from __future__ import annotations

from . import fixtures as fx
from .adapters.base import AdapterNotAvailable, MemoryAdapter
from .model import (
    BOUNDARY,
    CONTRACT,
    POSITIVE_CONTROL,
    Case,
    ProbeResult,
    make_probe,
    skipped_probe,
)

_LOW_READER = {"id": "agent:reader", "roles": (), "clearance": "internal"}
_LEGAL_READER = {"id": "agent:legal", "roles": ("legal",), "clearance": "confidential"}
_REVIEWER = {"id": "agent:reviewer", "roles": ("reviewer",), "clearance": "internal"}
_ALL_REVIEW = ["disputed", "rejected", "superseded", "proposed"]


def run_forgery(adapter: MemoryAdapter) -> ProbeResult:
    cls, receipt = "forgery_injection", "Signed provenance"
    rec = fx.FORGERY_RECORD
    try:
        cases: list[Case] = []

        with adapter.session(strict="off", durable_custody=True) as s:
            _write(s, rec)
            s.adv_flip_content_hash(rec["memory_id"])
            v = s.recall(rec["cue"], reader=_LOW_READER)
            h = v.hit(rec["memory_id"])
            cases.append(Case(
                "forgery_off_content_hash", CONTRACT,
                "A tampered content hash is surfaced as invalid at read (OFF mode).",
                "record present with content_hash_match=False and signature_valid=False",
                {"retrieved": h is not None,
                 "content_hash_match": h and h["content_hash_match"],
                 "signature_valid": h and h["signature_valid"]},
                bool(h) and h["content_hash_match"] is False
                and h["signature_valid"] is False,
                "content_provenance_authenticity"))

        with adapter.session(strict="off", durable_custody=True) as s:
            _write(s, rec)
            s.adv_forge_signature(rec["memory_id"])
            v = s.recall(rec["cue"], reader=_LOW_READER)
            h = v.hit(rec["memory_id"])
            cases.append(Case(
                "forgery_off_forged_signature", CONTRACT,
                "A forged producer signature fails verification and is surfaced.",
                "record present with signature_valid=False",
                {"retrieved": h is not None,
                 "signature_valid": h and h["signature_valid"]},
                bool(h) and h["signature_valid"] is False,
                "content_provenance_authenticity"))

        with adapter.session(strict="enforce", durable_custody=True) as s:
            _write(s, rec)
            s.adv_flip_content_hash(rec["memory_id"])
            v = s.recall(rec["cue"], reader=_LOW_READER)
            cases.append(Case(
                "forgery_enforce_fails_closed", CONTRACT,
                "Strict ENFORCE fails the recall closed when a returnable record "
                "fails verification.",
                "recall raises StrictSignatureError naming the tampered id",
                {"raised": v.raised, "dropped_ids": v.strict_dropped_ids},
                v.raised == "StrictSignatureError"
                and rec["memory_id"] in v.strict_dropped_ids,
                "content_provenance_authenticity"))

        with adapter.session(strict="filter", durable_custody=True) as s:
            _write(s, rec)
            s.adv_flip_content_hash(rec["memory_id"])
            v = s.recall(rec["cue"], reader=_LOW_READER)
            absent = v.hit(rec["memory_id"]) is None
            cases.append(Case(
                "forgery_filter_drops_and_counts", CONTRACT,
                "Strict FILTER drops the failing record and counts it (loud, not "
                "silent).",
                "record absent from results and present in strict_dropped ids",
                {"absent_from_results": absent,
                 "strict_dropped_ids": v.strict_dropped_ids},
                absent and rec["memory_id"] in v.strict_dropped_ids,
                "content_provenance_authenticity"))

        with adapter.session(strict="off", durable_custody=True) as s:
            # Store confidential+legal so a cleared reader still retrieves it after
            # a downgrade; isolates "signature covers content, not metadata".
            s.remember(memory_id=rec["memory_id"], subject=rec["subject"],
                       content=rec["content"], classification="confidential",
                       role_gate=("legal",))
            s.adv_flip_unsigned_field(rec["memory_id"], "classification", "internal")
            v = s.recall(rec["cue"], reader=_LEGAL_READER)
            h = v.hit(rec["memory_id"])
            cases.append(Case(
                "forgery_boundary_unsigned_metadata", BOUNDARY,
                "Provenance signs (id, content_hash, source.uri, created_by, "
                "epistemic) only; a metadata edit is not detected by signature "
                "verification. Documented non-claim (see docs/api/continuity.md).",
                "signature_valid=True and content_hash_match=True despite a "
                "classification downgrade (measured boundary, not a defect)",
                {"retrieved": h is not None,
                 "signature_valid": h and h["signature_valid"],
                 "content_hash_match": h and h["content_hash_match"],
                 "classification_now": h and h["classification"]},
                bool(h) and h["signature_valid"] is True
                and h["content_hash_match"] is True,
                "NOT_CLAIMED:authorization_integrity"))

        return make_probe(cls, receipt, cases)
    except AdapterNotAvailable as exc:
        return skipped_probe(cls, receipt, str(exc), adapter.requirements())


def run_policy_leak(adapter: MemoryAdapter) -> ProbeResult:
    cls, receipt = "policy_leak", "Policy before ranking"
    pub, conf = fx.PUBLIC_RECORD, fx.CONFIDENTIAL_RECORD
    needle = "board-restricted"
    try:
        cases: list[Case] = []

        with adapter.session(strict="off") as s:
            _write(s, pub)
            s.remember(memory_id=conf["memory_id"], subject=conf["subject"],
                       content=conf["content"], classification="confidential",
                       role_gate=conf["role_gate"])

            v = s.recall(conf["cue"], reader=_LOW_READER)
            leaked = v.hit(conf["memory_id"]) is not None or v.contains_text(needle)
            cases.append(Case(
                "policy_leak_adversarial_cue", CONTRACT,
                "An adversarial cue targeting confidential content does not leak "
                "it to an under-cleared reader.",
                "confidential record absent from results; content not present",
                {"confidential_in_results": v.hit(conf["memory_id"]) is not None,
                 "text_leaked": v.contains_text(needle),
                 "result_ids": v.ids},
                not leaked,
                "policy_before_ranking"))

            v2 = s.recall(conf["cue"], reader=_LOW_READER)
            cases.append(Case(
                "policy_leak_denial_audited_not_surfaced", CONTRACT,
                "The denial is recorded on the audit log (operator-visible) but "
                "not surfaced in the caller result set (constant shape).",
                "audit denied>=1 while confidential record absent from results",
                {"denied_in_audit": v2.denied,
                 "confidential_in_results": v2.hit(conf["memory_id"]) is not None},
                bool(v2.denied) and v2.denied >= 1
                and v2.hit(conf["memory_id"]) is None,
                "policy_before_ranking"))

            v3 = s.recall(conf["cue"], reader=_LOW_READER,
                          filters={"allowed_classifications":
                                   ["confidential", "restricted"]})
            cases.append(Case(
                "policy_leak_filter_cannot_escalate", CONTRACT,
                "Caller filters only narrow the candidate set; they cannot widen "
                "past the principal's clearance.",
                "confidential record still absent when caller passes "
                "allowed_classifications including 'confidential'",
                {"confidential_in_results": v3.hit(conf["memory_id"]) is not None,
                 "text_leaked": v3.contains_text(needle)},
                v3.hit(conf["memory_id"]) is None and not v3.contains_text(needle),
                "policy_before_ranking"))

            v4 = s.recall(conf["cue"], reader=_LEGAL_READER)
            cases.append(Case(
                "policy_positive_control_cleared_reader", POSITIVE_CONTROL,
                "A properly cleared principal (legal role, confidential clearance) "
                "does retrieve the confidential record.",
                "confidential record present for the cleared reader",
                {"confidential_in_results": v4.hit(conf["memory_id"]) is not None},
                v4.hit(conf["memory_id"]) is not None,
                "policy_before_ranking"))

        with adapter.session(strict="off") as s:
            s.remember(memory_id=conf["memory_id"], subject=conf["subject"],
                       content=conf["content"], classification="confidential",
                       role_gate=conf["role_gate"])
            s.adv_flip_unsigned_field(conf["memory_id"], "classification", "internal")
            s.adv_flip_unsigned_field(conf["memory_id"], "roles_json", "[]")
            v = s.recall(conf["cue"], reader=_LOW_READER)
            reached = v.hit(conf["memory_id"]) is not None or v.contains_text(needle)
            cases.append(Case(
                "policy_leak_boundary_db_write_downgrade", BOUNDARY,
                "Recall authorization runs on unsigned mutable metadata "
                "(classification, roles); a database-write attacker can downgrade "
                "it and reach the record. Documented non-claim under the "
                "single-trust-domain assumption (see docs/api/continuity.md).",
                "under-cleared reader reaches the record after a raw metadata "
                "downgrade (measured boundary, not a recall-time defect)",
                {"reached_after_downgrade": reached, "result_ids": v.ids},
                reached,
                "NOT_CLAIMED:authorization_integrity"))

        return make_probe(cls, receipt, cases)
    except AdapterNotAvailable as exc:
        return skipped_probe(cls, receipt, str(exc), adapter.requirements())


def run_tamper(adapter: MemoryAdapter) -> ProbeResult:
    cls, receipt = "audit_tamper_detection", "Tamper-evident audit"
    recs = [fx.PUBLIC_RECORD, fx.FORGERY_RECORD, fx.RETIREMENT_RECORD]
    try:
        cases: list[Case] = []

        with adapter.session(strict="off") as s:
            for i, r in enumerate(recs):
                _write(s, r, suffix=f"_tamper_a{i}")
            before = s.verify_audit()
            s.adv_edit_audit_body_inplace()
            after = s.verify_audit()
            cases.append(Case(
                "tamper_inplace_edit_detected", CONTRACT,
                "An in-place edit of an audit row body is detected by "
                "verify_audit().",
                "verify_audit() True before, False after the edit",
                {"before": before, "after": after},
                before is True and after is False, "tamper_evidence"))

        with adapter.session(strict="off") as s:
            for i, r in enumerate(recs):
                _write(s, r, suffix=f"_tamper_b{i}")
            s.adv_drop_interior_audit_row()
            cases.append(Case(
                "tamper_interior_drop_detected", CONTRACT,
                "Dropping an interior audit row breaks the hash chain and is "
                "detected.",
                "verify_audit() False after the interior row is dropped",
                {"after": s.verify_audit()},
                s.verify_audit() is False, "tamper_evidence"))

        with adapter.session(strict="off") as s:
            for i, r in enumerate(recs):
                _write(s, r, suffix=f"_tamper_c{i}")
            s.anchor()
            s.adv_truncate_audit_tail(1)
            chain_only = s.verify_audit()
            receipt_anchor = s.verify_against_anchors()
            cases.append(Case(
                "tamper_tail_truncation_chain_boundary", BOUNDARY,
                "The in-database chain alone cannot see tail-truncation: the "
                "surviving prefix still hashes consistently. Documented boundary "
                "(README: 'tail-truncation needs an external anchor').",
                "verify_audit() stays True after the last row is truncated "
                "(measured boundary)",
                {"chain_only_verify": chain_only},
                chain_only is True, "tamper_evidence"))
            cases.append(Case(
                "tamper_tail_truncation_anchor_detects", CONTRACT,
                "With an external anchor, the same tail-truncation is detected.",
                "verify_against_anchors() reports ok=False while chain_ok=True",
                {"anchor_ok": receipt_anchor.get("ok"),
                 "chain_ok": receipt_anchor.get("chain_ok"),
                 "anchor_status": receipt_anchor.get("anchor_status")},
                receipt_anchor.get("ok") is False
                and receipt_anchor.get("chain_ok") is True,
                "tamper_evidence"))

        with adapter.session(strict="off") as s:
            for i, r in enumerate(recs):
                _write(s, r, suffix=f"_tamper_d{i}")
            s.anchor()
            cases.append(Case(
                "tamper_positive_control_clean_chain", POSITIVE_CONTROL,
                "An untouched chain verifies and its anchor verification passes.",
                "verify_audit() True and verify_against_anchors() ok=True",
                {"chain": s.verify_audit(),
                 "anchor_ok": s.verify_against_anchors().get("ok")},
                s.verify_audit() is True
                and s.verify_against_anchors().get("ok") is True,
                "tamper_evidence"))

        return make_probe(cls, receipt, cases)
    except AdapterNotAvailable as exc:
        return skipped_probe(cls, receipt, str(exc), adapter.requirements())


def run_retirement(adapter: MemoryAdapter) -> ProbeResult:
    cls, receipt = "record_retirement", "Recall visibility and retirement"
    base = fx.RETIREMENT_RECORD
    adversarial = {"include_expired": True, "include_review_states": _ALL_REVIEW}
    try:
        cases: list[Case] = []
        with adapter.session(strict="off") as s:
            # (a) unindex — hardest gate, no opt-in reaches it.
            a = _mk(base, "_ret_unindex")
            _write(s, a)
            s.set_indexed(a["memory_id"], False)
            d_default = s.recall(a["cue"], reader=_LOW_READER).hit(a["memory_id"])
            d_optin = s.recall(a["cue"], reader=_LOW_READER,
                               filters=adversarial).hit(a["memory_id"])
            cases.append(Case(
                "retire_unindex_removes_from_corpus", CONTRACT,
                "set_indexed(False) removes a record from the answerable corpus; "
                "no opt-in or back-dated filter reaches it.",
                "record absent from default recall AND from an opt-in "
                "(include_expired + all review states) recall",
                {"in_default": d_default is not None, "in_optin": d_optin is not None},
                d_default is None and d_optin is None, "auditable_retirement"))

            # (b) expire — reversible, reachable via include_expired.
            b = _mk(base, "_ret_expire")
            _write(s, b)
            s.expire(b["memory_id"], "2020-01-01T00:00:00Z")
            e_default = s.recall(b["cue"], reader=_LOW_READER).hit(b["memory_id"])
            e_incl = s.recall(b["cue"], reader=_LOW_READER,
                              filters={"include_expired": True}).hit(b["memory_id"])
            cases.append(Case(
                "retire_expire_default_hidden_optin_visible", CONTRACT,
                "expire() removes a record from default recall but keeps it "
                "reachable via include_expired.",
                "absent by default, present with include_expired=True",
                {"in_default": e_default is not None, "in_include_expired": e_incl is not None},
                e_default is None and e_incl is not None, "auditable_retirement"))

            # (c) supersede — hidden review state, recoverable explicitly. The
            # record must enter the review workflow before it can be superseded.
            c = _mk(base, "_ret_supersede")
            s.remember(memory_id=c["memory_id"], subject=c["subject"],
                       content=c["content"], review_state="accepted")
            s.supersede(c["memory_id"], reviewer=_REVIEWER)
            su_default = s.recall(c["cue"], reader=_LOW_READER).hit(c["memory_id"])
            su_incl = s.recall(
                c["cue"], reader=_LOW_READER,
                filters={"include_review_states": ["superseded"]}).hit(c["memory_id"])
            cases.append(Case(
                "retire_supersede_default_hidden_optin_visible", CONTRACT,
                "transition_review(superseded) hides a record from default recall "
                "but keeps it reachable via include_review_states.",
                "absent by default, present with include_review_states=[superseded]",
                {"in_default": su_default is not None,
                 "in_include_superseded": su_incl is not None},
                su_default is None and su_incl is not None, "auditable_retirement"))

            # (d) every retirement is audited and the chain still verifies.
            audited = s.audit_action_present(a["memory_id"], "index_state")
            cases.append(Case(
                "retire_is_audited_and_chain_valid", CONTRACT,
                "Each retirement writes an audit event and the hash chain still "
                "verifies.",
                "index_state audit event present for the unindexed record and "
                "verify_audit() True",
                {"index_state_audited": audited, "chain": s.verify_audit()},
                audited is True and s.verify_audit() is True, "auditable_retirement"))

            # (e) boundary: a raw column write bypasses the audited verb.
            b2 = _mk(base, "_ret_rawbypass")
            _write(s, b2)
            s.adv_raw_unindex(b2["memory_id"])
            gone = s.recall(b2["cue"], reader=_LOW_READER).hit(b2["memory_id"]) is None
            unaudited = not s.audit_action_present(b2["memory_id"], "index_state")
            cases.append(Case(
                "retire_boundary_raw_write_unaudited", BOUNDARY,
                "A direct UPDATE to `indexed` bypasses set_indexed() and removes "
                "the record from recall with nothing on the audit log. Documented "
                "boundary (docs: 'direct column writes are a policy violation').",
                "record gone from recall AND no index_state audit event for it "
                "(measured boundary, not a defect)",
                {"gone_from_recall": gone, "no_audit_event": unaudited},
                gone and unaudited, "NOT_CLAIMED:tamper_proof_rbac_or_visibility"))

        return make_probe(cls, receipt, cases)
    except AdapterNotAvailable as exc:
        return skipped_probe(cls, receipt, str(exc), adapter.requirements())


def run_erasure(adapter: MemoryAdapter) -> ProbeResult:
    cls, receipt = "erasure_receipts", "Key-destruction receipt"
    rec = fx.ERASURE_RECORD
    try:
        cases: list[Case] = []
        with adapter.session(strict="off", durable_custody=False) as s:
            _write(s, rec)
            before = s.erase_proof(root_present=False)
            forget_receipt = s.forget(rec["subject"])
            cases.append(Case(
                "erasure_forget_shreds_key", CONTRACT,
                "forget(mode=hard) returns a key-destruction receipt and purges "
                "derived artifacts.",
                "key_shredded=True and purged>=1",
                {"key_shredded": forget_receipt.get("key_shredded"),
                 "purged": forget_receipt.get("purged")},
                forget_receipt.get("key_shredded") is True
                and (forget_receipt.get("purged") or 0) >= 1,
                "content_provenance_authenticity"))

            gone = s.recall(rec["cue"], reader=_LOW_READER).hit(rec["memory_id"])
            cases.append(Case(
                "erasure_content_unreachable_after_forget", CONTRACT,
                "After a hard forget the subject's content is no longer returned "
                "by recall.",
                "record absent from recall after forget",
                {"in_recall": gone is not None,
                 "raw_active_keys_before": before.get("raw_active_key_count")},
                gone is None, "content_provenance_authenticity"))

            proof = s.erase_proof(root_present=False)
            cases.append(Case(
                "erasure_crypto_erase_proof", CONTRACT,
                "prove_crypto_erase_path reports the subject key shredded and, "
                "with the root absent, content unrecoverable.",
                "content_unrecoverable=True, proved=True, raw_active_key_count=0, "
                "shredded_key_count>=1",
                {"content_unrecoverable": proof.get("content_unrecoverable"),
                 "proved": proof.get("proved"),
                 "raw_active_key_count": proof.get("raw_active_key_count"),
                 "shredded_key_count": proof.get("shredded_key_count")},
                proof.get("content_unrecoverable") is True
                and proof.get("proved") is True
                and proof.get("raw_active_key_count") == 0
                and (proof.get("shredded_key_count") or 0) >= 1,
                "content_provenance_authenticity"))

            audited = s.audit_action_present(rec["subject"], "forget")
            cases.append(Case(
                "erasure_event_retained_and_chain_valid", CONTRACT,
                "The erasure event is retained on the hash chain even after the "
                "payload is shredded, and the chain still verifies.",
                "forget audit event present and verify_audit() True",
                {"forget_audited": audited, "chain": s.verify_audit()},
                audited is True and s.verify_audit() is True,
                "content_provenance_authenticity"))

            proof_root = s.erase_proof(root_present=True)
            cases.append(Case(
                "erasure_boundary_conditional_on_root_absence", BOUNDARY,
                "The proof is conditional: with the wrapping root still present it "
                "does not assert unrecoverability. This is key-destruction "
                "evidence, not byte-level content deletion (documented boundary).",
                "content_unrecoverable=False when root_present=True (measured "
                "boundary, not a defect)",
                {"content_unrecoverable": proof_root.get("content_unrecoverable"),
                 "reason": proof_root.get("reason")},
                proof_root.get("content_unrecoverable") is False,
                "NOT_CLAIMED:db_compromise_resistance"))

        return make_probe(cls, receipt, cases)
    except AdapterNotAvailable as exc:
        return skipped_probe(cls, receipt, str(exc), adapter.requirements())


# --- helpers --------------------------------------------------------------- #
def _write(session, rec, *, suffix="") -> str:
    return session.remember(
        memory_id=rec["memory_id"] + suffix,
        subject=rec["subject"],
        content=rec["content"],
        classification=rec.get("classification", "internal"),
        role_gate=rec.get("role_gate", ()),
    )


def _mk(rec: dict, suffix: str) -> dict:
    clone = dict(rec)
    clone["memory_id"] = rec["memory_id"] + suffix
    return clone


ALL_PROBES = [
    run_forgery,
    run_policy_leak,
    run_tamper,
    run_retirement,
    run_erasure,
]
