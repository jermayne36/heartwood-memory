"""Storage, signing, and audit wiring for continuity measured diffs.

Receipt verification trusts the existing ``Signer`` verification-key registry.
That registry lives in the mutable Heartwood store. Operators that need a
stronger trust boundary must pin or custody the verification root outside that
store, and durable cross-process signing requires Heartwood's durable key
custodian. This module does not add a second key system.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

from ..audit import AuditLog
from ..envelope import Policy, hash_content
from ..policy import Principal
from ..provenance import verify_meta
from .schema import (
    RECEIPT_SIGNATURE_DOMAIN,
    RECEIPT_SIGNING_VERSION,
    BaselineBinding,
    CapabilityContract,
    ContractBinding,
    GenesisMarker,
    RotationReceiptDraft,
    SignedRotationReceipt,
    canonical_bytes,
    canonical_json,
    content_hash,
    validate_principal_id,
)


CONTINUITY_ADMIN_ROLE = "continuity-admin"
CONTINUITY_CONTRACT_KIND = "capability-contract"
CONTINUITY_POLICY_SCOPE = "continuity-privileged"
ROTATION_RECEIPT_AUDIT_ACTION = "continuity_rotation_receipt"


class ContinuityIntegrityError(RuntimeError):
    """A stored contract or signed measured diff failed integrity checks."""


@dataclass(frozen=True)
class StoredCapabilityContract:
    memory_id: str
    route_id: str
    schema_version: str
    contract_hash: str
    indexed: bool = False


class Continuity:
    """Privileged contract storage plus signed, audit-bound measured diffs."""

    def __init__(self, heartwood):
        self.heartwood = heartwood

    def store_capability_contract(
        self,
        contract: CapabilityContract | Mapping[str, Any],
        *,
        principal: Principal,
    ) -> StoredCapabilityContract:
        """Store a signed contract outside every ordinary recall corpus."""
        self._require_admin(principal)
        parsed = (
            contract
            if isinstance(contract, CapabilityContract)
            else CapabilityContract.from_dict(contract)
        )
        payload = canonical_json(parsed.to_dict())
        memory_id = self.heartwood.remember(
            payload,
            subject=f"continuity-contract:{parsed.contract_hash.removeprefix('sha256:')}",
            created_by=principal.id,
            kind=CONTINUITY_CONTRACT_KIND,
            epistemic="imported-source",
            confidence=1.0,
            salience=0.0,
            source={
                "kind": CONTINUITY_CONTRACT_KIND,
                "uri": (
                    "heartwood://continuity/contracts/"
                    + parsed.contract_hash.removeprefix("sha256:")
                ),
            },
            policy=Policy(
                visibility="tenant",
                classification="confidential",
                roles=(CONTINUITY_ADMIN_ROLE,),
            ),
            policy_scope=CONTINUITY_POLICY_SCOPE,
            indexed=False,
        )
        meta = self.heartwood.store.get_meta(memory_id)
        if meta is None or meta["indexed"]:
            raise ContinuityIntegrityError("capability contract indexing boundary failed")
        return StoredCapabilityContract(
            memory_id=memory_id,
            route_id=parsed.route_id,
            schema_version=parsed.schema_version,
            contract_hash=parsed.contract_hash,
        )

    def get_capability_contract(
        self,
        memory_id: str,
        *,
        principal: Principal,
    ) -> CapabilityContract:
        """Retrieve a contract only through the dedicated privileged API."""
        self._require_admin(principal)
        meta = self.heartwood.store.get_meta(memory_id)
        if not self._is_contract_meta(meta):
            raise KeyError("unknown capability contract")
        visible, _reason = self.heartwood.enforcer.visible(principal, meta)
        if not visible:
            raise PermissionError("capability contract access denied")
        return self._contract_from_meta(meta)

    def issue_rotation_receipt(
        self,
        draft: RotationReceiptDraft | Mapping[str, Any],
        *,
        principal: Principal,
    ) -> SignedRotationReceipt:
        """Sign and audit one measured diff without persisting its rich body."""
        self._require_admin(principal)
        parsed = (
            draft
            if isinstance(draft, RotationReceiptDraft)
            else RotationReceiptDraft.from_dict(draft)
        )
        self._require_stored_binding(parsed.from_contract)
        self._require_stored_binding(parsed.to_contract)
        audit = AuditLog(self.heartwood.store)
        if not audit.verify_chain():
            raise ContinuityIntegrityError("rotation receipt audit chain invalid")
        lineage_hash = self._route_lineage_hash(parsed)
        if not self._baseline_valid(
            parsed.prior_baseline,
            lineage_hash=lineage_hash,
        ):
            raise ContinuityIntegrityError("rotation receipt prior baseline invalid")

        # Registration may persist the public key, so it must complete before
        # append_bound opens the audit write transaction.
        self.heartwood.signer.register(principal.id)
        receipt_box: dict[str, SignedRotationReceipt] = {}

        def build_detail(audit_seq: int) -> dict[str, str]:
            if (
                isinstance(parsed.prior_baseline, BaselineBinding)
                and parsed.prior_baseline.audit_seq >= audit_seq
            ):
                raise ContinuityIntegrityError(
                    "rotation receipt prior baseline ordering invalid"
                )
            unsigned_payload = {
                **parsed.to_dict(),
                "signing_version": RECEIPT_SIGNING_VERSION,
                "signed_by": principal.id,
                "audit_seq": audit_seq,
            }
            receipt_hash = content_hash(unsigned_payload)
            signable_payload = {
                **unsigned_payload,
                "receipt_hash": receipt_hash,
            }
            signature = self.heartwood.signer.sign_detached(
                principal.id,
                canonical_bytes(signable_payload),
                domain=RECEIPT_SIGNATURE_DOMAIN,
            )
            receipt = SignedRotationReceipt(
                draft=parsed,
                signing_version=RECEIPT_SIGNING_VERSION,
                signed_by=principal.id,
                audit_seq=audit_seq,
                receipt_hash=receipt_hash,
                signature=signature,
            )
            receipt_box["receipt"] = receipt
            return {
                "receipt_hash": receipt.receipt_hash,
                "lineage_hash": lineage_hash,
                "status": receipt.draft.evidence_mode.value,
            }

        transition = self.heartwood.audit.append_bound(
            self.heartwood.tenant,
            principal.id,
            ROTATION_RECEIPT_AUDIT_ACTION,
            parsed.receipt_id,
            build_detail,
        )
        receipt = receipt_box.get("receipt")
        if receipt is None or transition["seq"] != receipt.audit_seq:
            raise ContinuityIntegrityError("rotation receipt audit binding failed")
        return receipt

    def verify_rotation_receipt(
        self,
        receipt: SignedRotationReceipt | Mapping[str, Any],
    ) -> dict[str, Any]:
        """Verify signature, current audit binding/chain, and prior baseline."""
        try:
            parsed = (
                receipt
                if isinstance(receipt, SignedRotationReceipt)
                else SignedRotationReceipt.from_dict(receipt)
            )
        except (TypeError, ValueError):
            return {
                "ok": False,
                "signature_valid": False,
                "audit_event_valid": False,
                "audit_chain_valid": False,
                "baseline_valid": False,
            }

        signature_valid = self.heartwood.signer.verify_detached(
            parsed.signature,
            parsed.signed_by,
            canonical_bytes(parsed.signable_payload()),
            domain=RECEIPT_SIGNATURE_DOMAIN,
        )
        row = self.heartwood.store.audit_row(parsed.audit_seq)
        audit_event_valid = self._audit_row_matches_receipt(row, parsed)
        audit_chain_valid = AuditLog(self.heartwood.store).verify_chain()
        baseline_valid = self._baseline_valid(
            parsed.draft.prior_baseline,
            lineage_hash=self._route_lineage_hash(parsed.draft),
            current_audit_seq=parsed.audit_seq,
        )
        return {
            "ok": (
                signature_valid
                and audit_event_valid
                and audit_chain_valid
                and baseline_valid
            ),
            "signature_valid": signature_valid,
            "audit_event_valid": audit_event_valid,
            "audit_chain_valid": audit_chain_valid,
            "baseline_valid": baseline_valid,
            "receipt_id": parsed.draft.receipt_id,
            "receipt_hash": parsed.receipt_hash,
        }

    def _baseline_valid(
        self,
        baseline: BaselineBinding | GenesisMarker,
        *,
        lineage_hash: str,
        current_audit_seq: int | None = None,
    ) -> bool:
        if isinstance(baseline, GenesisMarker):
            return not self._earlier_lineage_receipt_exists(
                lineage_hash,
                before_seq=current_audit_seq,
            )
        if current_audit_seq is not None and baseline.audit_seq >= current_audit_seq:
            return False
        row = self.heartwood.store.audit_row(baseline.audit_seq)
        if row is None:
            return False
        try:
            body = json.loads(row["body"])
        except (TypeError, json.JSONDecodeError):
            return False
        return (
            row["tenant"] == self.heartwood.tenant
            and row["action"] == ROTATION_RECEIPT_AUDIT_ACTION
            and row["target"] == baseline.receipt_id
            and body.get("detail", {}).get("receipt_hash") == baseline.receipt_hash
        )

    def _earlier_lineage_receipt_exists(
        self,
        lineage_hash: str,
        *,
        before_seq: int | None,
    ) -> bool:
        for row in self.heartwood.store.iter_audit():
            if before_seq is not None and row["seq"] >= before_seq:
                continue
            if row["action"] != ROTATION_RECEIPT_AUDIT_ACTION:
                continue
            try:
                detail = json.loads(row["body"]).get("detail", {})
            except (TypeError, json.JSONDecodeError):
                continue
            if detail.get("lineage_hash") == lineage_hash:
                return True
        return False

    @staticmethod
    def _route_lineage_hash(draft: RotationReceiptDraft) -> str:
        return content_hash(
            {
                "from_route": draft.from_route,
                "to_route": draft.to_route,
            }
        )

    def _require_admin(self, principal: Principal) -> None:
        if not isinstance(principal, Principal):
            raise PermissionError("continuity access denied")
        validate_principal_id(principal.id)
        if (
            principal.tenant != self.heartwood.tenant
            or CONTINUITY_ADMIN_ROLE not in principal.roles
        ):
            raise PermissionError("continuity access denied")

    def _require_stored_binding(self, binding: ContractBinding) -> None:
        for meta in self.heartwood.store.candidate_meta(self.heartwood.tenant):
            if not self._is_contract_meta(meta):
                continue
            try:
                contract = self._contract_from_meta(meta)
            except ContinuityIntegrityError:
                continue
            if (
                contract.route_id == binding.route_id
                and contract.schema_version == binding.schema_version
                and contract.contract_hash == binding.contract_hash
            ):
                return
        raise ContinuityIntegrityError("rotation receipt contract binding not found")

    def _contract_from_meta(self, meta: dict[str, Any]) -> CapabilityContract:
        content = self.heartwood._read_content_unchecked(meta["id"])
        if content is None:
            raise ContinuityIntegrityError("capability contract unavailable")
        if hash_content(content) != meta.get("content_hash"):
            raise ContinuityIntegrityError("capability contract content hash mismatch")
        if not verify_meta(self.heartwood.signer, meta, content):
            raise ContinuityIntegrityError("capability contract signature invalid")
        try:
            raw = json.loads(content)
            contract = CapabilityContract.from_dict(raw)
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ContinuityIntegrityError("capability contract schema invalid") from exc
        if canonical_json(contract.to_dict()) != content:
            raise ContinuityIntegrityError("capability contract encoding is not canonical")
        return contract

    @staticmethod
    def _is_contract_meta(meta: dict[str, Any] | None) -> bool:
        return bool(
            meta
            and meta.get("kind") == CONTINUITY_CONTRACT_KIND
            and meta.get("policy_scope") == CONTINUITY_POLICY_SCOPE
            and meta.get("indexed") is False
        )

    def _audit_row_matches_receipt(
        self,
        row: dict[str, Any] | None,
        receipt: SignedRotationReceipt,
    ) -> bool:
        if row is None:
            return False
        try:
            body = json.loads(row["body"])
        except (TypeError, json.JSONDecodeError):
            return False
        expected_detail = {
            "receipt_hash": receipt.receipt_hash,
            "lineage_hash": self._route_lineage_hash(receipt.draft),
            "status": receipt.draft.evidence_mode.value,
        }
        return (
            row["tenant"] == self.heartwood.tenant
            and row["principal"] == receipt.signed_by
            and row["action"] == ROTATION_RECEIPT_AUDIT_ACTION
            and row["target"] == receipt.draft.receipt_id
            and body
            == {
                "tenant": self.heartwood.tenant,
                "principal": receipt.signed_by,
                "action": ROTATION_RECEIPT_AUDIT_ACTION,
                "target": receipt.draft.receipt_id,
                "detail": expected_detail,
            }
        )
