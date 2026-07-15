"""Policy in the retrieval path.

Principle (adversarial-review finding): a similarity hit must never bypass
permissions, and existence must not leak. Enforcement gates the *candidate set*
before ranking; the client returns constant-shape responses so denials are
unobservable via count/score/latency.
"""
from __future__ import annotations

from dataclasses import dataclass

from .envelope import CLASSIFICATION_RANK


@dataclass(frozen=True)
class Principal:
    id: str
    tenant: str
    roles: tuple = ()
    attrs: tuple = ()        # ((key, value), ...)
    clearance: str = "internal"   # max classification this principal may read

    def attr_map(self) -> dict:
        return dict(self.attrs)


class PolicyEnforcer:
    """Decides which memory rows a principal may see. Pure, side-effect free."""

    def visible(self, principal: Principal, row: dict) -> tuple[bool, str]:
        """row: persisted memory metadata. Returns (allowed, reason)."""
        # 1. Hard tenant partition — never crossed.
        if row["tenant"] != principal.tenant:
            return False, "cross-tenant"
        # 2. Classification clearance.
        if CLASSIFICATION_RANK[row["classification"]] > CLASSIFICATION_RANK[principal.clearance]:
            return False, "classification>clearance"
        # 3. Role ACL — conjunction of disjunctive gates. The principal must
        #    satisfy EVERY group (need ANY role within each). Empty => any.
        groups = []
        if row.get("roles"):
            groups.append(row["roles"])
        for g in (row.get("role_groups") or ()):
            if g:
                groups.append(g)
        principal_roles = set(principal.roles)
        for g in groups:
            if not (principal_roles & set(g)):
                return False, "role"
        # 4. Attribute ABAC (every required attr must match).
        amap = principal.attr_map()
        for key, val in (row.get("attrs") or ()):
            if amap.get(key) != val:
                return False, f"attr:{key}"
        # 5. Private visibility => only the creator.
        if row["visibility"] == "private" and row["created_by"] != principal.id:
            return False, "private"
        return True, "ok"

    def allowed_view(self, principal: Principal, rows: list[dict]) -> tuple[list[dict], list[dict]]:
        """Partition rows into (visible, denied) — denied is for audit only,
        never surfaced to the caller."""
        visible, denied = [], []
        for r in rows:
            ok, reason = self.visible(principal, r)
            (visible if ok else denied).append({**r, "_deny_reason": reason} if not ok else r)
        return visible, denied
