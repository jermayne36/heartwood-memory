"""MCP server exposing Heartwood over the Model Context Protocol.

Any MCP client (Claude Desktop, IDEs, agent runtimes) gets governed memory:
provenance-tracked writes, policy-enforced recall, explainable retrieval, and
GDPR erasure — plus an Anthropic-memory-tool-compatible file interface.

Run (requires `python -m pip install -e ".[recall,mcp]"`):
    python -m heartwood.adapters.mcp_server
Config via env: HEARTWOOD_DB_PATH (default :memory:), HEARTWOOD_TENANT (default tenant:default).
Every tool call runs as one principal fixed when the server starts: the store's tenant
plus HEARTWOOD_MCP_PRINCIPAL_ID (default agent:mcp), HEARTWOOD_MCP_ROLES and
HEARTWOOD_MCP_ATTRS (comma-separated; key=value for attrs; default none) and
HEARTWOOD_MCP_CLEARANCE (default internal). MCP clients cannot choose any of these: a
tool call that sends tenant, principal_id, roles, attrs, clearance, created_by, actor,
or any other argument the tool does not declare is rejected, not ignored. Reads stay
inside that principal too: recall filters by its policy, explain_recall explains only
its own recalls, memory lists, reads and edits only /memories files it can read,
evaluate_egress and assess_faithfulness resolve a cited memory's text only when it can
read that memory, and remember's supersedes retires only memories it can read and may
retire (an unreadable id is refused like an unknown one).
forget is the exception: it erases a whole subject, including memories the principal
cannot read.
Tool exposure is fail-closed: when HEARTWOOD_MCP_ALLOWED_TOOLS is unset the server
exposes only the read-only subset (recall, explain_recall, health). The mutating and
destructive verbs (remember, memory, forget) and the source-text tools
(evaluate_egress, assess_faithfulness) require explicit opt-in by naming them in
HEARTWOOD_MCP_ALLOWED_TOOLS, e.g. HEARTWOOD_MCP_ALLOWED_TOOLS=recall,remember,forget.
"""
from __future__ import annotations

import inspect
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .. import __version__
from ..anchors import LocalFileAnchorSink
from ..client import Heartwood
from ..envelope import CLASSIFICATION_RANK
from ..ergonomics import attr_pairs, list_value, normalize_tenant, policy_from, principal_from
from ..policy import Principal
from .memory_tool import MemoryToolBackend


MCP_TOOL_NAMES = {
    "remember",
    "recall",
    "explain_recall",
    "forget",
    "evaluate_egress",
    "assess_faithfulness",
    "memory",
    "health",
}

# Fail-closed default exposure (ASA A4). When HEARTWOOD_MCP_ALLOWED_TOOLS is unset
# or empty, ONLY these read-only verbs are exposed to the MCP client. health is
# liveness; recall and explain_recall are policy-enforced reads. None of them mutate
# stored memory. They are NOT a confidentiality boundary on their own: any connected
# client reads everything the server's configured principal may read (tenant, roles,
# attrs, clearance), so configure that principal for the least the client should see.
DEFAULT_SAFE_TOOLS = frozenset({"recall", "explain_recall", "health"})

# Identity arguments an MCP client must never choose. tenant crosses the hard tenant
# partition; roles, attrs and clearance widen the policy filter; principal_id,
# created_by and actor name the identity that private visibility, provenance and audit
# are checked against. No registered tool declares any of them: build_server binds all
# of them from server configuration and rejects a call that sends one.
PRINCIPAL_ARGUMENT_NAMES = frozenset(
    {"tenant", "principal_id", "roles", "attrs", "clearance", "created_by", "actor"}
)
DEFAULT_MCP_PRINCIPAL_ID = "agent:mcp"

# Verbs that write, overwrite, delete, or crypto-shred governed memory. Exposing any
# of these to an untrusted MCP client enables memory poisoning (remember), arbitrary
# /memories mutation (memory: create/str_replace/insert/delete/rename), or a
# per-subject key-destruction workflow (forget). These are NEVER in the default set —
# an operator must name them explicitly in HEARTWOOD_MCP_ALLOWED_TOOLS to opt in.
MUTATING_TOOL_NAMES = frozenset({"remember", "memory", "forget"})

# Verbs that return or score the text of cited source spans. They resolve only spans in
# memories the server's principal can read, but that text can be quoted material recall
# never returns, so exposing them is an opt-in that is announced like the mutating verbs.
SOURCE_TEXT_TOOL_NAMES = frozenset({"evaluate_egress", "assess_faithfulness"})


def allowed_tools_from_env(value: str | None = None) -> set[str]:
    """Resolve the MCP tool allowlist (fail-closed).

    When HEARTWOOD_MCP_ALLOWED_TOOLS is unset or empty, return only the read-only
    subset (DEFAULT_SAFE_TOOLS); the mutating/destructive verbs are NOT exposed. A
    non-empty, explicit allowlist is honored verbatim, so deployments that already
    set the variable are unchanged. Unknown tool names fail closed (ValueError).
    """
    raw = os.environ.get("HEARTWOOD_MCP_ALLOWED_TOOLS", "") if value is None else value
    if not raw.strip():
        return set(DEFAULT_SAFE_TOOLS)
    allowed = {part.strip() for part in raw.replace(";", ",").split(",") if part.strip()}
    unknown = sorted(allowed - MCP_TOOL_NAMES)
    if unknown:
        raise ValueError(
            "Unknown HEARTWOOD_MCP_ALLOWED_TOOLS entries: "
            + ", ".join(unknown)
            + ". Valid tools: "
            + ", ".join(sorted(MCP_TOOL_NAMES))
        )
    return allowed


def principal_from_env(tenant: str, environ: Mapping[str, str] | None = None) -> Principal:
    """Resolve the one principal every MCP tool call runs as.

    The tenant is the store's tenant. The id, roles, attributes and clearance come
    from HEARTWOOD_MCP_PRINCIPAL_ID, HEARTWOOD_MCP_ROLES, HEARTWOOD_MCP_ATTRS and
    HEARTWOOD_MCP_CLEARANCE. Unset values give agent:mcp with no roles, no attributes
    and internal clearance: the values the tools used when a client sent none.
    """
    env = os.environ if environ is None else environ
    return principal_from(
        env.get("HEARTWOOD_MCP_PRINCIPAL_ID", "").strip() or DEFAULT_MCP_PRINCIPAL_ID,
        tenant=tenant,
        roles=list_value(env.get("HEARTWOOD_MCP_ROLES")),
        attrs=attr_pairs(env.get("HEARTWOOD_MCP_ATTRS")),
        clearance=env.get("HEARTWOOD_MCP_CLEARANCE", "").strip() or "internal",
    )


def _bound_principal(db: Heartwood, principal: Principal | None) -> Principal:
    bound = principal_from_env(db.tenant) if principal is None else principal_from(principal)
    # @fail-closed(mcp-principal-config): a principal for another tenant, or a
    # clearance the policy engine cannot rank, stops the server before it serves.
    if bound.tenant != db.tenant:
        hint = f" Set HEARTWOOD_TENANT={bound.tenant}." if normalize_tenant(db.tenant) == bound.tenant else ""
        raise ValueError(
            f"MCP principal tenant {bound.tenant!r} does not match the store tenant {db.tenant!r}.{hint}"
        )
    if bound.clearance not in CLASSIFICATION_RANK:
        raise ValueError(
            f"Unknown MCP principal clearance {bound.clearance!r}. Valid clearances: "
            + ", ".join(sorted(CLASSIFICATION_RANK, key=CLASSIFICATION_RANK.get))
        )
    return bound


def _undeclared_argument_error(tool: str, arguments: Mapping[str, Any],
                               declared: frozenset[str]) -> str | None:
    """Return the rejection message for a tool call, or None if every key is declared.

    Identity keys are checked first so the message names the server-side binding.
    """
    sent = set(arguments)
    identity = sorted(sent & PRINCIPAL_ARGUMENT_NAMES)
    if identity:
        return (
            f"{tool}: {', '.join(identity)} cannot be set by an MCP client. This server runs "
            "every call as the principal in its configuration (HEARTWOOD_TENANT, "
            "HEARTWOOD_MCP_PRINCIPAL_ID, HEARTWOOD_MCP_ROLES, HEARTWOOD_MCP_ATTRS, "
            "HEARTWOOD_MCP_CLEARANCE)."
        )
    unknown = sorted(sent - declared)
    if unknown:
        return f"{tool}: unknown arguments: {', '.join(unknown)}"
    return None


def _tool_enabled(allowed: set[str] | None, name: str) -> bool:
    return allowed is None or name in allowed


def _register_tool(mcp, allowed: set[str] | None, declared: dict[str, frozenset[str]]):
    def decorator(func):
        if _tool_enabled(allowed, func.__name__):
            declared[func.__name__] = frozenset(inspect.signature(func).parameters)
            return mcp.tool()(func)
        return func

    return decorator


def _mutating_exposure_warning(allowed: set[str] | None) -> str | None:
    """Fail-loud defense-in-depth: warn when mutating or source-text verbs are exposed.

    `allowed is None` means "no filter" (all tools); otherwise it is the resolved
    allowlist. Returns the warning string when any mutating or source-text verb is
    exposed, else None. The caller routes this to stderr — never stdout, which
    carries the MCP JSON-RPC stream.
    """
    announced = MUTATING_TOOL_NAMES | SOURCE_TEXT_TOOL_NAMES
    exposed = announced if allowed is None else (set(allowed) & announced)
    if not exposed:
        return None
    lines = []
    mutating = exposed & MUTATING_TOOL_NAMES
    if mutating:
        lines.append(
            "[heartwood-mcp] mutating MCP tools exposed: "
            + ", ".join(sorted(mutating))
            + " — 'forget' performs an irreversible per-subject key-destruction workflow."
        )
    source_text = exposed & SOURCE_TEXT_TOOL_NAMES
    if source_text:
        lines.append(
            "[heartwood-mcp] source-text MCP tools exposed: "
            + ", ".join(sorted(source_text))
            + " — they return or score the text of cited spans in memories the server's "
            + "principal can read."
        )
    lines.append("Restrict via HEARTWOOD_MCP_ALLOWED_TOOLS if this is unintended.")
    return " ".join(lines)


class MCPMemoryAPI:
    """Governed MCP-facing facade over one or more tenant-scoped clients.

    The tenant and identity arguments (tenant, principal_id, roles, attrs, clearance,
    created_by, actor, principal) are trusted: pass values from your own
    authentication, never from an MCP client's tool arguments. build_server binds them
    from configuration. memory, evaluate_egress and assess_faithfulness read past any
    principal unless you pass `principal`.
    """

    def __init__(self, db: Heartwood, backend: MemoryToolBackend | None = None):
        self.root = db
        self.clients: dict[str, Heartwood] = {db.tenant: db}
        # Keyed by (tenant, principal): a backend's file index is filtered for one principal.
        self.backends: dict[tuple[str, Principal | None], MemoryToolBackend] = {}
        if backend is not None:
            self.backends[(db.tenant, backend.principal)] = backend

    def close(self) -> None:
        for tenant, client in list(self.clients.items()):
            client.close()
            del self.clients[tenant]

    def client(self, tenant: str | None = None) -> Heartwood:
        tenant_id = normalize_tenant(tenant, default=self.root.tenant)
        if tenant_id not in self.clients:
            self.clients[tenant_id] = self.root.with_tenant(tenant_id)
        return self.clients[tenant_id]

    def backend(self, tenant: str | None = None, *, created_by: str | None = None,
                subject: str = "memory-tool-user", classification: str = "internal",
                principal: Principal | None = None) -> MemoryToolBackend:
        tenant_id = normalize_tenant(tenant, default=self.root.tenant)
        key = (tenant_id, principal)
        if key not in self.backends:
            self.backends[key] = MemoryToolBackend(
                self.client(tenant_id),
                created_by=created_by or (principal.id if principal is not None else "agent:mcp"),
                subject=subject,
                classification=classification,
                principal=principal,
            )
        return self.backends[key]

    def health(self) -> dict:
        return {
            "ok": True,
            "service": "heartwood-mcp",
            "tenants": sorted(self.clients),
            "models": {
                "embedder": self.root.embedder_name,
                "reranker": self.root.reranker_name,
                "index": self.root.index.name,
            },
            "key_custody": self.root.keys.custodian.name,
        }

    def remember(self, content: str, subject: str, created_by: str = "agent:mcp",
                 tenant: str | None = None, kind: str = "semantic",
                 epistemic: str = "user-stated", classification: str = "internal",
                 pii: bool = False, roles: list[str] | str | None = None,
                 attrs: dict | list[str] | str | None = None,
                 visibility: str = "tenant", source_uri: str = "",
                 source_ids: list[str] | str | None = None,
                 source_spans: list[dict] | None = None,
                 policy_scope: str = "", confidence: float = 0.8,
                 salience: float = 0.5, supersedes: list[str] | str | None = None,
                 principal: Principal | None = None) -> dict:
        """Store a governed memory. Returns id plus persisted governance metadata.

        `supersedes` retires the listed memories in the same write (see
        Heartwood.remember). With `principal`, each one must be a memory that
        principal can read and may retire; an unreadable one is refused like an
        unknown id.
        """
        client = self.client(tenant)
        if supersedes is None:
            superseded_ids: tuple[str, ...] = ()
        elif isinstance(supersedes, str):
            superseded_ids = (supersedes,)
        else:
            superseded_ids = tuple(supersedes)
        policy = policy_from(
            {
                "classification": classification,
                "pii": pii,
                "roles": list_value(roles),
                "attrs": attr_pairs(attrs),
                "visibility": visibility,
            }
        )
        source = {"kind": "mcp", "uri": source_uri} if source_uri else {"kind": "mcp"}
        source_id_values = tuple(str(item) for item in list_value(source_ids))
        if not source_id_values and source_uri:
            source_id_values = (source_uri,)
        mem_id = client.remember(
            content,
            subject=subject,
            created_by=created_by,
            kind=kind,
            epistemic=epistemic,
            confidence=max(0.0, min(1.0, float(confidence))),
            salience=max(0.0, min(1.0, float(salience))),
            source=source,
            policy=policy,
            policy_scope=policy_scope or client.tenant.split(":", 1)[-1],
            source_ids=source_id_values,
            source_spans=tuple(source_spans or ()),
            supersedes=superseded_ids,
            principal=principal,
        )
        return {
            "ok": True,
            "id": mem_id,
            "tenant": client.tenant,
            "subject": subject,
            "classification": policy.classification,
            "roles": list(policy.roles),
            "source_ids": list(source_id_values),
            "supersedes": list(dict.fromkeys(superseded_ids)),
        }

    def recall(self, cue: str, principal_id: str = "agent:mcp",
               tenant: str | None = None, roles: list[str] | str | None = None,
               attrs: dict | list[str] | str | None = None, clearance: str = "internal",
               subject: str = "", k: int = 8, topc: int = 50,
               filters: dict | None = None, method: str = "", typed: bool = False) -> dict:
        """Policy-enforced recall. Restricted/denied records are not surfaced."""
        client = self.client(tenant)
        local_filters = dict(filters or {})
        if subject:
            local_filters["subject"] = subject
        if method:
            local_filters["method"] = method
        if typed:
            local_filters["typed"] = True
        principal = principal_from(
            principal_id,
            tenant=client.tenant,
            roles=list_value(roles),
            attrs=attr_pairs(attrs),
            clearance=clearance,
        )
        out = client.recall(
            cue,
            principal=principal,
            filters=local_filters,
            k=max(1, min(20, int(k))),
            topc=max(1, min(200, int(topc))),
        )
        return {
            "ok": True,
            "tenant": client.tenant,
            "recall_id": out["recall_id"],
            "index_lag": out["index_lag"],
            "result_count": len(out["results"]),
            "receipt": out["receipt"],
            "receipt_unavailable_reason": out["receipt_unavailable_reason"],
            "results": [
                {
                    "id": r["id"],
                    "content": r["content"],
                    "score": r["score"],
                    "kind": r["kind"],
                    "epistemic": r["epistemic"],
                    "classification": r["classification"],
                    "truth_status": r["truth_status"],
                    "source_ids": r["source_ids"],
                    "source_uri": r["source_uri"],
                    "created_by": r["created_by"],
                    "content_hash": r["content_hash"],
                    "producer_sig": r["producer_sig"],
                    "producer_key_fingerprint": r["producer_key_fingerprint"],
                    "signature_valid_at_serve": r["signature_valid_at_serve"],
                    "content_hash_match_at_serve": r["content_hash_match_at_serve"],
                    "provenance_valid": r["provenance"].get("signature_valid"),
                    "content_hash_match": r["provenance"].get("content_hash_match"),
                    **(
                        {
                            "strict_exempt": r["strict_exempt"],
                            "strict_exempt_manifest_id": r["strict_exempt_manifest_id"],
                        }
                        if r.get("strict_exempt") == "pre_cutover"
                        else {}
                    ),
                    "signals": r["signals"],
                }
                for r in out["results"]
            ],
        }

    def explain_recall(self, recall_id: str, tenant: str | None = None,
                       principal_id: str | None = None) -> dict:
        """Explain a recall without exposing denied candidate counts.

        With `principal_id`, only that principal's own recalls are explained."""
        explanation = dict(self.client(tenant).explain_recall(recall_id, principal_id=principal_id))
        explanation.pop("denied", None)
        explanation.pop("denied_reasons", None)
        if isinstance(explanation.get("strict_dropped"), dict):
            explanation["strict_dropped"].pop("ids", None)
        return explanation

    def forget(self, subject: str, tenant: str | None = None, mode: str = "hard",
               actor: str = "agent:mcp", reason: str = "", legal_basis: str = "") -> dict:
        mode_value = str(mode or "hard").strip()
        if mode_value != "hard":
            return {"ok": False, "error": f"unsupported forget mode: {mode_value}", "mode": mode_value}
        return self.client(tenant).forget(
            subject,
            mode=mode_value,
            actor=actor,
            reason=reason,
            legal_basis=legal_basis,
        )

    def evaluate_egress(self, request: dict, provider_registry: dict | None = None,
                        tenant: str | None = None, principal: Principal | None = None) -> dict:
        return self.client(tenant).evaluate_egress(request, provider_registry, principal=principal)

    def assess_faithfulness(self, candidate: dict, support_threshold: float = 0.72,
                            review_threshold: float = 0.45,
                            tenant: str | None = None, principal: Principal | None = None) -> dict:
        return self.client(tenant).assess_faithfulness(
            candidate,
            support_threshold=support_threshold,
            review_threshold=review_threshold,
            principal=principal,
        )

    def memory(self, command: str, path: str = "", file_text: str = "", old_str: str = "",
               new_str: str = "", insert_line: int = 0, insert_text: str = "",
               old_path: str = "", new_path: str = "",
               view_range: list[int] | None = None, tenant: str | None = None,
               created_by: str | None = None, subject: str = "memory-tool-user",
               classification: str = "internal", principal: Principal | None = None) -> str:
        cmd: dict[str, Any] = {"command": command}
        if path:
            cmd["path"] = path
        if command == "create":
            cmd["file_text"] = file_text
        if command == "str_replace":
            cmd["old_str"], cmd["new_str"] = old_str, new_str
        if command == "insert":
            cmd["insert_line"], cmd["insert_text"] = insert_line, insert_text
        if command == "rename":
            cmd["old_path"], cmd["new_path"] = old_path, new_path
        if view_range:
            cmd["view_range"] = view_range
        return self.backend(
            tenant,
            created_by=created_by,
            subject=subject,
            classification=classification,
            principal=principal,
        ).handle(cmd)


def build_server(db: Heartwood | None = None, backend: MemoryToolBackend | None = None,
                 name: str = "heartwood", principal: Principal | None = None):
    """Build the FastMCP server. Every tool call runs as one server-bound principal.

    `principal` lets an embedding host bind the identity in code; it must belong to
    the store's tenant. When omitted, principal_from_env resolves it.
    """
    try:
        from mcp.server.fastmcp import FastMCP
        from mcp.server.fastmcp.exceptions import ToolError
    except Exception as e:  # pragma: no cover
        raise RuntimeError('MCP SDK not installed. Run: python -m pip install -e ".[recall,mcp]"') from e

    db_path_value = os.environ.get("HEARTWOOD_DB_PATH", ":memory:")
    db_path = db_path_value if db_path_value == ":memory:" else Path(db_path_value)
    anchor_path = os.environ.get("HEARTWOOD_ANCHOR_PATH")
    db = db or Heartwood(
        path=db_path,
        tenant=os.environ.get("HEARTWOOD_TENANT", "tenant:default"),
        anchor_sink=LocalFileAnchorSink(anchor_path) if anchor_path else None,
        anchor_root_fingerprints=os.environ.get("HEARTWOOD_ANCHOR_ROOT_FINGERPRINT"),
    )
    principal = _bound_principal(db, principal)
    backend = backend or MemoryToolBackend(db, principal=principal)
    # @fail-closed(mcp-principal-memory-backend): a memory backend built for another
    # principal, or for none, would list and edit files past this server's principal.
    if backend.principal is None or principal_from(backend.principal) != principal:
        raise ValueError("MCP memory backend must be built with principal= the server's principal")
    api = MCPMemoryAPI(db, backend)
    declared_arguments: dict[str, frozenset[str]] = {}

    class PrincipalBoundFastMCP(FastMCP):
        """FastMCP that rejects undeclared tool arguments instead of dropping them."""

        async def list_tools(self):
            return [
                tool.model_copy(update={"inputSchema": {**tool.inputSchema, "additionalProperties": False}})
                for tool in await super().list_tools()
            ]

        async def call_tool(self, name: str, arguments: dict[str, Any]):
            # @fail-closed(mcp-principal-arguments): FastMCP silently drops arguments a
            # tool does not declare, so a client-sent tenant or roles would be ignored
            # rather than refused. Refuse every undeclared key before the tool runs.
            declared = declared_arguments.get(name)
            if declared is not None:
                error = _undeclared_argument_error(name, arguments or {}, declared)
                if error:
                    raise ToolError(error)
            return await super().call_tool(name, arguments)

    def own_actor(tool: str, field: str, payload: dict) -> dict:
        # @fail-closed(mcp-principal-actor): the audit row names the server's principal;
        # a client-sent actor naming anyone else is refused, not silently replaced.
        actor = payload.get("actor")
        if actor is not None and actor != principal.id:
            raise ToolError(
                f"{tool}: {field}.actor cannot be set by an MCP client. This server records "
                f"every call as its configured principal ({principal.id})."
            )
        return payload

    mcp = PrincipalBoundFastMCP(name)
    protocol_server = getattr(mcp, "_mcp_server", None)
    if protocol_server is None or not hasattr(protocol_server, "version"):
        raise RuntimeError("installed MCP SDK cannot report the Heartwood server version")
    protocol_server.version = __version__
    allowed_tools = allowed_tools_from_env()
    warning = _mutating_exposure_warning(allowed_tools)
    if warning:
        print(warning, file=sys.stderr)

    @_register_tool(mcp, allowed_tools, declared_arguments)
    def remember(content: str, subject: str, kind: str = "semantic",
                 epistemic: str = "user-stated", classification: str = "internal",
                 pii: bool = False, source_uri: str = "",
                 supersedes: list[str] | str | None = None) -> dict:
        """Store a governed memory as this server's principal (provenance-signed, policy-tagged, audited). Returns its id.
        Heartwood does not detect that a memory replaces an older one. When it does, pass the older ids in supersedes: they are retired in the same step and default recall stops returning them. Only memories this server's principal can read and may retire (its own, or any with a reviewer or approver role) can be superseded."""
        return api.remember(
            content,
            subject=subject,
            created_by=principal.id,
            tenant=principal.tenant,
            kind=kind,
            epistemic=epistemic,
            classification=classification,
            pii=pii,
            source_uri=source_uri,
            supersedes=supersedes,
            principal=principal,
        )

    @_register_tool(mcp, allowed_tools, declared_arguments)
    def recall(cue: str, subject: str = "", k: int = 8) -> dict:
        """Policy-enforced hybrid recall as this server's principal. Restricted memories never leak; results carry provenance."""
        return api.recall(
            cue,
            principal_id=principal.id,
            tenant=principal.tenant,
            roles=list(principal.roles),
            attrs=principal.attrs,
            clearance=principal.clearance,
            subject=subject,
            k=k,
        )

    @_register_tool(mcp, allowed_tools, declared_arguments)
    def explain_recall(recall_id: str) -> dict:
        """Why was this recalled? Candidates considered, ranking signals, freshness."""
        return api.explain_recall(recall_id, tenant=principal.tenant, principal_id=principal.id)

    @_register_tool(mcp, allowed_tools, declared_arguments)
    def forget(subject: str, mode: str = "hard", reason: str = "", legal_basis: str = "") -> dict:
        """GDPR Art.17 erasure: crypto-shred the subject key + purge derived artifacts. Audit retained."""
        return api.forget(
            subject,
            tenant=principal.tenant,
            mode=mode,
            actor=principal.id,
            reason=reason,
            legal_basis=legal_basis,
        )

    @_register_tool(mcp, allowed_tools, declared_arguments)
    def evaluate_egress(request: dict, provider_registry: dict | None = None) -> dict:
        """Evaluate whether source spans may leave the deployment boundary before model use. Cited memories resolve only if this server's principal can read them."""
        return api.evaluate_egress(
            own_actor("evaluate_egress", "request", request),
            provider_registry,
            tenant=principal.tenant,
            principal=principal,
        )

    @_register_tool(mcp, allowed_tools, declared_arguments)
    def assess_faithfulness(candidate: dict, support_threshold: float = 0.72,
                            review_threshold: float = 0.45) -> dict:
        """Evaluate generated-memory claims against cited source spans this server's principal can read."""
        return api.assess_faithfulness(
            own_actor("assess_faithfulness", "candidate", candidate),
            support_threshold=support_threshold,
            review_threshold=review_threshold,
            tenant=principal.tenant,
            principal=principal,
        )

    @_register_tool(mcp, allowed_tools, declared_arguments)
    def memory(command: str, path: str = "", file_text: str = "", old_str: str = "",
               new_str: str = "", insert_line: int = 0, insert_text: str = "",
               old_path: str = "", new_path: str = "",
               view_range: list[int] | None = None) -> str:
        """Anthropic memory-tool-compatible ops over the /memories files this server's principal can read, backed by governed Heartwood memories.
        commands: view | create | str_replace | insert | delete | rename."""
        return api.memory(
            command,
            path=path,
            file_text=file_text,
            old_str=old_str,
            new_str=new_str,
            insert_line=insert_line,
            insert_text=insert_text,
            old_path=old_path,
            new_path=new_path,
            view_range=view_range,
            tenant=principal.tenant,
            principal=principal,
        )

    @_register_tool(mcp, allowed_tools, declared_arguments)
    def health() -> dict:
        """Readiness, warmed tenants, model names, and key-custody mode."""
        return api.health()

    return mcp, db, backend


def main():  # pragma: no cover
    mcp, _db, _backend = build_server()
    mcp.run()


if __name__ == "__main__":  # pragma: no cover
    main()
