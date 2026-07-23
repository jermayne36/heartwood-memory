"""MCP server exposing Heartwood over the Model Context Protocol.

Any MCP client (Claude Desktop, IDEs, agent runtimes) gets governed memory:
provenance-tracked writes, policy-enforced recall, explainable retrieval, and
GDPR erasure — plus an Anthropic-memory-tool-compatible file interface.

Run (requires `python -m pip install -e ".[recall,mcp]"`):
    python -m heartwood.adapters.mcp_server
Config via env: HEARTWOOD_DB_PATH (default :memory:), HEARTWOOD_TENANT (default tenant:default).
Tool exposure is fail-closed: when HEARTWOOD_MCP_ALLOWED_TOOLS is unset the server
exposes only the read-only subset (recall, explain_recall, health). The mutating and
destructive verbs (remember, memory, forget) require explicit opt-in by naming them in
HEARTWOOD_MCP_ALLOWED_TOOLS, e.g. HEARTWOOD_MCP_ALLOWED_TOOLS=recall,remember,forget.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from .. import __version__
from ..client import Heartwood
from ..ergonomics import attr_pairs, list_value, normalize_tenant, policy_from, principal_from
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
# or empty, ONLY these read-only verbs are exposed to the MCP client. recall and
# explain_recall are policy-enforced reads; health is liveness. None of them mutate
# stored memory, so they are safe to expose to any client by default.
DEFAULT_SAFE_TOOLS = frozenset({"recall", "explain_recall", "health"})

# Verbs that write, overwrite, delete, or crypto-shred governed memory. Exposing any
# of these to an untrusted MCP client enables memory poisoning (remember), arbitrary
# /memories mutation (memory: create/str_replace/insert/delete/rename), or a
# per-subject key-destruction workflow (forget). These are NEVER in the default set —
# an operator must name them explicitly in HEARTWOOD_MCP_ALLOWED_TOOLS to opt in.
MUTATING_TOOL_NAMES = frozenset({"remember", "memory", "forget"})


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


def _tool_enabled(allowed: set[str] | None, name: str) -> bool:
    return allowed is None or name in allowed


def _register_tool(mcp, allowed: set[str] | None):
    def decorator(func):
        if _tool_enabled(allowed, func.__name__):
            return mcp.tool()(func)
        return func

    return decorator


def _mutating_exposure_warning(allowed: set[str] | None) -> str | None:
    """Fail-loud defense-in-depth: warn when mutating/destructive verbs are exposed.

    `allowed is None` means "no filter" (all tools); otherwise it is the resolved
    allowlist. Returns the warning string when any mutating verb is exposed, else
    None. The caller routes this to stderr — never stdout, which carries the MCP
    JSON-RPC stream.
    """
    exposed = MUTATING_TOOL_NAMES if allowed is None else (set(allowed) & MUTATING_TOOL_NAMES)
    if not exposed:
        return None
    return (
        "[heartwood-mcp] mutating MCP tools exposed: "
        + ", ".join(sorted(exposed))
        + " — 'forget' performs an irreversible per-subject key-destruction workflow. "
        + "Restrict via HEARTWOOD_MCP_ALLOWED_TOOLS if this is unintended."
    )


class MCPMemoryAPI:
    """Governed MCP-facing facade over one or more tenant-scoped clients."""

    def __init__(self, db: Heartwood, backend: MemoryToolBackend | None = None):
        self.root = db
        self.clients: dict[str, Heartwood] = {db.tenant: db}
        self.backends: dict[str, MemoryToolBackend] = {}
        if backend is not None:
            self.backends[db.tenant] = backend

    def close(self) -> None:
        for tenant, client in list(self.clients.items()):
            client.close()
            del self.clients[tenant]

    def client(self, tenant: str | None = None) -> Heartwood:
        tenant_id = normalize_tenant(tenant, default=self.root.tenant)
        if tenant_id not in self.clients:
            self.clients[tenant_id] = self.root.with_tenant(tenant_id)
        return self.clients[tenant_id]

    def backend(self, tenant: str | None = None, *, created_by: str = "agent:mcp",
                subject: str = "memory-tool-user", classification: str = "internal") -> MemoryToolBackend:
        tenant_id = normalize_tenant(tenant, default=self.root.tenant)
        if tenant_id not in self.backends:
            self.backends[tenant_id] = MemoryToolBackend(
                self.client(tenant_id),
                created_by=created_by,
                subject=subject,
                classification=classification,
            )
        return self.backends[tenant_id]

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
                 salience: float = 0.5) -> dict:
        """Store a governed memory. Returns id plus persisted governance metadata."""
        client = self.client(tenant)
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
        )
        return {
            "ok": True,
            "id": mem_id,
            "tenant": client.tenant,
            "subject": subject,
            "classification": policy.classification,
            "roles": list(policy.roles),
            "source_ids": list(source_id_values),
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

    def explain_recall(self, recall_id: str, tenant: str | None = None) -> dict:
        """Explain a recall without exposing denied candidate counts."""
        explanation = dict(self.client(tenant).explain_recall(recall_id))
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
                        tenant: str | None = None) -> dict:
        return self.client(tenant).evaluate_egress(request, provider_registry)

    def assess_faithfulness(self, candidate: dict, support_threshold: float = 0.72,
                            review_threshold: float = 0.45,
                            tenant: str | None = None) -> dict:
        return self.client(tenant).assess_faithfulness(
            candidate,
            support_threshold=support_threshold,
            review_threshold=review_threshold,
        )

    def memory(self, command: str, path: str = "", file_text: str = "", old_str: str = "",
               new_str: str = "", insert_line: int = 0, insert_text: str = "",
               old_path: str = "", new_path: str = "",
               view_range: list[int] | None = None, tenant: str | None = None,
               created_by: str = "agent:mcp", subject: str = "memory-tool-user",
               classification: str = "internal") -> str:
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
        ).handle(cmd)


def build_server(db: Heartwood | None = None, backend: MemoryToolBackend | None = None,
                 name: str = "heartwood"):
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception as e:  # pragma: no cover
        raise RuntimeError('MCP SDK not installed. Run: python -m pip install -e ".[recall,mcp]"') from e

    db_path_value = os.environ.get("HEARTWOOD_DB_PATH", ":memory:")
    db_path = db_path_value if db_path_value == ":memory:" else Path(db_path_value)
    db = db or Heartwood(path=db_path, tenant=os.environ.get("HEARTWOOD_TENANT", "tenant:default"))
    backend = backend or MemoryToolBackend(db)
    api = MCPMemoryAPI(db, backend)
    mcp = FastMCP(name)
    protocol_server = getattr(mcp, "_mcp_server", None)
    if protocol_server is None or not hasattr(protocol_server, "version"):
        raise RuntimeError("installed MCP SDK cannot report the Heartwood server version")
    protocol_server.version = __version__
    allowed_tools = allowed_tools_from_env()
    warning = _mutating_exposure_warning(allowed_tools)
    if warning:
        print(warning, file=sys.stderr)

    @_register_tool(mcp, allowed_tools)
    def remember(content: str, subject: str, created_by: str = "agent:mcp",
                 tenant: str | None = None,
                 kind: str = "semantic", epistemic: str = "user-stated",
                 classification: str = "internal", pii: bool = False,
                 roles: list[str] | None = None, attrs: dict | None = None,
                 source_uri: str = "") -> dict:
        """Store a governed memory (provenance-signed, policy-tagged, audited). Returns its id."""
        return api.remember(
            content,
            subject=subject,
            created_by=created_by,
            tenant=tenant,
            kind=kind,
            epistemic=epistemic,
            classification=classification,
            pii=pii,
            roles=roles,
            attrs=attrs,
            source_uri=source_uri,
        )

    @_register_tool(mcp, allowed_tools)
    def recall(cue: str, principal_id: str = "agent:mcp", roles: list[str] | None = None,
               tenant: str | None = None, attrs: dict | None = None,
               clearance: str = "internal", subject: str = "", k: int = 8) -> dict:
        """Policy-enforced hybrid recall. Restricted memories never leak; results carry provenance."""
        return api.recall(
            cue,
            principal_id=principal_id,
            tenant=tenant,
            roles=roles,
            attrs=attrs,
            clearance=clearance,
            subject=subject,
            k=k,
        )

    @_register_tool(mcp, allowed_tools)
    def explain_recall(recall_id: str, tenant: str | None = None) -> dict:
        """Why was this recalled? Candidates considered, ranking signals, freshness."""
        return api.explain_recall(recall_id, tenant=tenant)

    @_register_tool(mcp, allowed_tools)
    def forget(subject: str, tenant: str | None = None, mode: str = "hard",
               actor: str = "agent:mcp", reason: str = "", legal_basis: str = "") -> dict:
        """GDPR Art.17 erasure: crypto-shred the subject key + purge derived artifacts. Audit retained."""
        return api.forget(subject, tenant=tenant, mode=mode, actor=actor, reason=reason, legal_basis=legal_basis)

    @_register_tool(mcp, allowed_tools)
    def evaluate_egress(request: dict, provider_registry: dict | None = None,
                        tenant: str | None = None) -> dict:
        """Evaluate whether source spans may leave the deployment boundary before model use."""
        return api.evaluate_egress(request, provider_registry, tenant=tenant)

    @_register_tool(mcp, allowed_tools)
    def assess_faithfulness(candidate: dict, support_threshold: float = 0.72,
                            review_threshold: float = 0.45, tenant: str | None = None) -> dict:
        """Evaluate generated-memory claims against cited source spans."""
        return api.assess_faithfulness(
            candidate,
            support_threshold=support_threshold,
            review_threshold=review_threshold,
            tenant=tenant,
        )

    @_register_tool(mcp, allowed_tools)
    def memory(command: str, path: str = "", file_text: str = "", old_str: str = "",
               new_str: str = "", insert_line: int = 0, insert_text: str = "",
               old_path: str = "", new_path: str = "",
               view_range: list[int] | None = None, tenant: str | None = None) -> str:
        """Anthropic memory-tool-compatible ops over /memories, backed by governed Heartwood memories.
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
            tenant=tenant,
        )

    @_register_tool(mcp, allowed_tools)
    def health() -> dict:
        """Readiness, warmed tenants, model names, and key-custody mode."""
        return api.health()

    return mcp, db, backend


def main():  # pragma: no cover
    mcp, _db, _backend = build_server()
    mcp.run()


if __name__ == "__main__":  # pragma: no cover
    main()
