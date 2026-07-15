"""Hermes Agent MemoryProvider adapter.

When Hermes Agent is installed, ``HeartwoodHermesMemoryProvider`` subclasses the
real ``agent.memory_provider.MemoryProvider`` ABC. When Hermes is absent, the
same class remains importable so the rest of Heartwood's adapter package keeps
working without a Hermes runtime dependency.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from ..client import Heartwood
from ..envelope import Policy
from ..policy import Principal

try:  # pragma: no cover - covered by tests/test_hermes_integration.py
    from agent.memory_provider import MemoryProvider as HermesMemoryProviderABC
except ImportError:  # pragma: no cover - exercised in the default Heartwood CI lane
    class HermesMemoryProviderABC:  # type: ignore[no-redef]
        """Fallback base used when Hermes Agent is not installed."""

    HERMES_MEMORY_PROVIDER_ABC_AVAILABLE = False
else:
    HERMES_MEMORY_PROVIDER_ABC_AVAILABLE = True


DEFAULT_HERMES_TENANT = "tenant:hermes"
DEFAULT_HERMES_DB_NAME = "heartwood.sqlite"
CONFIG_FILENAME = "heartwood.json"


_MEMORY_CONTEXT_RE = re.compile(
    r"<\s*memory-context\s*>[\s\S]*?</\s*memory-context\s*>",
    re.IGNORECASE,
)
_SYSTEM_NOTE_RE = re.compile(
    r"\[System note:\s*The following is recalled memory context[^\]]*\]\s*",
    re.IGNORECASE,
)


def sanitize_hermes_memory_text(text: str) -> str:
    """Remove already-injected memory blocks before persisting a turn."""
    text = _MEMORY_CONTEXT_RE.sub("", text or "")
    return _SYSTEM_NOTE_RE.sub("", text).strip()


def _load_config(hermes_home: str | None) -> dict[str, Any]:
    if not hermes_home:
        return {}
    config_path = Path(hermes_home).expanduser() / CONFIG_FILENAME
    if not config_path.exists():
        return {}
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


class HeartwoodHermesMemoryProvider(HermesMemoryProviderABC):
    """MemoryProvider binding that stores Hermes turns in Heartwood."""

    def __init__(
        self,
        db: Heartwood | None = None,
        *,
        principal: Principal | None = None,
        db_path: str | None = None,
        tenant: str | None = None,
        created_by: str = "agent:hermes",
        classification: str = "internal",
        auto_retain: bool = True,
        auto_recall: bool = True,
    ):
        self.db = db
        self._owns_db = False
        self._configured_db_path = db_path
        self._configured_tenant = tenant
        self.principal = principal
        self.created_by = created_by
        self.classification = classification
        self.auto_retain = auto_retain
        self.auto_recall = auto_recall
        self.session_id = "default"
        self.initialized = False
        self._queued_query = ""
        if self.db is not None:
            self._ensure_principal()

    @property
    def name(self) -> str:
        return "heartwood"

    def _ensure_principal(self) -> Principal:
        if self.principal is None:
            if self.db is None:
                tenant = self._configured_tenant or os.getenv("HEARTWOOD_TENANT") or DEFAULT_HERMES_TENANT
            else:
                tenant = self.db.tenant
            self.principal = Principal(
                id=self.created_by,
                tenant=tenant,
                roles=("support",),
                clearance=self.classification,
            )
        return self.principal

    def _ensure_db(self, *, hermes_home: str | None = None) -> Heartwood:
        if self.db is not None:
            self._ensure_principal()
            return self.db

        config = _load_config(hermes_home)
        tenant = (
            self._configured_tenant
            or os.getenv("HEARTWOOD_TENANT")
            or str(config.get("tenant") or DEFAULT_HERMES_TENANT)
        )
        db_path = self._configured_db_path or os.getenv("HEARTWOOD_DB_PATH") or config.get("db_path")
        if not db_path:
            home = Path(hermes_home).expanduser() if hermes_home else Path.cwd()
            db_path = str(home / DEFAULT_HERMES_DB_NAME)
        elif hermes_home:
            home = str(Path(hermes_home).expanduser())
            db_path = str(db_path).replace("$HERMES_HOME", home).replace("${HERMES_HOME}", home)

        self.db = Heartwood(path=str(db_path), tenant=tenant)
        self._owns_db = True
        self._ensure_principal()
        return self.db

    def is_available(self) -> bool:
        return True

    def initialize(self, session_id: str, **kwargs: Any) -> None:
        self._ensure_db(hermes_home=kwargs.get("hermes_home"))
        self.session_id = session_id or "default"
        self.initialized = True

    def system_prompt_block(self) -> str:
        return "Heartwood Memory is active: recall is policy-enforced and provenance-tracked."

    def prefetch(self, query: str, *, session_id: str = "") -> str:
        if not self.auto_recall or not query:
            return ""
        db = self._ensure_db()
        principal = self._ensure_principal()
        out = db.recall(
            query,
            principal=principal,
            filters={"subject": f"session:{session_id or self.session_id}"} if session_id or self.session_id else {},
            k=5,
            topc=40,
        )
        if not out["results"]:
            out = db.recall(query, principal=principal, k=5, topc=40)
        if not out["results"]:
            return ""
        lines = ["Heartwood recalled context:"]
        for result in out["results"]:
            provenance = result["provenance"]
            source = provenance.get("source", {}).get("uri", "heartwood://memory")
            lines.append(f"- {result['content']} (source={source}, sig_valid={provenance.get('signature_valid')})")
        return "\n".join(lines)

    def queue_prefetch(self, query: str, *, session_id: str = "") -> None:
        self._queued_query = query

    def sync_turn(
        self,
        user_content: str,
        assistant_content: str,
        *,
        session_id: str = "",
        messages: list[dict[str, Any]] | None = None,
    ) -> None:
        if not self.auto_retain:
            return
        db = self._ensure_db()
        sid = session_id or self.session_id
        user = sanitize_hermes_memory_text(user_content)
        assistant = sanitize_hermes_memory_text(assistant_content)
        if not user and not assistant:
            return
        content = f"User: {user}\nAssistant: {assistant}".strip()
        db.remember(
            content,
            subject=f"session:{sid}",
            created_by=self.created_by,
            kind="episodic",
            epistemic="observed-fact",
            source={"kind": "hermes-turn", "uri": f"hermes://session/{sid}"},
            policy=Policy(classification=self.classification),
            model_version="hermes-memory-provider",
        )

    def get_tool_schemas(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "heartwood_recall",
                "description": "Policy-enforced recall from Heartwood Memory.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "cue": {"type": "string"},
                        "subject": {"type": "string"},
                        "k": {"type": "integer"},
                    },
                    "required": ["cue"],
                },
            },
            {
                "name": "heartwood_remember",
                "description": "Store a governed Heartwood memory.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "content": {"type": "string"},
                        "subject": {"type": "string"},
                        "classification": {"type": "string"},
                    },
                    "required": ["content", "subject"],
                },
            },
            {
                "name": "heartwood_forget",
                "description": "Erase a subject through Heartwood deletion lineage.",
                "parameters": {
                    "type": "object",
                    "properties": {"subject": {"type": "string"}, "reason": {"type": "string"}},
                    "required": ["subject"],
                },
            },
        ]

    def handle_tool_call(self, tool_name: str, args: dict[str, Any], **kwargs: Any) -> str:
        try:
            db = self._ensure_db()
            principal = self._ensure_principal()
            if tool_name == "heartwood_recall":
                filters = {"subject": args["subject"]} if args.get("subject") else {}
                out = db.recall(
                    args["cue"],
                    principal=principal,
                    filters=filters,
                    k=int(args.get("k", 5)),
                    topc=40,
                )
                return json.dumps(
                    {
                        "recall_id": out["recall_id"],
                        "results": [
                            {
                                "id": result["id"],
                                "content": result["content"],
                                "score": result["score"],
                                "provenance_valid": result["provenance"].get("signature_valid"),
                            }
                            for result in out["results"]
                        ],
                    }
                )
            if tool_name == "heartwood_remember":
                mem_id = db.remember(
                    args["content"],
                    subject=args["subject"],
                    created_by=self.created_by,
                    source={"kind": "hermes-tool", "uri": "hermes://tool/heartwood_remember"},
                    policy=Policy(classification=args.get("classification", self.classification)),
                    model_version="hermes-memory-provider",
                )
                return json.dumps({"id": mem_id})
            if tool_name == "heartwood_forget":
                return json.dumps(
                    db.forget(
                        args["subject"],
                        actor=self.created_by,
                        reason=args.get("reason", "hermes memory provider forget"),
                        legal_basis=args.get("legal_basis", ""),
                    )
                )
            return json.dumps({"error": f"unknown tool {tool_name}"})
        except Exception as exc:  # noqa: BLE001 - tool contract returns JSON errors
            return json.dumps({"error": str(exc)})

    def get_config_schema(self) -> list[dict[str, Any]]:
        return [
            {
                "key": "db_path",
                "description": "Path to the Heartwood SQLite database.",
                "default": f"$HERMES_HOME/{DEFAULT_HERMES_DB_NAME}",
                "env_var": "HEARTWOOD_DB_PATH",
            },
            {
                "key": "tenant",
                "description": "Heartwood tenant id for Hermes memories.",
                "default": DEFAULT_HERMES_TENANT,
                "env_var": "HEARTWOOD_TENANT",
            },
        ]

    def save_config(self, values: dict[str, Any], hermes_home: str) -> None:
        path = Path(hermes_home).expanduser() / CONFIG_FILENAME
        config = {
            "db_path": values.get("db_path") or f"$HERMES_HOME/{DEFAULT_HERMES_DB_NAME}",
            "tenant": values.get("tenant") or DEFAULT_HERMES_TENANT,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        os.chmod(path, 0o600)

    def shutdown(self) -> None:
        if self._owns_db and self.db is not None:
            self.db.close()
            self.db = None
            self.principal = None
            self._owns_db = False
        self.initialized = False


def register(ctx: Any) -> None:
    """Register Heartwood as a Hermes memory provider plugin."""
    ctx.register_memory_provider(HeartwoodHermesMemoryProvider())
