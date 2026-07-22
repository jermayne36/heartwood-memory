"""Contract tests for Heartwood against the real Hermes Agent MemoryProvider ABC.

Validated dependency pin:
- hermes-agent 0.17.0
- git tag v2026.6.19
- tag commit 2bd1977d8fad185c9b4be47884f7e87f1add0ce3
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import inspect
import json
import re
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import pytest

from heartwood import Heartwood
from heartwood.adapters.hermes import HeartwoodHermesMemoryProvider, register
from heartwood.envelope import Policy
from heartwood.policy import Principal

# TODO(public split 73ceae4): run this contract suite in the Hermes Agent
# integration environment once that plugin boundary is published independently.
# The public Heartwood package intentionally does not ship the external
# ``agent`` or ``plugins`` modules that this real-provider contract exercises.
MemoryProvider = pytest.importorskip(
    "agent.memory_provider",
    reason=(
        "requires the optional Hermes Agent integration; the public Heartwood "
        "split does not ship agent.memory_provider or plugins.memory"
    ),
).MemoryProvider


HERMES_AGENT_VERSION = "0.17.0"
HERMES_AGENT_TAG = "v2026.6.19"
HERMES_AGENT_COMMIT = "2bd1977d8fad185c9b4be47884f7e87f1add0ce3"
TOKEN_RE = re.compile(r"[a-z0-9]+")


def tokenize(text: str) -> list[str]:
    return TOKEN_RE.findall(text.lower())


def fast_embed(texts: Iterable[str], dim: int = 256) -> np.ndarray:
    rows = list(texts)
    vecs = np.zeros((len(rows), dim), dtype=np.float32)
    for row_idx, text in enumerate(rows):
        for token in tokenize(text):
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            vecs[row_idx, int.from_bytes(digest[:4], "big") % dim] += 1.0
    norms = np.linalg.norm(vecs, axis=1, keepdims=True)
    norms[norms == 0.0] = 1.0
    return vecs / norms


def lexical_rerank(query: str, texts: list[str]) -> np.ndarray:
    query_tokens = set(tokenize(query))
    scores = np.zeros(len(texts), dtype=np.float32)
    for idx, text in enumerate(texts):
        doc_tokens = set(tokenize(text))
        scores[idx] = len(query_tokens & doc_tokens) / (len(query_tokens | doc_tokens) or 1)
    return scores


def make_db(path: Path, tenant: str) -> Heartwood:
    return Heartwood(
        path=str(path),
        tenant=tenant,
        embedder=(fast_embed, "hashing-embedder(hermes-real-contract)"),
        reranker=(lexical_rerank, "lexical-overlap-reranker(hermes-real-contract)"),
    )


def make_provider(tmp_path: Path) -> HeartwoodHermesMemoryProvider:
    tenant = "tenant:hermes-real-contract"
    db = make_db(tmp_path / "hermes-real.sqlite", tenant)
    principal = Principal(
        id="agent:hermes-support",
        tenant=tenant,
        roles=("support",),
        clearance="internal",
    )
    return HeartwoodHermesMemoryProvider(db, principal=principal)


def test_hermes_dependency_pin_is_the_validated_release() -> None:
    assert importlib.metadata.version("hermes-agent") == HERMES_AGENT_VERSION
    assert HERMES_AGENT_TAG == "v2026.6.19"
    assert HERMES_AGENT_COMMIT == "2bd1977d8fad185c9b4be47884f7e87f1add0ce3"


def test_provider_subclasses_real_memory_provider_abc_and_instantiates(tmp_path: Path) -> None:
    assert issubclass(HeartwoodHermesMemoryProvider, MemoryProvider)
    assert not inspect.isabstract(HeartwoodHermesMemoryProvider)

    provider = make_provider(tmp_path)
    assert isinstance(provider, MemoryProvider)
    assert provider.name == "heartwood"
    assert provider.is_available() is True
    provider.initialize("session-alpha", hermes_home=str(tmp_path))
    assert provider.initialized is True
    assert provider.session_id == "session-alpha"
    provider.shutdown()


def test_register_exposes_real_memory_provider_instance() -> None:
    class Collector:
        def __init__(self) -> None:
            self.provider: Any = None

        def register_memory_provider(self, provider: Any) -> None:
            self.provider = provider

    collector = Collector()
    register(collector)
    assert isinstance(collector.provider, HeartwoodHermesMemoryProvider)
    assert isinstance(collector.provider, MemoryProvider)


def test_hermes_plugin_loader_loads_register_entrypoint(tmp_path: Path) -> None:
    from plugins.memory import _load_provider_from_dir

    plugin_dir = tmp_path / "heartwood"
    plugin_dir.mkdir()
    (plugin_dir / "__init__.py").write_text(
        "from heartwood.adapters.hermes import HeartwoodHermesMemoryProvider\n\n"
        "def register(ctx):\n"
        "    ctx.register_memory_provider(HeartwoodHermesMemoryProvider())\n",
        encoding="utf-8",
    )

    provider = _load_provider_from_dir(plugin_dir)
    assert isinstance(provider, HeartwoodHermesMemoryProvider)
    assert isinstance(provider, MemoryProvider)


def test_hermes_lifecycle_governance_round_trip(tmp_path: Path) -> None:
    provider = make_provider(tmp_path)
    provider.initialize("session-alpha", hermes_home=str(tmp_path))
    assert isinstance(provider, MemoryProvider)

    provider.sync_turn(
        "Please remember the refund escalation playbook for duplicate charges.",
        "I will remember it. <memory-context>acct-HERMES-SECRET should never be retained.</memory-context>",
        session_id="session-alpha",
    )
    restricted_id = provider.db.remember(
        "Restricted Hermes billing token acct-HERMES-SECRET is for billing users only.",
        subject="customer:hermes-secret",
        created_by="agent:billing",
        source={"uri": "hermes://billing/secret"},
        policy=Policy(classification="restricted", roles=("billing",), pii=True),
    )

    prefetched = provider.prefetch("refund escalation duplicate charge playbook", session_id="session-alpha")
    secret_prefetch = provider.prefetch("acct-HERMES-SECRET", session_id="session-alpha")
    schemas = provider.get_tool_schemas()
    tool_names = {schema["name"] for schema in schemas}
    tool_recall = json.loads(provider.handle_tool_call("heartwood_recall", {"cue": "refund escalation playbook", "k": 3}))
    tool_write = json.loads(
        provider.handle_tool_call(
            "heartwood_remember",
            {
                "content": "Hermes tool-created memory for refund checklist.",
                "subject": "session:session-alpha",
                "classification": "internal",
            },
        )
    )

    assert "refund escalation" in prefetched.lower()
    assert "acct-HERMES-SECRET" not in prefetched + secret_prefetch
    assert restricted_id not in {item.get("id") for item in tool_recall["results"]}
    assert {"heartwood_recall", "heartwood_remember", "heartwood_forget"}.issubset(tool_names)
    assert tool_recall["results"], tool_recall
    assert tool_write["id"]
    assert provider.db.verify_audit() is True

    tool_forget = json.loads(
        provider.handle_tool_call(
            "heartwood_forget",
            {"subject": "session:session-alpha", "reason": "Hermes integration test cleanup"},
        )
    )
    after_forget = provider.prefetch("refund escalation duplicate charge playbook", session_id="session-alpha")
    assert tool_forget["purged"] >= 2
    assert "refund escalation" not in after_forget.lower()
    provider.shutdown()
