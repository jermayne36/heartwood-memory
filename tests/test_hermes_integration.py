"""Contract tests for Heartwood against the real Hermes Agent MemoryProvider ABC.

Validated dependency pin:
- Hermes Agent v0.22.4, commit 4d04303818b61bf3aa09278af48356315515965b

Run with HEARTWOOD_TEST_HERMES=1; missing/broken Hermes then fails collection.
Source installs report distribution version 0.0.0; verify the actual checkout.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import inspect
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import pytest

from heartwood import Heartwood
from heartwood.adapters.hermes import HeartwoodHermesMemoryProvider, register
from heartwood.envelope import Policy
from heartwood.policy import Principal

if os.environ.get("HEARTWOOD_TEST_HERMES") != "1":
    pytest.skip("Hermes opt-in: run plugins/hermes/check_release.sh", allow_module_level=True)

# @fail-closed(hermes-release-opt-in)
# Deliberately not importorskip: the release lane must fail if Hermes is absent.
from agent import memory_provider as hermes_memory_provider  # noqa: E402

MemoryProvider = hermes_memory_provider.MemoryProvider
HERMES_AGENT_VERSION = "0.22.4"
HERMES_AGENT_TAG = "v0.22.4"
HERMES_AGENT_COMMIT = "4d04303818b61bf3aa09278af48356315515965b"
PLUGIN_DIR = Path(__file__).resolve().parents[1] / "plugins" / "hermes"
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
    assert importlib.metadata.version("hermes-agent") == "0.0.0"
    root = Path(hermes_memory_provider.__file__).resolve().parents[1]
    actual = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    assert actual == HERMES_AGENT_COMMIT, f"expected {HERMES_AGENT_TAG}, got {actual}"


def test_opt_in_fails_collection_when_hermes_is_missing() -> None:
    # @positive-control(hermes-release-opt-in)
    script = """
import importlib.abc
import sys
class MissingHermes(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "agent" or fullname.startswith("agent."):
            raise ModuleNotFoundError("Hermes deliberately unavailable")
sys.meta_path.insert(0, MissingHermes())
import pytest
raise SystemExit(pytest.main(["tests/test_hermes_integration.py", "-q"]))
"""
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=PLUGIN_DIR.parents[1],
        env={**os.environ, "HEARTWOOD_TEST_HERMES": "1"}, capture_output=True, text=True,
    )
    assert result.returncode == 2, result.stdout + result.stderr
    assert "Hermes deliberately unavailable" in result.stdout + result.stderr
    assert "skipped" not in result.stdout


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
    shutil.copy(PLUGIN_DIR / "__init__.py", plugin_dir / "__init__.py")

    provider = _load_provider_from_dir(plugin_dir)
    assert isinstance(provider, HeartwoodHermesMemoryProvider)
    assert isinstance(provider, MemoryProvider)


def test_session_switch_tracks_the_current_hermes_session(tmp_path: Path) -> None:
    provider = make_provider(tmp_path)
    provider.initialize("session-alpha", hermes_home=str(tmp_path))
    provider.on_session_switch("session-beta", parent_session_id="session-alpha", reset=True)
    provider.sync_turn("My project colour is aubergine.", "Saved.", turn_author={"id": "test-user"})
    recalled = json.loads(provider.handle_tool_call(
        "heartwood_recall", {"cue": "project colour", "subject": "session:session-beta"},
    ))
    assert any("aubergine" in row["content"] for row in recalled["results"])
    assert provider.session_id == "session-beta"
    provider.db.close()


def test_real_manager_stores_and_recalls_a_fact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent.memory_manager import MemoryManager
    from hermes_cli.config import load_config, save_config
    from hermes_constants import reset_hermes_home_override, set_hermes_home_override
    from plugins.memory import load_memory_provider

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    plugin_dir = tmp_path / "plugins" / "heartwood"
    plugin_dir.mkdir(parents=True)
    shutil.copy(PLUGIN_DIR / "__init__.py", plugin_dir / "__init__.py")
    shutil.copy(PLUGIN_DIR / "plugin.yaml", plugin_dir / "plugin.yaml")
    token = set_hermes_home_override(tmp_path)
    manager = MemoryManager()
    db = make_db(tmp_path / "session.sqlite", "tenant:hermes-session")
    try:
        config = load_config()
        config["memory"]["provider"] = "heartwood"
        save_config(config)
        provider = load_memory_provider(load_config()["memory"]["provider"])
        assert isinstance(provider, MemoryProvider)
        # Real database, deterministic test models; no model API/account or network.
        provider.db = db
        manager.add_provider(provider)
        manager.initialize_all("session-demo", hermes_home=str(tmp_path))
        assert provider.initialized
        manager.sync_all("My project colour is aubergine.", "I will remember that.", session_id="session-demo")
        assert manager.flush_pending(timeout=10), "Hermes background write did not finish"
        manager.on_session_switch("session-next", parent_session_id="session-demo")
        assert provider.session_id == "session-next"
        recall = json.loads(manager.handle_tool_call("heartwood_recall", {"cue": "project colour"}))
        assert any("aubergine" in row["content"] for row in recall["results"]), recall
        prefetched = manager.prefetch_all("What is my project colour?", session_id="session-next")
        assert "aubergine" in prefetched
    finally:
        manager.shutdown_all()
        db.close()
        reset_hermes_home_override(token)


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
