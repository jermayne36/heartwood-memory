"""MCP tools read only what the server's principal can read.

Binding the identity arguments is not enough on its own: a tool that takes no
identity argument can still read past the principal if it decrypts through an
unfiltered path. Each case below names or cites a synthetic canary that the
default principal (agent:mcp, internal clearance, no roles) cannot read, then
checks the canary never comes back, the hidden file is not changed, and the
audit row names the server's principal. Positive controls run first: a
principal that may read the canary does get it, so a test cannot pass only
because nothing resolves.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from types import SimpleNamespace

import pytest
from mcp.server.fastmcp.exceptions import ToolError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Heartwood  # noqa: E402
from heartwood.adapters.mcp_server import (  # noqa: E402
    _mutating_exposure_warning,
    allowed_tools_from_env,
    build_server,
)
from heartwood.adapters.memory_tool import MemoryToolBackend  # noqa: E402
from heartwood.envelope import Policy, hash_content  # noqa: E402
from heartwood.importers.markdown import dev_models  # noqa: E402
from heartwood.policy import Principal  # noqa: E402

TENANT = "tenant:acme"
ALL_TOOLS = "remember,recall,explain_recall,forget,evaluate_egress,assess_faithfulness,memory,health"
HIDDEN_POLICY = Policy(classification="restricted", roles=("finance",), visibility="private")
ALICE = Principal("agent:alice", TENANT, roles=("finance",), clearance="restricted")

HIDDEN_FILE = "/memories/alice/plan.md"
TEAM_FILE = "/memories/team/notes.md"
SHARED_FILE = "/memories/shared/plan.md"
FILE_CANARY = "MEMFILE-CANARY"
SPAN_CANARY = "SPANSECRET-CANARY wire 4417 to account 99"
# The claim repeats the hidden fact but not the canary marker, so a "leak" in
# the output can only come from the server.
SPAN_CLAIM = "wire 4417 to account 99"
OPEN_SPAN = "Refund policy allows expedited review for duplicate charges."
MODEL = {"runtime": "external", "provider": "p", "region": "r", "retention": "zero", "training_opt_out": True}
EGRESS_POLICY = {"allow_external_models": True, "allowed_providers": ["p"], "allowed_regions": ["r"]}


@pytest.fixture()
def seeded(tmp_path, monkeypatch):
    monkeypatch.setenv("HEARTWOOD_MCP_ALLOWED_TOOLS", ALL_TOOLS)
    embedder, reranker = dev_models()
    db = Heartwood(path=tmp_path / "heartwood.db", tenant=TENANT, embedder=embedder, reranker=reranker)
    hidden_id = db.remember(
        "Restricted finance summary.", subject="acme:restricted", created_by="agent:alice",
        policy=HIDDEN_POLICY, source_spans=({"span_id": "s1", "text": SPAN_CANARY},),
    )
    # A visible row that cites the hidden one: recall hands its id to any reader.
    visible_id = db.remember(
        "Visible orbit note citing prior analysis.", subject="acme:visible", created_by="agent:writer",
        source_ids=(hidden_id,), source_spans=({"span_id": "s2", "text": OPEN_SPAN},),
    )
    file_id = db.remember(
        f"{FILE_CANARY} alice plan", subject="alice:notes", created_by="agent:alice", kind="working",
        source={"kind": "memfile", "uri": HIDDEN_FILE}, policy=HIDDEN_POLICY,
    )
    db.remember(
        "Team notes: ship on Friday.", subject="team:notes", created_by="agent:writer", kind="working",
        source={"kind": "memfile", "uri": TEAM_FILE},
    )
    # A readable first version, then a current version the default principal cannot read.
    for content, policy in (("Shared plan v1.", Policy()), (f"{FILE_CANARY} shared plan v2.", HIDDEN_POLICY)):
        db.remember(content, subject="shared:plan", created_by="agent:alice", kind="working",
                    source={"kind": "memfile", "uri": SHARED_FILE}, policy=policy)
    try:
        yield SimpleNamespace(db=db, hidden_id=hidden_id, visible_id=visible_id, file_id=file_id)
    finally:
        db.close()


def _call(server, name, arguments):
    output = asyncio.run(server.call_tool(name, arguments))
    if isinstance(output, tuple):
        output = output[1]
    if isinstance(output, dict):
        return output["result"] if set(output) == {"result"} else output
    text = output[0].text
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _attempt(server, name, arguments):
    try:
        return _call(server, name, arguments)
    except ToolError as exc:
        return exc


def _span(memory_id, text=None):
    span = {"span_id": "x", "memory_id": memory_id, "text_ref": "encrypted", "text_index": 0}
    if text is not None:
        span["content_hash"] = hash_content(text)
    return span


def _egress(span, **extra):
    return {"request": {"request_id": "probe", "model": MODEL, "policy": EGRESS_POLICY,
                        "source_spans": [span], **extra}}


def _faithfulness(span, claim, **extra):
    return {"candidate": {"candidate_id": "probe", "source_spans": [span],
                          "claims": [{"claim_id": "c1", "text": claim, "source_span_ids": ["x"]}], **extra}}


def _memfiles(db, path):
    return [m for m in db.store.candidate_meta(TENANT) if (m.get("source") or {}).get("uri") == path]


def test_memory_view_lists_and_reads_only_files_the_principal_can_read(seeded):
    """@positive-control(memory-tool-principal)"""
    alice, _db, _backend = build_server(seeded.db, principal=ALICE)
    assert FILE_CANARY in _call(alice, "memory", {"command": "view", "path": HIDDEN_FILE})
    assert FILE_CANARY in _call(alice, "memory", {"command": "view", "path": SHARED_FILE})

    server, _db, _backend = build_server(seeded.db)
    listing = _call(server, "memory", {"command": "view", "path": "/memories"})
    assert TEAM_FILE in listing
    assert HIDDEN_FILE not in listing and SHARED_FILE not in listing
    # The older readable version of SHARED_FILE does not reopen it.
    for path in (HIDDEN_FILE, "/memories/alice", SHARED_FILE):
        out = _call(server, "memory", {"command": "view", "path": path})
        assert FILE_CANARY not in out
        assert out == f"The path {path} does not exist. Please provide a valid path."


@pytest.mark.parametrize(
    "arguments",
    [
        {"command": "str_replace", "path": HIDDEN_FILE, "old_str": "alice", "new_str": "TAMPERED"},
        {"command": "insert", "path": HIDDEN_FILE, "insert_line": 0, "insert_text": "TAMPERED"},
        {"command": "rename", "old_path": HIDDEN_FILE, "new_path": "/memories/mine.md"},
        {"command": "delete", "path": HIDDEN_FILE},
        {"command": "delete", "path": "/memories/alice"},
        # Not a hole on the unfiltered index; guards the filtered one against
        # shadowing a hidden file with a new current version.
        {"command": "create", "path": HIDDEN_FILE, "file_text": "TAMPERED"},
    ],
    ids=["str_replace", "insert", "rename", "delete", "delete-dir", "create"],
)
def test_memory_edits_to_a_file_the_principal_cannot_read_are_refused(seeded, arguments):
    """@positive-control(memory-tool-principal)"""
    server, _db, _backend = build_server(seeded.db)
    out = _call(server, "memory", arguments)
    assert FILE_CANARY not in out
    assert out.startswith("Error"), out
    assert [m["id"] for m in _memfiles(seeded.db, HIDDEN_FILE)] == [seeded.file_id]
    assert seeded.db.read_content(seeded.file_id) == f"{FILE_CANARY} alice plan"
    assert _memfiles(seeded.db, "/memories/mine.md") == []


def test_memory_tool_writes_are_authored_as_the_server_principal(seeded):
    server, _db, _backend = build_server(seeded.db)
    created = _call(server, "memory", {"command": "create", "path": "/memories/mcp/new.md", "file_text": "hello"})
    assert created == "File created successfully at: /memories/mcp/new.md"
    assert [m["created_by"] for m in _memfiles(seeded.db, "/memories/mcp/new.md")] == ["agent:mcp"]


def test_evaluate_egress_returns_no_text_from_a_memory_the_principal_cannot_read(seeded):
    """@positive-control(span-principal-read)"""
    alice, _db, _backend = build_server(seeded.db, principal=ALICE)
    payload = _call(alice, "evaluate_egress", _egress(_span(seeded.hidden_id, SPAN_CANARY)))["payload"]
    assert payload[0]["text"] == SPAN_CANARY

    server, _db, _backend = build_server(seeded.db)
    recalled = _call(server, "recall", {"cue": "orbit note citing prior analysis", "k": 8})
    assert seeded.hidden_id in [sid for row in recalled["results"] for sid in row["source_ids"]]
    for span in (_span(seeded.hidden_id), _span(seeded.hidden_id, SPAN_CANARY)):
        out = _call(server, "evaluate_egress", _egress(span))
        assert "SPANSECRET-CANARY" not in json.dumps(out)
        assert out["decision"] == "external_model_allowed"
        assert out["payload"][0]["text"] == ""


def test_encrypted_span_needs_its_content_hash_even_when_readable(seeded):
    """@positive-control(span-principal-read)"""
    server, _db, _backend = build_server(seeded.db)
    with_hash = _call(server, "evaluate_egress", _egress(_span(seeded.visible_id, OPEN_SPAN)))
    assert with_hash["payload"][0]["text"] == OPEN_SPAN
    without_hash = _call(server, "evaluate_egress", _egress(_span(seeded.visible_id)))
    assert without_hash["payload"][0]["text"] == ""

    alice, _db, _backend = build_server(seeded.db, principal=ALICE)
    out = _call(alice, "evaluate_egress", _egress(_span(seeded.hidden_id)))
    assert "SPANSECRET-CANARY" not in json.dumps(out)


def test_assess_faithfulness_is_no_oracle_on_hidden_span_text(seeded):
    """@positive-control(span-principal-read)"""
    def verdict(server, span, claim):
        out = _call(server, "assess_faithfulness", _faithfulness(span, claim))
        return out["decision"], out["claims"][0]["support_score"], out["claims"][0]["label"]

    alice, _db, _backend = build_server(seeded.db, principal=ALICE)
    assert verdict(alice, _span(seeded.hidden_id, SPAN_CANARY), SPAN_CLAIM)[0] == "accepted"

    server, _db, _backend = build_server(seeded.db)
    for span in (_span(seeded.hidden_id), _span(seeded.hidden_id, SPAN_CANARY)):
        true_claim = verdict(server, span, SPAN_CLAIM)
        false_claim = verdict(server, span, "the moon is made of cheese")
        assert true_claim == false_claim
        assert true_claim[0] != "accepted"


@pytest.mark.parametrize(
    ("tool", "field", "arguments"),
    [
        ("evaluate_egress", "request", lambda ids: _egress(_span(ids.visible_id, OPEN_SPAN), actor="human:owner")),
        ("assess_faithfulness", "candidate",
         lambda ids: _faithfulness(_span(ids.visible_id, OPEN_SPAN), OPEN_SPAN, actor="human:owner")),
    ],
    ids=["evaluate_egress", "assess_faithfulness"],
)
def test_client_cannot_forge_the_audit_actor(seeded, tool, field, arguments):
    """@positive-control(mcp-principal-actor)"""
    server, _db, _backend = build_server(seeded.db)
    forged = _attempt(server, tool, arguments(seeded))
    assert isinstance(forged, ToolError), forged
    assert f"{tool}: {field}.actor cannot be set by an MCP client" in str(forged)

    honest = arguments(seeded)
    honest[field].pop("actor")
    _call(server, tool, honest)
    principals = [row[0] for row in seeded.db.store.conn.execute(
        "SELECT principal FROM audit_log WHERE action=? ORDER BY seq", (tool,))]
    assert principals == ["agent:mcp"]


def test_explain_recall_explains_only_the_principals_own_recalls(seeded):
    """@positive-control(explain-recall-principal)"""
    # Two servers that share one store, as an embedding host might run them.
    finance, _db, _backend = build_server(seeded.db, principal=Principal("agent:finance-bot", TENANT, roles=("finance",)))
    server, _db, _backend = build_server(seeded.db)
    cue = "orbit note citing prior analysis"
    recall_id = _call(finance, "recall", {"cue": cue, "k": 8})["recall_id"]
    assert _call(finance, "explain_recall", {"recall_id": recall_id})["cue"] == cue
    assert _call(server, "explain_recall", {"recall_id": recall_id}) == {"error": "unknown recall_id"}


def test_source_text_tools_are_announced_when_exposed():
    warning = _mutating_exposure_warning(allowed_tools_from_env("recall,evaluate_egress,assess_faithfulness"))
    assert warning is not None
    assert "evaluate_egress" in warning and "assess_faithfulness" in warning


def test_server_refuses_a_memory_backend_not_bound_to_its_principal(seeded):
    """@positive-control(mcp-principal-memory-backend)"""
    with pytest.raises(ValueError, match="memory backend must be built with principal="):
        build_server(seeded.db, backend=MemoryToolBackend(seeded.db))
    with pytest.raises(ValueError, match="memory backend must be built with principal="):
        build_server(seeded.db, backend=MemoryToolBackend(seeded.db, principal=ALICE))
    server, _db, backend = build_server(seeded.db, backend=MemoryToolBackend(seeded.db, principal=ALICE),
                                        principal=ALICE)
    assert FILE_CANARY in _call(server, "memory", {"command": "view", "path": HIDDEN_FILE})
