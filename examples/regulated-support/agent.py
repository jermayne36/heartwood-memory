"""A scripted support agent that handles a ticket through Heartwood.

In production, Claude drives these operations via the MCP server / memory tool
(heartwood/adapters). Here the calls are scripted so the demo is deterministic and
runs without an LLM. The agent:

  1. recalls governed knowledge (policy-enforced for the acting principal);
  2. drafts an answer that CITES its sources (provenance);
  3. records a governed 'answer' memory linked to those sources (derived_from);
  4. writes a working note via the Anthropic memory-tool interface.
"""
from __future__ import annotations

from heartwood.adapters import MemoryToolBackend
from heartwood.envelope import Policy
from heartwood.policy import Principal


def handle_ticket(db, principal: Principal, ticket_id: str, query: str, k: int = 20) -> dict:
    out = db.recall(query, principal=principal, k=k)

    # enrich each recalled memory with its classification (for the report)
    recalled = []
    for r in out["results"]:
        meta = db.store.get_meta(r["id"])
        recalled.append({**r, "classification": meta["classification"],
                         "subject": meta["subject"], "source": meta["source"]})

    cited = recalled[:4]
    restricted_used = [c for c in cited if c["classification"] == "restricted"]

    # draft an answer citing sources; the clinical sentence only appears if the
    # principal was actually allowed to recall the clinical record.
    lines = [f"Ticket {ticket_id} — handled by {principal.id} (clearance={principal.clearance}):"]
    for i, c in enumerate(cited, 1):
        lines.append(f"  [{i}] {c['content']}  (src={c['source'].get('uri')}, "
                     f"{c['epistemic']}, sig_valid={c['provenance'].get('signature_valid')})")
    answer_text = "\n".join(lines)

    # record a governed, provenance-linked answer memory
    answer_id = db.remember(
        answer_text, subject=f"ticket:{ticket_id}", created_by=principal.id, kind="procedural",
        epistemic="model-generated", model_version="agent:support-v1",
        source={"kind": "derived", "uri": f"ticket://{ticket_id}/answer"},
        policy=Policy(classification="internal"), derived_from=[c["id"] for c in cited])

    # write a working note via the Anthropic memory-tool interface (governed)
    backend = MemoryToolBackend(db, created_by=principal.id, subject=f"ticket:{ticket_id}")
    note_path = f"/memories/ticket-{ticket_id}.md"
    # The working note references the governed answer record (which holds the
    # source provenance under its own, inherited classification) rather than
    # embedding source content/URIs — so the note doesn't become a side channel.
    note = (f"# Ticket {ticket_id}\nQuery: {query}\n"
            f"Status: answer drafted — see governed answer record {answer_id} for cited sources.\n")
    backend.handle({"command": "create", "path": note_path, "file_text": note})

    return {
        "ticket": ticket_id, "principal": principal.id, "clearance": principal.clearance,
        "recall_id": out["recall_id"], "index_lag": out["index_lag"],
        "recalled": recalled, "cited": cited, "restricted_used": restricted_used,
        "answer_id": answer_id, "answer_text": answer_text, "note_path": note_path,
    }
