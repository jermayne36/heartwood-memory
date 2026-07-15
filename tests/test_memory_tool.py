"""Tests the Anthropic memory-tool backend + the governance it adds.

Exercises all six commands against the exact response contract, the path-traversal
guard, and the Heartwood governance the raw file backend lacks: version history
(supersedes chain), audit integrity, semantic recall across memory-tool files,
and crypto-shred erasure.

Run:  python tests/test_memory_tool.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heartwood import Principal, Heartwood                       # noqa: E402
from heartwood.adapters import MemoryToolBackend, route_tool_use  # noqa: E402

TENANT = "tenant:acme"
NOTES = "/memories/notes.txt"


def main():
    db = Heartwood(path=":memory:", tenant=TENANT)
    mt = MemoryToolBackend(db, created_by="agent:asst", subject="user:jane")
    assert mt.TOOL_SPEC == {"type": "memory_20250818", "name": "memory"}

    # --- create ---------------------------------------------------------- #
    r = mt.handle({"command": "create", "path": NOTES,
                   "file_text": "Project notes:\n- Discussed timeline\n- Defined next steps\n"})
    assert r == f"File created successfully at: {NOTES}", r
    assert mt.handle({"command": "create", "path": NOTES, "file_text": "x"}).startswith("Error: File")
    print("[1] create + already-exists error OK")

    # --- view dir + file ------------------------------------------------- #
    d = mt.handle({"command": "view", "path": "/memories"})
    assert NOTES in d and "up to 2 levels deep" in d, d
    f = mt.handle({"command": "view", "path": NOTES})
    assert "with line numbers" in f and "\t- Discussed timeline" in f, f
    print("[2] view dir listing + line-numbered file OK")

    # --- str_replace ----------------------------------------------------- #
    r = mt.handle({"command": "str_replace", "path": NOTES,
                   "old_str": "Discussed timeline", "new_str": "Locked the timeline"})
    assert r.startswith("The memory file has been edited."), r
    assert "Locked the timeline" in mt.handle({"command": "view", "path": NOTES})
    miss = mt.handle({"command": "str_replace", "path": NOTES, "old_str": "nope", "new_str": "y"})
    assert miss.startswith("No replacement was performed"), miss
    print("[3] str_replace (edit + not-found) OK")

    # --- insert ---------------------------------------------------------- #
    r = mt.handle({"command": "insert", "path": NOTES, "insert_line": 1,
                   "insert_text": "- Reviewed budget"})
    assert r == f"The file {NOTES} has been edited.", r
    assert "- Reviewed budget" in mt.handle({"command": "view", "path": NOTES})
    print("[4] insert OK")

    # --- governance: version history + audit + semantic recall ----------- #
    versions = [row for row in db.store.candidates(TENANT)
                if (row.get("source") or {}).get("uri") == NOTES]
    assert len(versions) >= 3, f"expected version history, got {len(versions)}"
    assert db.verify_audit() is True
    out = db.recall("what did we decide about the project schedule?",
                    principal=Principal(id="agent:asst", tenant=TENANT, clearance="internal"))
    assert any("timeline" in r["content"] for r in out["results"]), "memory-tool file must be recallable"
    print(f"[5] governance: {len(versions)} immutable versions, audit verified, "
          f"file semantically recallable")

    # --- path traversal guard ------------------------------------------- #
    assert mt.handle({"command": "view", "path": "/etc/passwd"}).startswith("Error")
    assert mt.handle({"command": "view", "path": "/memories/../secret"}).startswith("Error")
    print("[6] path-traversal attempts rejected")

    # --- rename ---------------------------------------------------------- #
    mt.handle({"command": "create", "path": "/memories/draft.txt", "file_text": "draft"})
    r = mt.handle({"command": "rename", "old_path": "/memories/draft.txt",
                   "new_path": "/memories/final.txt"})
    assert r == "Successfully renamed /memories/draft.txt to /memories/final.txt", r
    assert mt.handle({"command": "view", "path": "/memories/draft.txt"}).startswith("The path")
    assert "final" in mt.handle({"command": "view", "path": "/memories/final.txt"})
    print("[7] rename OK")

    # --- delete ---------------------------------------------------------- #
    r = mt.handle({"command": "delete", "path": "/memories/final.txt"})
    assert r == "Successfully deleted /memories/final.txt", r
    assert mt.handle({"command": "view", "path": "/memories/final.txt"}).startswith("The path")
    print("[8] delete (governed purge) OK")

    # --- SDK routing helper --------------------------------------------- #
    tr = route_tool_use(mt, {"id": "toolu_x", "input": {"command": "view", "path": "/memories"}})
    assert tr["type"] == "tool_result" and tr["tool_use_id"] == "toolu_x" and NOTES in tr["content"]
    print("[9] route_tool_use produces a valid tool_result block")

    # --- erasure: crypto-shred the subject ------------------------------ #
    rcpt = db.forget("user:jane", mode="hard", reason="DSAR", legal_basis="GDPR Art.17")
    assert rcpt["key_shredded"] and rcpt["purged"] >= 1
    after = db.recall("project timeline", principal=Principal(id="agent:asst", tenant=TENANT))
    assert after["results"] == [], "memory-tool files must be erasable"
    print(f"[10] forget(hard): purged={rcpt['purged']}, post-erasure recall=0")

    print("\nALL MEMORY-TOOL ADAPTER TESTS PASSED")


if __name__ == "__main__":
    main()
