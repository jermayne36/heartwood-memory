"""Anthropic Memory Tool backend (memory_20250818) backed by Heartwood.

The Claude memory tool is a client-side, filesystem-like tool over `/memories`
with commands view/create/str_replace/insert/delete/rename. The app executes the
operations. Backing it with Heartwood upgrades the raw file store with governance the
tool itself does not provide:

  - every write is provenance-signed and audited (who/when/model);
  - edits create immutable, version-linked memories (supersedes chain) — a real
    edit history, not a silent overwrite;
  - files are policy-tagged (tenant/classification) and semantically indexed, so
    Heartwood `recall()` works across all memory-tool files;
  - delete physically purges the file's derived artifacts; full erasure
    (forget(subject)) crypto-shreds.

Wire it to the Anthropic SDK by subclassing `BetaAbstractMemoryTool` and routing
its abstract methods to `handle({...})`, or call `handle()` directly from your own
tool-result loop. Tool declaration: {"type": "memory_20250818", "name": "memory"}.
"""
from __future__ import annotations

import posixpath

from ..envelope import Policy

ROOT = "/memories"


class PathError(ValueError):
    pass


def _validate(path: str) -> str:
    """Reject traversal; confine to /memories (docs: MUST prevent traversal)."""
    if not isinstance(path, str) or not path:
        raise PathError("path required")
    if "\\" in path or "%2e" in path.lower() or ".." in path.split("/"):
        raise PathError(f"Error: illegal path {path}")
    norm = posixpath.normpath(path)
    if norm != ROOT and not norm.startswith(ROOT + "/"):
        raise PathError(f"Error: path {path} is outside {ROOT}")
    return norm


def _human(n: int) -> str:
    if n < 1024:
        return f"{n}B"
    if n < 1024 ** 2:
        return f"{n / 1024:.1f}K"
    return f"{n / 1024 ** 2:.1f}M"


def _numbered(content: str, start: int = 1, end: int | None = None) -> str:
    lines = content.split("\n")
    out = []
    for i, line in enumerate(lines, 1):
        if i < start:
            continue
        if end is not None and i > end:
            break
        out.append(f"{i:>6}\t{line}")
    return "\n".join(out)


class MemoryToolBackend:
    """Maps memory-tool commands onto a Heartwood instance. One backend per
    (tenant, owner-subject). `subject` is the erasure unit for full forget()."""

    def __init__(self, db, *, created_by="agent:memory", subject="memory-tool-user",
                 classification="internal", model_version="memory-tool"):
        self.db = db
        self.created_by = created_by
        self.subject = subject
        self.policy = Policy(classification=classification, visibility="tenant")
        self.model_version = model_version
        self.index: dict[str, str] = {}      # path -> current memory id
        self._rebuild_index()

    TOOL_SPEC = {"type": "memory_20250818", "name": "memory"}

    # -- dispatch -------------------------------------------------------- #
    def handle(self, cmd: dict) -> str:
        """Execute one memory-tool command, returning the exact result string the
        model expects. Errors are returned as strings (never raised) per the tool
        contract."""
        try:
            op = cmd.get("command")
            if op == "view":
                return self._view(_validate(cmd["path"]), cmd.get("view_range"))
            if op == "create":
                return self._create(_validate(cmd["path"]), cmd.get("file_text", ""))
            if op == "str_replace":
                return self._str_replace(_validate(cmd["path"]), cmd["old_str"], cmd["new_str"])
            if op == "insert":
                return self._insert(_validate(cmd["path"]), int(cmd["insert_line"]),
                                    cmd.get("insert_text", ""))
            if op == "delete":
                return self._delete(_validate(cmd["path"]))
            if op == "rename":
                return self._rename(_validate(cmd["old_path"]), _validate(cmd["new_path"]))
            return f"Error: unknown command {op!r}"
        except PathError as e:
            return str(e)
        except KeyError as e:
            return f"Error: missing parameter {e}"

    # -- commands -------------------------------------------------------- #
    def _view(self, path: str, view_range=None) -> str:
        if path in self.index:
            content = self.db.read_content(self.index[path]) or ""
            if view_range:
                body = _numbered(content, int(view_range[0]), int(view_range[1]))
            else:
                body = _numbered(content)
            return f"Here's the content of {path} with line numbers:\n{body}"
        # directory listing (path is a prefix)
        children = sorted(p for p in self.index if p == path or p.startswith(path.rstrip("/") + "/"))
        if not children and path != ROOT:
            return f"The path {path} does not exist. Please provide a valid path."
        lines = [f"Here're the files and directories up to 2 levels deep in {path}, "
                 f"excluding hidden items and node_modules:"]
        total = 0
        rows = []
        for p in children:
            size = len((self.db.read_content(self.index[p]) or "").encode())
            total += size
            rows.append((size, p))
        lines.append(f"{_human(total)}\t{path}")
        for size, p in rows:
            lines.append(f"{_human(size)}\t{p}")
        return "\n".join(lines)

    def _create(self, path: str, file_text: str) -> str:
        if path in self.index:
            return f"Error: File {path} already exists"
        mem_id = self.db.remember(
            file_text, subject=self.subject, created_by=self.created_by, kind="working",
            epistemic="model-generated", source={"kind": "memfile", "uri": path},
            policy=self.policy, model_version=self.model_version)
        self.index[path] = mem_id
        return f"File created successfully at: {path}"

    def _str_replace(self, path: str, old_str: str, new_str: str) -> str:
        if path not in self.index:
            return f"Error: The path {path} does not exist. Please provide a valid path."
        content = self.db.read_content(self.index[path]) or ""
        count = content.count(old_str)
        if count == 0:
            return f"No replacement was performed, old_str `{old_str}` did not appear verbatim in {path}."
        if count > 1:
            lines = [str(i) for i, ln in enumerate(content.split("\n"), 1) if old_str in ln]
            return (f"No replacement was performed. Multiple occurrences of old_str `{old_str}` "
                    f"in lines: {', '.join(lines)}. Please ensure it is unique")
        new_content = content.replace(old_str, new_str, 1)
        self._new_version(path, new_content)
        return "The memory file has been edited.\n" + _numbered(new_content)

    def _insert(self, path: str, insert_line: int, insert_text: str) -> str:
        if path not in self.index:
            return f"Error: The path {path} does not exist"
        content = self.db.read_content(self.index[path]) or ""
        lines = content.split("\n")
        if not (0 <= insert_line <= len(lines)):
            return (f"Error: Invalid `insert_line` parameter: {insert_line}. It should be within "
                    f"the range of lines of the file: [0, {len(lines)}]")
        lines.insert(insert_line, insert_text.rstrip("\n"))
        self._new_version(path, "\n".join(lines))
        return f"The file {path} has been edited."

    def _delete(self, path: str) -> str:
        targets = [p for p in self.index if p == path or p.startswith(path.rstrip("/") + "/")]
        if not targets:
            return f"Error: The path {path} does not exist"
        for p in targets:
            self.db.purge(self.index.pop(p), actor=self.created_by)
        return f"Successfully deleted {path}"

    def _rename(self, old_path: str, new_path: str) -> str:
        if old_path not in self.index:
            return f"Error: The path {old_path} does not exist"
        if new_path in self.index:
            return f"Error: The destination {new_path} already exists"
        content = self.db.read_content(self.index[old_path]) or ""
        # new governed memory at the new path; supersedes the old (provenance chain)
        old_id = self.index[old_path]
        new_id = self.db.remember(
            content, subject=self.subject, created_by=self.created_by, kind="working",
            epistemic="model-generated", source={"kind": "memfile", "uri": new_path},
            policy=self.policy, model_version=self.model_version, derived_from=[old_id])
        self.db.add_provenance_edge(new_id, old_id, "supersedes")
        self.db.purge(old_id, actor=self.created_by)
        del self.index[old_path]
        self.index[new_path] = new_id
        return f"Successfully renamed {old_path} to {new_path}"

    # -- helpers --------------------------------------------------------- #
    def _new_version(self, path: str, new_content: str):
        old_id = self.index[path]
        new_id = self.db.remember(
            new_content, subject=self.subject, created_by=self.created_by, kind="working",
            epistemic="model-generated", source={"kind": "memfile", "uri": path},
            policy=self.policy, model_version=self.model_version, derived_from=[old_id])
        self.db.add_provenance_edge(new_id, old_id, "supersedes")
        self.index[path] = new_id   # old version retained as immutable history

    def _rebuild_index(self):
        latest: dict[str, float] = {}
        for r in self.db.store.candidates(self.db.tenant):
            src = r.get("source") or {}
            if src.get("kind") != "memfile":
                continue
            uri = src.get("uri")
            if uri and r["created_at"] >= latest.get(uri, -1):
                latest[uri] = r["created_at"]
                self.index[uri] = r["id"]
