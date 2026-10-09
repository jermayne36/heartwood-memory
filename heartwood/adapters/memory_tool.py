"""Anthropic Memory Tool backend (memory_20250818) backed by Heartwood.

The Claude memory tool is a client-side, filesystem-like tool over `/memories`
with commands view/create/str_replace/insert/delete/rename. The app executes the
operations. Backing it with Heartwood upgrades the raw file store with governance the
tool itself does not provide:

  - every write is provenance-signed and audited (who/when/model);
  - edits create immutable, version-linked memories (supersedes chain) — a real
    edit history, not a silent overwrite. The earlier version moves to review
    state `superseded`, so default recall returns only the current text;
  - files are policy-tagged (tenant/classification) and semantically indexed, so
    Heartwood `recall()` works across all memory-tool files;
  - delete physically purges the file's current version and retires its earlier
    versions from default recall; full erasure (forget(subject)) crypto-shreds.

Wire it to the Anthropic SDK by subclassing `BetaAbstractMemoryTool` and routing
its abstract methods to `handle({...})`, or call `handle()` directly from your own
tool-result loop. Tool declaration: {"type": "memory_20250818", "name": "memory"}.
"""
from __future__ import annotations

import posixpath

from ..envelope import Policy
from ..review import DEFAULT_HIDDEN_REVIEW_STATES, ReviewState

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
    (tenant, owner-subject). `subject` is the erasure unit for full forget().

    With `principal`, the backend acts as that principal: it lists, reads and
    edits only files whose current version the principal can read, cannot create
    or rename over a file it cannot read, and authors writes as the principal.
    Without one it sees every file in the tenant, for trusted in-process callers.
    The path index is built once, when the backend is constructed.

    An edit or rename supersedes every earlier version of the file the principal
    can read, in the same write, under the rules of `remember(supersedes=...)`:
    it is refused when one of them is another principal's (or approved) and the
    principal lacks the reviewer (or approver) role. A delete purges the current
    version and supersedes the earlier ones, and the same rule decides whether the
    principal may purge the current version. A superseded version is history,
    never the file: it is not listed or read, and does not come back after a
    restart."""

    def __init__(self, db, *, created_by=None, subject="memory-tool-user",
                 classification="internal", model_version="memory-tool", principal=None):
        if principal is not None and created_by is not None and created_by != principal.id:
            raise ValueError("created_by must equal principal.id when principal is given")
        self.db = db
        self.principal = principal
        self.created_by = created_by or (principal.id if principal is not None else "agent:memory")
        self.subject = subject
        self.policy = Policy(classification=classification, visibility="tenant")
        self.model_version = model_version
        self.index: dict[str, str] = {}      # path -> current memory id
        # Paths whose current version is older than a superseded one. Delete and
        # rename retire that version instead of purging it (see _rebuild_index).
        self._retire_only: set[str] = set()
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
        if self._current(path):
            content = self.db.read_content(self.index[path]) or ""
            if view_range:
                body = _numbered(content, int(view_range[0]), int(view_range[1]))
            else:
                body = _numbered(content)
            return f"Here's the content of {path} with line numbers:\n{body}"
        # directory listing (path is a prefix)
        children = sorted(p for p in self.index
                          if (p == path or p.startswith(path.rstrip("/") + "/")) and self._current(p))
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
        if self._taken(path):
            return f"Error: File {path} already exists"
        mem_id = self.db.remember(
            file_text, subject=self.subject, created_by=self.created_by, kind="working",
            epistemic="model-generated", source={"kind": "memfile", "uri": path},
            policy=self.policy, model_version=self.model_version)
        self.index[path] = mem_id
        return f"File created successfully at: {path}"

    def _str_replace(self, path: str, old_str: str, new_str: str) -> str:
        if not self._current(path):
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
        refused = self._new_version(path, new_content)
        if refused:
            return refused
        return "The memory file has been edited.\n" + _numbered(new_content)

    def _insert(self, path: str, insert_line: int, insert_text: str) -> str:
        if not self._current(path):
            return f"Error: The path {path} does not exist"
        content = self.db.read_content(self.index[path]) or ""
        lines = content.split("\n")
        if not (0 <= insert_line <= len(lines)):
            return (f"Error: Invalid `insert_line` parameter: {insert_line}. It should be within "
                    f"the range of lines of the file: [0, {len(lines)}]")
        lines.insert(insert_line, insert_text.rstrip("\n"))
        refused = self._new_version(path, "\n".join(lines))
        if refused:
            return refused
        return f"The file {path} has been edited."

    def _delete(self, path: str) -> str:
        targets = [p for p in self.index
                   if (p == path or p.startswith(path.rstrip("/") + "/")) and self._current(p)]
        if not targets:
            return f"Error: The path {path} does not exist"
        purged = [p for p in targets if p not in self._retire_only]
        retired = [self.index[p] for p in targets if p in self._retire_only]
        retired += self._earlier_versions(*targets)
        # Every check and retirement happens before anything is purged, so a
        # refusal deletes nothing.
        try:
            if self.principal is not None:
                # @fail-closed(memory-tool-delete-principal): purging a version needs
                # the authorship or role that superseding it does.
                for p in purged:
                    mem_id = self.index[p]
                    self.db._authorize_retirement(mem_id, self.db.store.get_meta(mem_id),
                                                  self.principal, verb="deleting")
            if retired:
                self.db.supersede(retired, actor=self.created_by, principal=self.principal,
                                  reason="memory tool delete")
        except (KeyError, PermissionError, RuntimeError, ValueError) as exc:
            return self._refused(path, "deleted", exc)
        for p in targets:
            mem_id = self.index.pop(p)
            if p in purged:
                self.db.purge(mem_id, actor=self.created_by)
            self._retire_only.discard(p)
        return f"Successfully deleted {path}"

    def _rename(self, old_path: str, new_path: str) -> str:
        if not self._current(old_path):
            return f"Error: The path {old_path} does not exist"
        if self._taken(new_path):
            return f"Error: The destination {new_path} already exists"
        content = self.db.read_content(self.index[old_path]) or ""
        # new governed memory at the new path; supersedes the old (provenance chain)
        old_id = self.index[old_path]
        try:
            new_id = self.db.remember(
                content, subject=self.subject, created_by=self.created_by, kind="working",
                epistemic="model-generated", source={"kind": "memfile", "uri": new_path},
                policy=self.policy, model_version=self.model_version, derived_from=[old_id],
                supersedes=[old_id, *self._earlier_versions(old_path)], principal=self.principal)
        except (KeyError, PermissionError, RuntimeError, ValueError) as exc:
            return self._refused(old_path, "renamed", exc)
        self.db.add_provenance_edge(new_id, old_id, "supersedes")
        if old_path not in self._retire_only:
            self.db.purge(old_id, actor=self.created_by)
        self._retire_only.discard(old_path)
        del self.index[old_path]
        self.index[new_path] = new_id
        return f"Successfully renamed {old_path} to {new_path}"

    # -- helpers --------------------------------------------------------- #
    def _current(self, path: str) -> str | None:
        """The path's current memory id, if this backend's principal can read it.

        The index keeps every path in the tenant, so create and rename still see
        an unreadable path as taken and cannot shadow it with a newer version.
        Every read and edit goes through here instead.
        """
        mem_id = self.index.get(path)
        if mem_id is None:
            return None
        meta = self.db.store.get_meta(mem_id)
        # @fail-closed(memory-tool-superseded): the newest version of a deleted file
        # is superseded history; it does not bring the file back.
        if meta is not None and meta.get("review_state") == ReviewState.SUPERSEDED.value:
            return None
        # @fail-closed(memory-tool-principal): a path whose current version the
        # principal cannot read is neither listed, read nor edited; an older readable
        # version does not reopen it.
        if self.principal is not None and not self.db.can_read(self.principal, meta):
            return None
        return mem_id

    def _taken(self, path: str) -> bool:
        """Whether `path` holds a file, readable or not. A path whose newest version
        is superseded was deleted and may be reused."""
        mem_id = self.index.get(path)
        if mem_id is None:
            return False
        meta = self.db.store.get_meta(mem_id)
        return meta is None or meta.get("review_state") != ReviewState.SUPERSEDED.value

    def _earlier_versions(self, *paths: str) -> list[str]:
        """Earlier versions of `paths` that default recall still returns and this
        backend's principal can read. Versions written before edits superseded
        them stay current until the file is next edited, renamed or deleted."""
        current = {self.index.get(path) for path in paths}
        earlier = []
        for meta in self.db.store.candidate_meta(self.db.tenant):
            source = meta.get("source") or {}
            if source.get("kind") != "memfile" or source.get("uri") not in paths or meta["id"] in current:
                continue
            if meta.get("review_state") in DEFAULT_HIDDEN_REVIEW_STATES:
                continue
            if self.principal is not None and not self.db.can_read(self.principal, meta):
                continue
            earlier.append(meta["id"])
        return earlier

    def _new_version(self, path: str, new_content: str) -> str | None:
        """Write the edited file as a new version that supersedes the old ones.
        Returns an error string if the edit is refused; nothing is written then."""
        old_id = self.index[path]
        try:
            new_id = self.db.remember(
                new_content, subject=self.subject, created_by=self.created_by, kind="working",
                epistemic="model-generated", source={"kind": "memfile", "uri": path},
                policy=self.policy, model_version=self.model_version, derived_from=[old_id],
                supersedes=[old_id, *self._earlier_versions(path)], principal=self.principal)
        except (KeyError, PermissionError, RuntimeError, ValueError) as exc:
            return self._refused(path, "edited", exc)
        self.db.add_provenance_edge(new_id, old_id, "supersedes")
        self.index[path] = new_id   # old versions retained as superseded history
        self._retire_only.discard(path)
        return None

    @staticmethod
    def _refused(path: str, verb: str, exc: Exception) -> str:
        # Role and transition refusals name no record; the others could carry an
        # id, so they get a fixed message.
        if isinstance(exc, (PermissionError, ValueError)):
            return f"Error: {path} was not {verb}: {exc}"
        return f"Error: {path} changed while it was being {verb}. View it and try again."

    def _rebuild_index(self):
        """Point each path at its newest version. When that version is superseded
        (the file was deleted) but an older version is still current, the older
        one is the file: a stale second writer's deleted version must not hide it
        from the principals who can read it. Delete never purged such a version,
        because the superseded one hid it, so it is marked retire-only."""
        newest: dict[str, dict] = {}
        live: dict[str, dict] = {}
        for meta in self.db.store.candidate_meta(self.db.tenant):
            src = meta.get("source") or {}
            uri = src.get("uri")
            if src.get("kind") != "memfile" or not uri:
                continue
            if meta["created_at"] >= newest.get(uri, meta)["created_at"]:
                newest[uri] = meta
            if (meta.get("review_state") not in DEFAULT_HIDDEN_REVIEW_STATES
                    and meta["created_at"] >= live.get(uri, meta)["created_at"]):
                live[uri] = meta
        for uri, meta in newest.items():
            if meta.get("review_state") == ReviewState.SUPERSEDED.value and uri in live:
                meta = live[uri]
                self._retire_only.add(uri)
            self.index[uri] = meta["id"]
