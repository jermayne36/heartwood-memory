# Heartwood shared memory for Herdr

An evaluation plugin for **Herdr 0.9.5+**, Python 3.11+, macOS or Linux. It calls
Heartwood's existing Python client; no signing, policy or retrieval engine is
implemented here. It is a community integration, not a Herdr endorsement.

Heartwood shares memory between agents. It does not stop two agents editing the
same file. Coordinate file ownership or use separate Git worktrees.

## Install locally

From this Git checkout, install Heartwood into a dedicated environment outside
your project. For example, replace the absolute paths below with your own:

```sh
python3.11 -m venv /absolute/path/to/heartwood-env
/absolute/path/to/heartwood-env/bin/python -m pip install -e '.[dev]'
herdr plugin link /absolute/path/to/heartwood-memory/plugins/herdr
herdr plugin config-dir heartwood.memory
```

Copy [config.example.json](config.example.json) to `config.json` in the directory
printed by the last command, then set:

| Field | Meaning |
|---|---|
| `repo_root` | Absolute path to the Git repository whose panes share notes. Linked worktrees with the same Git common directory also match. |
| `db_path` | Absolute persistent SQLite path outside the source tree. All participating clients must use this same file and tenant. Its parent directory is created if needed. |
| `tenant` | Explicit `tenant:...` identifier, shared by these agents. |

Start a **new Herdr server** with the environment's `bin` directory first on
`PATH`, so the manifest's `python3` has Heartwood installed:

```sh
PATH=/absolute/path/to/heartwood-env/bin:$PATH herdr --session memory-demo
```

An existing server keeps its launch environment. Linking a plugin does not run
its startup hook; agent events begin on the running server, and startup runs at
the next server start. Inspect failures with:

```sh
herdr plugin log list --plugin heartwood.memory
```

Herdr 0.9.5 accepts **GitHub shorthand**, not a local Git path, for `plugin install`.
Use `plugin link` for this checkout. After this PR is reviewed and merged, the
owner can install a pinned revision with:

```sh
herdr plugin install jermayne36/heartwood-memory/plugins/herdr --ref REVIEWED_COMMIT --yes
```

This repo only stages the plugin. No marketplace submission, GitHub topic change,
or external announcement is part of this change.

## Behavior

- `[[startup]]` runs once per Herdr server, after restore and socket readiness.
  It checks restored agent panes. New panes are handled when an agent is
  detected, rather than when an ordinary shell is created.
- `pane.agent_detected` and the first eligible `idle` status recall this repo's
  handoffs. The adapter requests up to 50 policy-filtered candidates, retains
  records with valid served signatures and content hashes, sorts their timestamp
  prefixed text, and sends at most eight through **`herdr agent prompt`**. This
  submits a prompt to the agent; it may start a turn. Notes are explicitly marked
  as untrusted reference data. No input is sent while blocked, working or unknown.
- Startup is checked once per socket/pane/agent/native-session combination,
  including an empty recall. This prevents recall/idle feedback loops. If an agent
  supplies no native session ID, the check lasts for that pane and agent kind;
  start a new pane for a fresh session. Concurrent startup/event invocations
  serialize through local marker files in Herdr's plugin state directory.
- `pane.agent_status_changed` with `agent_status=done` or `blocked` calls
  `Heartwood.remember`, which signs the record. `created_by` is the current
  Herdr agent **name** when available, otherwise its kind (for example `claude`
  or `codex`). A viewed completion may appear as `idle`; a matching Herdr
  `completion_seq` identifies that completion too. Completion/state sequences
  deduplicate repeated events. Delayed events for a replaced agent kind are ignored.
- The short note contains a UTC timestamp, status and at most 400 characters of
  Herdr's reported task `title`. If there is no title it says so. The plugin does
  **not** summarize or read terminal transcripts. For a useful handoff, the agent
  or its integration should report a concise task title before settling:

  ```sh
  herdr pane report-metadata "$HERDR_PANE_ID" --source my-agent-hook \
    --title 'Parser added; review empty input cases next'
  ```

The store's signing identity authenticates the record, not the human identity
behind an agent label. All local panes sharing a tenant trust the same local
store. Do not put secrets in task titles. The plugin does not expose tools for
deletion, key management or policy changes. Herdr's event history is ephemeral;
events missed while the plugin is disabled or failing are not recovered. Recall
is bounded relevance retrieval, not an exhaustive chronological database listing.

Plugin writers serialize on a lock beside the configured database. Standard
Heartwood transaction handling still applies to other clients. Keep a local
SQLite store on one host; this is not a cross-machine synchronization service.

## Reproduce the two-pane proof

Install a C compiler and Herdr 0.9.5, then run from the checkout:

```sh
/absolute/path/to/heartwood-env/bin/python plugins/herdr/smoke.py \
  --herdr /absolute/path/to/herdr
python3.11 -m ruff check .
python3.11 -m pytest -q
```

The smoke script links this local Git checkout in a new isolated Herdr config,
creates a temporary Git repo and real store, compiles two account-free terminal
fixtures named `claude` and `codex`, and opens two real panes. They are **stubs**,
not authenticated Claude Code or Codex sessions. Pane one finishes; pane two must
receive its signed handoff with `created_by=claude`. The script polls conditions,
prints `HERDR_TWO_PANE_SIGNED_HANDOFF=PASS`, and stops only its own server. All
artifacts remain in the printed temporary directory for inspection.

See the
[Claude Code + Codex guide](../../docs/guides/one-memory-claude-code-and-codex.md).

## Contract sources (checked 2026-10-22)

- [Herdr plugin manifest, startup, environment and local link](https://herdr.dev/docs/plugins/).
- [CLI input, custom agent reports and metadata](https://herdr.dev/docs/cli-reference/).
- [Socket lifecycle events and agent statuses](https://herdr.dev/docs/socket-api/).
- Source: [EventEnvelope and snake_case EventKind](https://github.com/herdrdev/herdr/blob/v0.9.5/src/api/schema/events.rs),
  [plugin hook runtime](https://github.com/herdrdev/herdr/blob/v0.9.5/src/app/api/plugins/runtime.rs).
  `HERDR_PLUGIN_EVENT` uses dotted names; `HERDR_PLUGIN_EVENT_JSON.event` uses
  snake_case (for example `pane_agent_status_changed`). These are different
  representations of the same event, verified by the real smoke run.

## Staged marketplace text — owner use only

**Name:** Heartwood shared memory. **Description:** One local, signed handoff
store for agents working in Herdr panes. Recall previous handoffs at agent
startup and record done/blocked task titles with the writer's name. **Install:**
the pinned GitHub command above after merge. **Limit:** shares context; does not
lock files or coordinate concurrent edits. The owner decides whether to add the
`herdr-plugin` GitHub topic that enables Herdr's marketplace indexing.
