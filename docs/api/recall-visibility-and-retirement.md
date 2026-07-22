# Recall Visibility and Record Retirement

Default recall answers one question: **what is true right now?** This page states
the visibility contract that answer rests on, and the preservation-safe way to
retire a record without destroying it.

## Default recall visibility contract

`Heartwood.recall(cue, principal=...)` with no `filters` applies three gates
before ranking (`heartwood/client.py`, `match()`):

| Gate | Excluded by default | Opt back in with |
| --- | --- | --- |
| Index state | rows with `indexed = 0` | (none — reindex the row) |
| Validity window | `valid_until <= now`, `valid_from > now` | `filters={"include_expired": True}` |
| Review state | `rejected`, `disputed`, `superseded` | `filters={"include_review_states": [...]}` |

Every one of these decisions is reported on the recall receipt, so a caller can
always tell what was filtered and against which instant:

```python
out = db.recall("retention policy", principal=reader)
explained = db.explain_recall(out["recall_id"])

explained["validity_enforced"]      # True unless include_expired was set
explained["effective_at"]           # the resolved reference time
explained["hidden_review_states"]   # ["disputed", "rejected", "superseded"]
```

### `effective_at` moves the clock; it does not switch the filter on

`filters={"effective_at": ...}` selects the instant that validity is judged
against — use it for back-dated ("what did we believe on 1 June?") recall. It is
**not** an enable flag. Omitting it, or supplying an empty or unparseable value,
falls back to the current time rather than disabling validity filtering.

```python
# Back-dated view: returns records that were live on 2026-06-01.
db.recall(cue, principal=reader, filters={"effective_at": "2026-06-01T00:00:00Z"})

# Audit view: returns expired and not-yet-valid records too.
db.recall(cue, principal=reader, filters={"include_expired": True})
```

## Retiring a record

Three mechanisms exist. They are not interchangeable — only the first two
preserve the record.

### 1. Expire it — `valid_until` (preserves the row, reversible)

Set a validity window at write time, or update `valid_until` on the stored row.
The record stops appearing in default recall the instant the window closes,
stays fully readable via `include_expired` or a back-dated `effective_at`, and
its content, provenance chain, and signatures are untouched.

Use this for **time-boxed operational records** — session snapshots, working
notes, anything with a natural shelf life. Prefer it when the record may need to
be read again later, or when the retirement is scheduled rather than final.

### 2. Supersede it — `transition_review` (preserves the row, terminal)

```python
db.transition_review(mem_id, "superseded", reviewer_principal, reason="replaced by v2")
```

Requires the `reviewer` or `approver` role, validates the transition against
`LEGAL_TRANSITIONS` (`heartwood/review.py`), writes a `review_transition` audit
event, and leaves the row and its `indexed` flag intact. The record drops out of
default recall as a hidden review state and is recoverable with
`include_review_states=["superseded"]`.

`superseded` is terminal — it has no legal exits, and `approve()` refuses it.
Use this when a **newer record replaces this one** and the replacement is final.

### 3. Purge it — `db.purge` (destroys the row)

`db.purge(mem_id)` physically deletes the row and removes it from the index
(`heartwood/client.py`). It appends a `purge` audit event, so the *deletion* is
on the tamper-evident record — but the content is gone. It does not crypto-shred
the subject key; that is reserved for `forget()`.

Use this only when the content itself must not persist.

## Warning: `import-markdown --update` purges, it does not supersede

The markdown importer's update path is destructive, and its vocabulary hides
that. When `--update` re-imports a source file whose content hash has changed,
`_purge_superseded_rows` (`heartwood/importers/markdown.py`) calls `db.purge()`
on every prior row for that source path.

The receipt field is named `superseded` / `superseded_count`, but **no row is
moved to `review_state = "superseded"`.** The prior rows are deleted. A field
named for mechanism 2 is performing mechanism 3.

**Do not use `--update` to retire a governed operational record.** For any record
under review, retention, or audit obligation:

1. Retire it explicitly first — `transition_review(..., "superseded")` for a
   final replacement, or `valid_until` for a time-boxed one.
2. Confirm the retirement landed: `db.store.get_meta(mem_id)` shows the new
   `review_state` or `valid_until`, and the row still exists.
3. Only then re-import, so the importer finds a matching content hash and has
   no stale prior row to purge.

To find what an `--update` run *would* delete before running it, list the prior
rows for the source path with `db.store.memories_by_source_path(tenant, path)`
and compare each `content_hash` against the incoming file.
