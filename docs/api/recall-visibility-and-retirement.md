# Recall Visibility and Record Retirement

Default recall answers one question: **what is true right now?** This page states
the visibility contract that answer rests on, and the preservation-safe way to
retire a record without destroying it.

## Default recall visibility contract

`Heartwood.recall(cue, principal=...)` with no `filters` applies three gates
before ranking (`heartwood/client.py`, `match()`):

| Gate | Excluded by default | Opt back in with |
| --- | --- | --- |
| Index state | rows with `indexed = 0` | no filter reaches these — reinstate with `set_indexed` |
| Validity window | `valid_until <= now`, `valid_from > now` | `filters={"include_expired": True}` |
| Review state | `rejected`, `disputed`, `superseded` | `filters={"include_review_states": [...]}` |

Index state is the hardest of the three: an expired or superseded record is still
reachable by an explicit opt-in, an unindexed one is reachable by none. Treat
`indexed = 0` as removal from the answerable corpus, not as a soft filter.

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

Four mechanisms exist. They are not interchangeable — only the first three
preserve the record. Every one of them writes an audit event; see
[Every retirement is audited](#every-retirement-is-audited).

### 1. Expire it — `db.expire` (preserves the row, reversible)

```python
db.expire(mem_id, "2026-07-21T00:00:00Z", actor="agent:ops", reason="superseded snapshot")
```

`at` is the instant the record stops being current. `valid_until` is exclusive,
so passing the current time retires it immediately, and passing a future time
schedules the retirement. The record stops appearing in default recall the
instant the window closes, stays fully readable via `include_expired` or a
back-dated `effective_at`, and its content, provenance chain, and signatures are
untouched. `db.expire(mem_id, None, actor=...)` lifts the window again.

The instant is normalized to ISO-8601 UTC before it is stored, and an
unparseable one raises rather than being written. This matters: recall parses
`valid_until` with `datetime.fromisoformat`, so a hand-written epoch number or
malformed string in that column is silently read as *no expiry* — the record
stays live while the operator believes it was retired.

The returned receipt reports the change and whether the record is still inside
its validity window:

```python
{"id": mem_id, "from": None, "to": "2026-07-21T00:00:00+00:00", "valid_now": False}
```

Use this for **time-boxed operational records** — session snapshots, working
notes, anything with a natural shelf life. Prefer it when the record may need to
be read again later, or when the retirement is scheduled rather than final.

### 2. Unindex it — `db.set_indexed` (preserves the row, no recall reaches it)

```python
db.set_indexed(mem_id, False, actor="agent:ops", reason="owner-authorized retirement")
db.set_indexed(mem_id, True, actor="agent:ops", reason="reinstated")
```

Removes the record from the answerable corpus entirely: no recall filter, opt-in
or back-dated, returns an unindexed row. The row, its content, its provenance
chain and its stored embedding are untouched, so the change is fully reversible
with a second call — nothing has to be re-embedded.

Use this when a record must stop answering **every** query, including audit
views, but must not be destroyed. Prefer expiry or supersession when the record
should stay reachable to someone who asks for it explicitly.

Both verbs accept a re-assertion of the state a record is already in. That is a
deliberate no-op that still writes the audit event, so a change made out of band
can be put on the record after the fact.

### 3. Supersede it — `transition_review` (preserves the row, terminal)

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

### 4. Purge it — `db.purge` (destroys the row)

`db.purge(mem_id)` physically deletes the row and removes it from the index
(`heartwood/client.py`). It appends a `purge` audit event, so the *deletion* is
on the tamper-evident record — but the content is gone. It does not crypto-shred
the subject key; that is reserved for `forget()`.

Use this only when the content itself must not persist.

## Every retirement is audited

Each mechanism appends one row to the hash-chained audit log, so the question
"why did this record stop answering?" is answerable from the record itself:

| Mechanism | Audit `action` | `detail` |
| --- | --- | --- |
| `db.expire` | `expire` | `{"from": <prior valid_until>, "to": <new>, "reason": ...}` |
| `db.set_indexed` | `index_state` | `{"from": <prior indexed>, "to": <new>, "reason": ...}` |
| `db.transition_review` | `review_transition` | `{"from": <state>, "to": <state>, "reason": ...}` |
| `db.purge` | `purge` | `{}` |

```python
[(row["action"], row["principal"]) for row in db.store.iter_audit()
 if row["target"] == mem_id]
db.verify_audit()      # the chain still verifies after any of them
```

## Direct column writes are a policy violation

`indexed` and `valid_until` decide whether a stored record still answers "what is
true right now?". Writing either one with a direct `UPDATE` — a SQL client, a
migration script, a helper that reaches past the client — moves a record out of
recall with **nothing on the audit log**. The row then reads as created and never
touched, which is precisely the claim the audit log exists to make falsifiable.

Since these columns have sanctioned verbs, a direct write to either is a policy
violation, not a shortcut:

| Instead of | Use |
| --- | --- |
| `UPDATE memories SET indexed=0 WHERE id=...` | `db.set_indexed(mem_id, False, actor=..., reason=...)` |
| `UPDATE memories SET valid_until=... WHERE id=...` | `db.expire(mem_id, at, actor=..., reason=...)` |

If a record was already moved out of band, re-assert the same state through the
verb. Both are no-ops on an unchanged row and still write the audit event, so the
prior change can be put on the record rather than left implicit.

## Warning: `import-markdown --update` purges, it does not supersede

The markdown importer's update path is destructive. When `--update` re-imports a
source file whose content hash has changed, `_purge_prior_rows`
(`heartwood/importers/markdown.py`) calls `db.purge()` on every prior row for
that source path.

**No row is moved to `review_state = "superseded"` — the prior rows are
deleted.** The receipt reports this under `purged` / `purged_count`.

> **Deprecated:** these fields were previously named `superseded` /
> `superseded_count`, which named mechanism 3 for work that performs mechanism
> 4. Both old keys are still emitted as aliases of the new ones and will be
> removed in 0.3.0. Update report consumers to read `purged_count` / `purged`.

**Do not use `--update` to retire a governed operational record.** For any record
under review, retention, or audit obligation:

1. Retire it explicitly first — `transition_review(..., "superseded")` for a
   final replacement, or `db.expire(...)` for a time-boxed one.
2. Confirm the retirement landed: `db.store.get_meta(mem_id)` shows the new
   `review_state` or `valid_until`, and the row still exists.
3. Only then re-import, so the importer finds a matching content hash and has
   no stale prior row to purge.

To find what an `--update` run *would* delete before running it, list the prior
rows for the source path with `db.store.memories_by_source_path(tenant, path)`
and compare each `content_hash` against the incoming file.
