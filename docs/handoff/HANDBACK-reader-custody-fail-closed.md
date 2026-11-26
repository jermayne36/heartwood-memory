# Reader custody verification

## Behavior

`KeyStore._resolve_key` rejects a wrapped subject key when the process uses the
default unwrap implementation, including `KeyCustodian` and
`RawKeyCustodian`. Both `recall()` and `remember()` report the same
configuration error. The refusal happens before `remember()` encrypts or
inserts the memory. A process with matching custody can still read the
original memory, and raw-local stores continue to support reads and writes
without a root.

The default `KeyCustodian.unwrap` also refuses a wrapped key when called
directly. Bulk rewrap reports the custody error before it attempts to replace
the affected subject key.

A custody-enabled process can still wrap a raw key when it first resolves it,
including during recall. Every process reading those memories must then have the
same root and key ID. The security guides and quickstarts document that setup.

## Verification

- `tests/test_key_custody.py` covers no-root recall and direct read, refusal
  before encryption with the row count unchanged for default and explicit
  base custody, and raw-local reads and writes.
- Bulk rewrap tests cover envelopes both divisible and indivisible by eight
  bytes, with a raw or omitted old custodian. Each test checks for the named
  custody error before any key replacement and verifies the original stored
  subject key after reopening the store.
- The reader matrix covers a missing root, a missing key ID, matching custody,
  and a raw-local store before and after lazy wrapping. MCP surfaces the missing
  custody configuration as a tool error.
- Hard forget physically purged a synthetic row encrypted under an unrelated key
  in the same SQLite store. The ciphertext was absent from the database and the
  WAL was truncated before the connection closed. The unrelated subject survived.
  This result covers the active store and its WAL. Copies made before the purge
  are outside that operation.
- Ruff passed. The full pytest suite returned 532 passed and 3 skipped.
