# Fail closed when a server lacks custody for a wrapped key

## Behavior

In Heartwood 0.2.10, a raw-local server could silently skip memories protected
by a wrapped subject DEK. A write to the same subject could treat the wrapped
envelope as a raw encryption key, bypassing custody protection.

In `KeyStore._resolve_key`, refuse to resolve a wrapped DEK with the raw-local
custodian. Reads and writes must report both `HEARTWOOD_KEY_CUSTODY_ROOT_B64`
and `HEARTWOOD_KEY_CUSTODY_KEY_ID`. A refused write must leave no memory row.
Stores using only raw keys must still support writes and recall without custody.

## Scope and verification

- Keep the implementation in `heartwood/erasure.py`. Cover read refusal, write
  refusal before encryption, and raw-local compatibility in `tests/`.
- Verify whether `forget(mode="hard")` physically purges an existing memory
  whose ciphertext was created outside custody. Keep cleanup changes out of scope.
- Update the key custody and multi-agent identity guides, the MCP and Codex
  quickstarts, and the Unreleased changelog. Every server opening a shared store
  with wrapped keys needs the same custody root and key ID, including readers.
- Run `bash scripts/check.sh` and replay the reader matrix with both wrapped
  and raw-local stores. Open a pull request for review. Release and package
  publication are separate work.
