# Multi-Agent Identity

Heartwood's default multi-agent identity path is one customer-held custody
root, provided through `HEARTWOOD_KEY_CUSTODY_ROOT_B64`, with deterministic
per-principal Ed25519 signing keys derived from that root.

The root is never written to the Heartwood database or source tree. Store it in
your vault, KMS, HSM, or deployment secret manager. Once a shared store uses
wrapped keys, inject the same custody root and key ID into every process that
opens it, whether it writes or only reads.

## Initialize A Root

Generate a 32-byte root and register the first agent principals:

```bash
heartwood init-identity \
  --db ./heartwood.db \
  --tenant tenant:acme \
  --principal agent:researcher \
  --principal agent:reviewer
```

The command prints:

- `export HEARTWOOD_KEY_CUSTODY_ROOT_B64=...`
- `export HEARTWOOD_KEY_CUSTODY_KEY_ID=...`
- a reminder to store the root in your vault
- the public principal identities registered in the DB
- a worked two-agent example

Only public keys are registered. The root remains customer-side secret
material.

## Run Multiple Agents

Set the same root and key ID in every process that opens the store, including
read-only recall servers:

```bash
export HEARTWOOD_KEY_CUSTODY_ROOT_B64="..."
export HEARTWOOD_KEY_CUSTODY_KEY_ID="env-root-v1"

heartwood import-markdown ./memory \
  --db ./heartwood.db \
  --created-by agent:researcher

heartwood import-markdown ./team-memory \
  --db ./heartwood.db \
  --created-by agent:reviewer
```

Both agents derive stable signing keys from the same root. Their public keys
remain verifiable after restart, and Heartwood can sign new memories for those
principals as long as the same root is supplied.

## Failure Mode

In 0.2.10, a process without the root silently skipped memories it could not
decrypt. When that process wrote to a subject with a wrapped key, it encrypted
the new memory with a fixed, non-secret key. If a subject received
those writes, `forget(subject, mode="hard")` purges its memory rows from the
active store, including valid memories for that subject. Copies made before
the purge are outside its scope.

The custody check now raises an error naming `HEARTWOOD_KEY_CUSTODY_ROOT_B64`
and `HEARTWOOD_KEY_CUSTODY_KEY_ID` when a process without the root tries to read
or write a subject with a wrapped key. A different key ID also causes recall
to fail. Supply the same root and key ID the store already uses.

If a process sees a registered public key but lacks the matching private key,
Heartwood raises an error naming `HEARTWOOD_KEY_CUSTODY_ROOT_B64`. That means
the process is missing the custody root or is using the wrong
`HEARTWOOD_KEY_CUSTODY_KEY_ID`.

Do not fix this by deleting the principal key registry. Supply the same root, or
intentionally rotate/re-key under a written migration plan.
