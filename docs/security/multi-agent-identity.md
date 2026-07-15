# Multi-Agent Identity

Heartwood's default multi-agent identity path is one customer-held custody
root, provided through `HEARTWOOD_KEY_CUSTODY_ROOT_B64`, with deterministic
per-principal Ed25519 signing keys derived from that root.

The root is never written to the Heartwood database or source tree. Store it in
your vault, KMS, HSM, or deployment secret manager and inject it into every
process that needs to sign as the same agents.

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

Set the same root in every process that writes governed memory:

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

If a process sees a registered public key but lacks the matching private key,
Heartwood raises an error naming `HEARTWOOD_KEY_CUSTODY_ROOT_B64`. That means
the process is missing the custody root or is using the wrong
`HEARTWOOD_KEY_CUSTODY_KEY_ID`.

Do not fix this by deleting the principal key registry. Supply the same root, or
intentionally rotate/re-key under a written migration plan.
