# Key Custody

Phase 1 adds a pluggable key-custody path for subject data-encryption keys
(DEKs). The production pattern is:

```text
deployment root secret -> HKDF tenant/subject KEK -> AES key-wrap -> stored DEK envelope
```

The implementation lives in `heartwood/key_custody.py`.

## Signing-Key Custody And Provenance Trust

The same custody root also derives per-principal Ed25519 signing keys for
provenance. This keeps importer identities stable across process restarts, but
it expands the root secret's blast radius: compromise of
`HEARTWOOD_KEY_CUSTODY_ROOT_B64` enables both subject data decryption and
provenance forging for any principal in that tenant.

Treat the custody root as both a data-encryption root and an identity root.
Store it only in managed secret storage such as KMS, HSM, or a vault, restrict
operator access, and rotate it with a migration plan that preserves legacy
public-key aliases for audit verification.

For a multi-agent setup, use
[`multi-agent-identity.md`](multi-agent-identity.md). It documents
`heartwood init-identity`, the `HEARTWOOD_KEY_CUSTODY_ROOT_B64` env-root path,
and the rule that the root stays in the customer's vault while Heartwood stores
only public principal keys.

## Modes

| Mode | Class | Use |
|---|---|---|
| `raw-local` | `RawKeyCustodian` | Backward-compatible local mode for existing stores and small tests |
| `hkdf-aeskw-local` | `LocalKmsCustodian` | Phase 1 KMS-compatible pattern using a vault-provided root secret |

Production should pass a custodian whose root secret comes from KMS/HSM/vault
storage. The local class exists to verify the envelope pattern without adding a
managed dependency.

## Environment Configuration

Set a 32-byte base64url root:

```powershell
$root = [Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 }))
$env:HEARTWOOD_KEY_CUSTODY_ROOT_B64 = $root
$env:HEARTWOOD_KEY_CUSTODY_KEY_ID = "local-root-v1"
```

Then start Heartwood normally:

```powershell
heartwood bulk-remember --input .\records.jsonl --db .\heartwood.db
```

When the env var is present, newly created subject DEKs are stored as wrapped
envelopes rather than raw key bytes.

## Python API

```python
from heartwood import Heartwood, LocalKmsCustodian

custodian = LocalKmsCustodian(root_key=b"\x01" * 32, key_id="vault-root-v1")
db = Heartwood(path="heartwood.db", tenant="tenant:ops", key_custodian=custodian)
```

Check custody state for a subject:

```python
db.key_custody_info("customer:42")
```

## Tenant Key Lifecycle

Provision a new tenant root locally, then deliver `material.env()` through the
approved provisioner/secret store path:

```python
from heartwood import provision_tenant_root

material = provision_tenant_root("tenant:acme", key_id="tenant:acme-root-v1")
custodian = material.custodian()
```

Migrate a legacy raw-local store into wrapped custody, or re-wrap DEKs during an
owner-approved root rotation:

```python
from heartwood import LocalKmsCustodian, RawKeyCustodian, rewrap_tenant_keys
from heartwood.store import Store

store = Store("heartwood.db")
new_root = LocalKmsCustodian(root_key=b"\x02" * 32, key_id="tenant:acme-root-v1")
report = rewrap_tenant_keys(
    store,
    tenant="tenant:acme",
    old_custodian=RawKeyCustodian(),
    new_custodian=new_root,
)
assert report.complete
```

For root rotation, use `rotate_tenant_root(...)` so DEKs are re-wrapped and
legacy provenance public-key aliases are registered in the same operation.
Rotation of an existing production root remains owner-gated under Rule 45.

To verify local crypto-erase after root destruction, use
`prove_crypto_erase_path(db_path, tenant=..., root_present=False)`. The proof is
valid only when no raw active DEKs remain; destroying the SQLite data files gives
the stronger full-tenant deprovision proof.

## Verification

```powershell
python tests/test_key_custody.py
```

The test proves that:

- the persisted key blob is an HKDF/AES-KW envelope;
- content survives restart when the same root secret is supplied;
- a different root secret fails closed;
- recall still verifies provenance over encrypted content.
- raw-local stores can be re-wrapped into custody idempotently;
- root rotation preserves historical provenance verification through aliases;
- crypto-erase proof rejects raw DEKs and accepts wrapped data with the root gone.
