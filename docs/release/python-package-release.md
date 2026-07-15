# Python Package Release

Phase 1 C1 produces a signed local wheel artifact and an Ed25519 release
manifest.

## Build

```powershell
python scripts/build_release.py
```

Outputs:

- `dist/heartwood_memory-<version>-py3-none-any.whl`
- `dist/heartwood-memory-release-manifest.json`

The manifest contains:

- package artifact path;
- byte size;
- SHA-256 digest;
- git commit;
- dirty-worktree flag;
- Ed25519 public key and signature over the manifest payload.

## Production Signing

For production releases, provide a stable 32-byte Ed25519 private key:

```powershell
$env:HEARTWOOD_RELEASE_SIGNING_KEY_B64 = "<32-byte-base64url-private-key>"
python scripts/build_release.py
```

Without the env var, the script uses an ephemeral local key. That still proves
the artifact and manifest match each other, but it is not a durable identity for
public releases.

## Verify

The build script verifies the signature and checksums before it exits. A failed
verification raises a non-zero exit.

## PyPI Publication

`heartwood-memory` is published on PyPI at version `0.1.2`.

Buyer install:

```powershell
python -m pip install heartwood-memory
python -m pip install "heartwood-memory[recall,mcp]"
heartwood --help
```

Future public releases still require owner-controlled PyPI credentials, release
notes approval, and legal/trademark clearance for the next version.
