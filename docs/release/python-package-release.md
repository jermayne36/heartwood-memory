# Python Package Release

Phase 1 C1 produces a signed local wheel artifact and an Ed25519 release
manifest.

## Build

Use the supported Python 3.11 release environment and run the local gate before
building:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
bash scripts/check.sh
```

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

`heartwood-memory` is published on PyPI at version `0.2.3`.

Buyer install:

```powershell
python -m pip install heartwood-memory
python -m pip install "heartwood-memory[recall,mcp]"
heartwood --help
```

Future public releases still require owner-controlled PyPI credentials, release
notes approval, and legal/trademark clearance for the next version.

## Production Consumer Gate

After publishing a Heartwood core release, and before merging any repository
split or package-tree removal, EdukasAI operators must repin and smoke the live
recall consumer from the private team workspace:

```bash
HEARTWOOD_TEAM_WORKSPACE=/path/to/orchestration-workspace
HEARTWOOD_RELEASE_VERSION=0.2.1 \
HEARTWOOD_RELEASE_WHEEL_SHA256=b08a303c281b611bde4baf01f53658eac2d3dcc6bed271be5e136e0462a548f2 \
  bash "$HEARTWOOD_TEAM_WORKSPACE/scripts/heartwood/release-consumer-smoke.sh" --repin
```

The gate inventories the launchd venv and installer, verifies the released
wheel hash, verifies imports before restart, then requires health, live recall,
pack-lane refresh, a clean import/write-read roundtrip, no crash state, and a
stable serving child for at least four minutes. A failed smoke automatically
restores the captured pre-run installation and exits non-zero.
The gate also requires the expected version to match the public repository's
`pyproject.toml`, so a stale release command cannot approve a newer package.
