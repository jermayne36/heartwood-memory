# Python Package Release

This runbook builds, publishes, and verifies one immutable
`heartwood-memory` release. Run it from the repository root with Python 3.11.
Do not upload until the version change is reviewed, merged, and checked out on
a clean `main`.

## 1. Prepare the release version

Start from current `main`:

```bash
git switch main
git pull --ff-only origin main
test -z "$(git status --porcelain)"
git rev-parse HEAD
```

Set the new, unpublished version:

```bash
export RELEASE_VERSION="X.Y.Z"
```

Update all four release surfaces:

- `pyproject.toml`: `[project].version`
- `heartwood/__init__.py`: `__version__`
- `tests/test_version_consistency.py`: expected version
- `CHANGELOG.md`: move `[Unreleased]` entries into a dated release section

Verify the version is internally consistent and absent from PyPI:

```bash
python3.11 scripts/check_version.py
rg -n '^(version =|__version__ =)|== "[0-9]+\.[0-9]+\.[0-9]+"' \
  pyproject.toml heartwood/__init__.py tests/test_version_consistency.py
PYPI_STATUS="$(
  curl -sS -o /dev/null -w '%{http_code}' \
    "https://pypi.org/pypi/heartwood-memory/${RELEASE_VERSION}/json"
)"
test "$PYPI_STATUS" = "404"
echo "pypi_version_available=true version=${RELEASE_VERSION}"
```

Expected shapes:

```text
version guard: OK (X.Y.Z)
pypi_version_available=true version=X.Y.Z
```

Install the release tools and run the repository gate:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pip install twine
bash scripts/check.sh
```

Expected final shape:

```text
All checks passed!
<N> passed, <N> skipped in <seconds>s
```

Commit the version change, open a protected-main pull request, and obtain the
required review. After it merges, return to a clean, updated `main` and repeat
the version and quality gates:

```bash
git switch main
git pull --ff-only origin main
test -z "$(git status --porcelain)"
python3.11 scripts/check_version.py
bash scripts/check.sh
export RELEASE_COMMIT="$(git rev-parse HEAD)"
```

## 2. Build the wheel, sdist, and signed manifest

The post-PR-12 builder creates both publishable artifacts in one invocation,
then signs one manifest that covers both:

```bash
python3.11 scripts/build_release.py
export WHEEL="dist/heartwood_memory-${RELEASE_VERSION}-py3-none-any.whl"
export SDIST="dist/heartwood_memory-${RELEASE_VERSION}.tar.gz"
export MANIFEST="dist/heartwood-memory-release-manifest.json"
test -f "$WHEEL"
test -f "$SDIST"
test -f "$MANIFEST"
```

Expected final shape:

```text
Version guard passed: X.Y.Z
Successfully built heartwood_memory-X.Y.Z-py3-none-any.whl and heartwood_memory-X.Y.Z.tar.gz
Built release artifacts:
- .../dist/heartwood_memory-X.Y.Z-py3-none-any.whl
- .../dist/heartwood_memory-X.Y.Z.tar.gz
- .../dist/heartwood-memory-release-manifest.json
```

`scripts/build_release.py` verifies its Ed25519 signature and every recorded
SHA-256 digest before exiting. Run this independent receipt as well:

```bash
PYTHONPATH=scripts RELEASE_COMMIT="$RELEASE_COMMIT" python3.11 - <<'PY'
import json
import os
from pathlib import Path

from build_release import sha256, verify_manifest

manifest = Path("dist/heartwood-memory-release-manifest.json")
verify_manifest(manifest)
payload = json.loads(manifest.read_text(encoding="utf-8"))
expected = {
    "dist/heartwood_memory-" + os.environ["RELEASE_VERSION"] + "-py3-none-any.whl",
    "dist/heartwood_memory-" + os.environ["RELEASE_VERSION"] + ".tar.gz",
}
actual = {item["path"] for item in payload["files"]}
assert actual == expected, (actual, expected)
assert payload["git_commit"] == os.environ["RELEASE_COMMIT"]
assert payload["git_dirty"] is False
print("manifest_signature=verified")
print(f"manifest_git_commit={payload['git_commit']}")
print("manifest_git_dirty=false")
print(f"manifest_key_source={payload['signing']['key_source']}")
for item in payload["files"]:
    assert sha256(Path(item["path"])) == item["sha256"]
    print(f"manifest_file={item['path']} sha256={item['sha256']} parity=MATCH")
PY
```

Expected shapes:

```text
manifest_signature=verified
manifest_git_commit=<RELEASE_COMMIT>
manifest_git_dirty=false
manifest_key_source=env|ephemeral-local
manifest_file=dist/...whl sha256=<64 hex> parity=MATCH
manifest_file=dist/...tar.gz sha256=<64 hex> parity=MATCH
```

`HEARTWOOD_RELEASE_SIGNING_KEY_B64`, when already configured from an approved
secure source, makes `manifest_key_source=env`. Without it, the builder uses an
ephemeral local key. Never create, rotate, or replace a signing key during a
release without the credential-change approval and rollback plan.

## 3. Check metadata and scan the public artifacts

```bash
python3.11 -m twine check "$WHEEL" "$SDIST"
git diff --check HEAD^ HEAD
if git ls-tree -r --name-only HEAD |
  rg -n '(\.db$|\.pem$|\.key$|(^|/)\.env($|\.)|credential)'; then
  echo "release_forbidden_paths=found"
  exit 1
else
  echo "release_forbidden_paths=clean"
fi
LEAK_PATTERN="$(
  printf '%s' \
    '/Us' 'ers/[^[:space:]]+' \
    '|pyp' 'i-[A-Za-z0-9_-]{20,}' \
    '|sk_' '(live|test)_[A-Za-z0-9]{16,}' \
    '|-----BEGIN ' '(RSA |EC |OPENSSH )?PRIVATE KEY-----'
)"
if unzip -p "$WHEEL" | LC_ALL=C rg -a -n "$LEAK_PATTERN"; then
  echo "wheel_secret_shape_scan=found"
  exit 1
else
  echo "wheel_secret_shape_scan=clean"
fi
if tar -xOzf "$SDIST" | LC_ALL=C rg -a -n "$LEAK_PATTERN"; then
  echo "sdist_secret_shape_scan=found"
  exit 1
else
  echo "sdist_secret_shape_scan=clean"
fi
```

Expected final shapes:

```text
Checking ...whl: PASSED
Checking ...tar.gz: PASSED
release_forbidden_paths=clean
wheel_secret_shape_scan=clean
sdist_secret_shape_scan=clean
```

Any match is a stop condition. Do not paste a suspected value into a ticket,
pull request, log, or chat.

## 4. Publish with the existing PyPI token

This is the irreversible step. Execute it only with release/publish approval.
The existing upload token is stored in Azure Key Vault `edukasai-kv` under the
secret name `shared-infra--pypi--token`. Never print the value or enable shell
tracing around this block.

```bash
set +x
cleanup_twine_env() {
  unset TWINE_USERNAME TWINE_PASSWORD
}
trap cleanup_twine_env EXIT INT TERM
export TWINE_USERNAME="__token__"
export TWINE_PASSWORD="$(
  az keyvault secret show \
    --vault-name edukasai-kv \
    --name shared-infra--pypi--token \
    --query value \
    --output tsv
)"
test -n "$TWINE_PASSWORD"
if python3.11 -m twine upload "$WHEEL" "$SDIST"; then
  UPLOAD_STATUS=0
else
  UPLOAD_STATUS=$?
fi
cleanup_twine_env
trap - EXIT INT TERM
test "$UPLOAD_STATUS" -eq 0
```

Expected final shape:

```text
Uploading distributions to https://upload.pypi.org/legacy/
Uploading heartwood_memory-X.Y.Z-py3-none-any.whl
Uploading heartwood_memory-X.Y.Z.tar.gz
View at:
https://pypi.org/project/heartwood-memory/X.Y.Z/
```

The block reads an existing credential into Twine and unsets it on success,
failure, or interruption. It does not authorize credential mutation.

## 5. Verify PyPI propagation and SHA parity

Treat the exact-version release JSON as the immediate authority. Project-level
`info.version` can lag briefly after upload.

```bash
export RELEASE_JSON="$(mktemp)"
curl -fsS \
  "https://pypi.org/pypi/heartwood-memory/${RELEASE_VERSION}/json" \
  -o "$RELEASE_JSON"
RELEASE_JSON="$RELEASE_JSON" python3.11 - <<'PY'
import hashlib
import json
import os
import urllib.request
from pathlib import Path

manifest = json.loads(
    Path("dist/heartwood-memory-release-manifest.json").read_text(encoding="utf-8")
)
release = json.loads(Path(os.environ["RELEASE_JSON"]).read_text(encoding="utf-8"))
expected_version = os.environ["RELEASE_VERSION"]
assert release["info"]["version"] == expected_version
local = {Path(item["path"]).name: item["sha256"] for item in manifest["files"]}
remote = {item["filename"]: item for item in release["urls"]}
assert set(local) == set(remote), (set(local), set(remote))
print(f"release_json_version={release['info']['version']}")
for filename, local_sha in sorted(local.items()):
    item = remote[filename]
    json_sha = item["digests"]["sha256"]
    byte_sha = hashlib.sha256(
        urllib.request.urlopen(item["url"], timeout=30).read()
    ).hexdigest()
    assert local_sha == json_sha == byte_sha
    print(
        f"remote_file={filename} local_sha256={local_sha} "
        f"json_sha256={json_sha} byte_sha256={byte_sha} parity=MATCH"
    )
PY
```

Wait for both artifacts to appear on the simple index:

```bash
curl -fsS "https://pypi.org/simple/heartwood-memory/" |
  rg "heartwood_memory-${RELEASE_VERSION}.*(whl|tar\.gz)"
```

Expected shapes:

```text
release_json_version=X.Y.Z
remote_file=...whl ... parity=MATCH
remote_file=...tar.gz ... parity=MATCH
...heartwood_memory-X.Y.Z-py3-none-any.whl...
...heartwood_memory-X.Y.Z.tar.gz...
```

Finally, verify the published package from a neutral working directory. This
prevents the repository-local `heartwood/` tree from shadowing the installed
wheel:

```bash
export VERIFY_DIR="$(mktemp -d)"
python3.11 -m pip install \
  --quiet \
  --disable-pip-version-check \
  --no-deps \
  --target "$VERIFY_DIR/site" \
  "heartwood-memory==${RELEASE_VERSION}"
(
  cd /tmp
  VERIFY_SITE="$VERIFY_DIR/site" python3.11 - <<'PY'
import ast
import importlib.metadata
import importlib.util
import os
import sys
from pathlib import Path

sys.path.insert(0, os.environ["VERIFY_SITE"])
spec = importlib.util.find_spec("heartwood")
assert spec is not None and spec.origin is not None
module_path = Path(spec.origin)
module = ast.parse(module_path.read_text(encoding="utf-8"), filename=str(module_path))
runtime_versions = [
    ast.literal_eval(node.value)
    for node in module.body
    if isinstance(node, ast.Assign)
    and any(
        isinstance(target, ast.Name) and target.id == "__version__"
        for target in node.targets
    )
]
distribution_version = importlib.metadata.version("heartwood-memory")
expected = os.environ["RELEASE_VERSION"]
assert distribution_version == expected
assert runtime_versions == [expected]
print(f"neutral_cwd_distribution_version={distribution_version}")
print(f"neutral_cwd_runtime_version={runtime_versions[0]}")
print(f"neutral_cwd_module_path={module_path}")
PY
)
```

## 6. Repin the production consumer

Publishing does not update the EdukasAI recall daemon. Continue in the private
team workspace at `docs/runbooks/heartwood.md`, then run the sanctioned
`scripts/heartwood/release-consumer-smoke.sh --repin` flow with the exact wheel
SHA-256 from the verified release manifest.

Run the repin only in a quiet release window. The gate restarts the daemon and
automatically restores the prior installed version if a gate fails, but a
restart is not a fully quiesced SQLite maintenance window. Any direct database
maintenance immediately after a repin requires a separately reviewed explicit
daemon bootout/bootstrap procedure; `launchctl kickstart -k` is not a quiesce
gate. Do not add ad hoc database writes to the repin.

## Rollback

PyPI artifacts are immutable and cannot be overwritten. For a defective
release, obtain owner approval before yanking it, publish a corrected higher
version, verify that version with this runbook, and repin to the corrected
wheel. For a consumer-only failure, use the automatic/manual rollback path in
the private `docs/runbooks/heartwood.md`; do not bypass a failed repin gate.
