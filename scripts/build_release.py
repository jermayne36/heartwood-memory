from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from check_version import assert_versions_match

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(data: str) -> bytes:
    pad = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + pad)


def ensure_build_module() -> None:
    try:
        __import__("build")
    except Exception:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "build>=1.2"])


def git_value(*args: str) -> str:
    try:
        return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()
    except Exception:
        return "unknown"


def source_dirty() -> bool:
    try:
        output = subprocess.check_output(["git", "status", "--short"], cwd=ROOT, text=True)
    except Exception:
        return True
    for line in output.splitlines():
        path = line[3:].replace("\\", "/")
        if path.startswith(("build/", "dist/")) or ".egg-info/" in path:
            continue
        return True
    return False


def signing_key() -> tuple[ed25519.Ed25519PrivateKey, str]:
    raw = os.environ.get("HEARTWOOD_RELEASE_SIGNING_KEY_B64")
    if raw:
        return ed25519.Ed25519PrivateKey.from_private_bytes(_b64d(raw)[:32]), "env"
    return ed25519.Ed25519PrivateKey.generate(), "ephemeral-local"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_distributions() -> list[Path]:
    ensure_build_module()
    DIST.mkdir(exist_ok=True)
    for pattern in ("heartwood_memory-*.whl", "heartwood_memory-*.tar.gz"):
        for path in DIST.glob(pattern):
            path.unlink()
    subprocess.check_call(
        [sys.executable, "-m", "build", "--wheel", "--sdist", "--outdir", str(DIST)],
        cwd=ROOT,
    )
    wheels = sorted(DIST.glob("heartwood_memory-*.whl"))
    sdists = sorted(DIST.glob("heartwood_memory-*.tar.gz"))
    if not wheels or not sdists:
        raise RuntimeError("release build did not produce both a wheel and an sdist")
    return [*wheels, *sdists]


def write_manifest(artifacts: list[Path]) -> Path:
    private_key, key_source = signing_key()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    files = [
        {
            "path": str(path.relative_to(ROOT)).replace("\\", "/"),
            "sha256": sha256(path),
            "bytes": path.stat().st_size,
        }
        for path in artifacts
    ]
    payload = {
        "schema": "heartwood.release.v1",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git_commit": git_value("rev-parse", "HEAD"),
        "git_dirty": source_dirty(),
        "package": "heartwood-memory",
        "files": files,
        "signing": {
            "algorithm": "Ed25519",
            "public_key_b64": _b64e(public_key),
            "key_source": key_source,
            "note": (
                "Use HEARTWOOD_RELEASE_SIGNING_KEY_B64 for production releases. "
                "ephemeral-local proves artifact integrity for local verification only."
            ),
        },
    }
    signed_bytes = json.dumps(
        {key: value for key, value in payload.items() if key != "signature_b64"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    payload["signature_b64"] = _b64e(private_key.sign(signed_bytes))
    out = DIST / "heartwood-memory-release-manifest.json"
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out


def verify_manifest(path: Path) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    signature = _b64d(payload.pop("signature_b64"))
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(_b64d(payload["signing"]["public_key_b64"]))
    public_key.verify(
        signature,
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
    )
    for item in payload["files"]:
        file_path = ROOT / item["path"]
        if sha256(file_path) != item["sha256"]:
            raise RuntimeError(f"checksum mismatch: {file_path}")


def main() -> None:
    version = assert_versions_match(ROOT / "pyproject.toml", ROOT / "heartwood" / "__init__.py")
    print(f"Version guard passed: {version}")
    artifacts = build_distributions()
    manifest = write_manifest(artifacts)
    verify_manifest(manifest)
    print("Built release artifacts:")
    for path in artifacts:
        print(f"- {path}")
    print(f"- {manifest}")


if __name__ == "__main__":
    main()
