from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519


def _b64d(data: str) -> bytes:
    value = data.strip()
    pad = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + pad)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_release(manifest_path: Path, public_key_path: Path, artifacts: list[Path]) -> None:
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    signature = _b64d(payload.pop("signature_b64"))
    published_key = _b64d(public_key_path.read_text(encoding="utf-8"))
    embedded_key = _b64d(payload["signing"]["public_key_b64"])
    if published_key != embedded_key:
        raise RuntimeError("published public key does not match the signed manifest")

    ed25519.Ed25519PublicKey.from_public_bytes(published_key).verify(
        signature,
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
    )

    manifest_files = {Path(item["path"]).name: item for item in payload["files"]}
    if not artifacts:
        raise RuntimeError("at least one --artifact is required")
    for artifact in artifacts:
        item = manifest_files.get(artifact.name)
        if item is None:
            raise RuntimeError(f"artifact is not covered by the manifest: {artifact.name}")
        actual = _sha256(artifact)
        if actual != item["sha256"]:
            raise RuntimeError(f"checksum mismatch: {artifact}")
        print(f"VERIFIED {artifact.name} sha256={actual}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify Heartwood release artifacts against a separately published Ed25519 key."
    )
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--artifact", required=True, action="append", type=Path)
    args = parser.parse_args()
    verify_release(args.manifest, args.public_key, args.artifact)


if __name__ == "__main__":
    main()
