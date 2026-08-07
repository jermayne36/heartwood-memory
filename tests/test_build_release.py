import base64
import hashlib
import importlib.util
import json
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build_release.py"


def load_build_release():
    spec = importlib.util.spec_from_file_location("build_release", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_manifest_covers_wheel_and_sdist_with_verifiable_signature(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(SCRIPT.parent))
    monkeypatch.delenv("HEARTWOOD_RELEASE_SIGNING_KEY_B64", raising=False)
    release = load_build_release()
    root = tmp_path / "release"
    dist = root / "dist"
    dist.mkdir(parents=True)
    wheel = dist / "heartwood_memory-0.2.3-py3-none-any.whl"
    sdist = dist / "heartwood_memory-0.2.3.tar.gz"
    wheel.write_bytes(b"wheel artifact")
    sdist.write_bytes(b"source distribution artifact")
    monkeypatch.setattr(release, "ROOT", root)
    monkeypatch.setattr(release, "DIST", dist)

    manifest = release.write_manifest([wheel, sdist])
    release.verify_manifest(manifest)

    payload = json.loads(manifest.read_text(encoding="utf-8"))
    files = {item["path"]: item for item in payload["files"]}
    assert set(files) == {"dist/heartwood_memory-0.2.3-py3-none-any.whl", "dist/heartwood_memory-0.2.3.tar.gz"}
    assert files["dist/heartwood_memory-0.2.3-py3-none-any.whl"]["sha256"] == hashlib.sha256(
        wheel.read_bytes()
    ).hexdigest()
    assert files["dist/heartwood_memory-0.2.3.tar.gz"]["sha256"] == hashlib.sha256(
        sdist.read_bytes()
    ).hexdigest()
    assert (dist / release.PUBLIC_KEY_NAME).read_text(encoding="utf-8").strip() == payload["signing"][
        "public_key_b64"
    ]


def test_customer_verifier_rejects_a_key_or_artifact_mismatch(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(SCRIPT.parent))
    monkeypatch.delenv("HEARTWOOD_RELEASE_SIGNING_KEY_B64", raising=False)
    release = load_build_release()
    from heartwood.release_verify import verify_release

    root = tmp_path / "release"
    dist = root / "dist"
    dist.mkdir(parents=True)
    wheel = dist / "heartwood_memory-0.2.3-py3-none-any.whl"
    wheel.write_bytes(b"wheel artifact")
    monkeypatch.setattr(release, "ROOT", root)
    monkeypatch.setattr(release, "DIST", dist)
    manifest = release.write_manifest([wheel])
    public_key = dist / release.PUBLIC_KEY_NAME

    verify_release(manifest, public_key, [wheel])

    original_key = public_key.read_text(encoding="utf-8")
    public_key.write_text(base64.urlsafe_b64encode(b"x" * 32).decode("ascii") + "\n", encoding="utf-8")
    try:
        verify_release(manifest, public_key, [wheel])
    except RuntimeError as error:
        assert "public key does not match" in str(error)
    else:
        raise AssertionError("mismatched public key unexpectedly verified")
    public_key.write_text(original_key, encoding="utf-8")

    wheel.write_bytes(b"tampered")
    try:
        verify_release(manifest, public_key, [wheel])
    except RuntimeError as error:
        assert "checksum mismatch" in str(error)
    else:
        raise AssertionError("tampered wheel unexpectedly verified")
