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
