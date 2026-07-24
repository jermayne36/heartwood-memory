"""Model-cache path regressions."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

from heartwood import model_cache


def _import_default_cache_dir(env: dict[str, str]) -> dict[str, object]:
    script = """
import json
from heartwood.model_cache import DEFAULT_CACHE_DIR

DEFAULT_CACHE_DIR.mkdir(parents=True, exist_ok=True)
probe = DEFAULT_CACHE_DIR / "heartwood-write-probe"
probe.write_text("ok", encoding="utf-8")
print(json.dumps({"path": str(DEFAULT_CACHE_DIR), "writable": probe.read_text() == "ok"}))
probe.unlink()
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        text=True,
    )
    return json.loads(completed.stdout)


def test_unset_hf_home_uses_writable_user_cache(tmp_path, monkeypatch):
    monkeypatch.delenv("HF_HOME", raising=False)
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "AppData" / "Local"))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    if os.name == "nt":
        expected = tmp_path / "AppData" / "Local" / "heartwood" / "hf"
    elif sys.platform == "darwin":
        expected = tmp_path / "Library" / "Caches" / "heartwood" / "hf"
    else:
        expected = tmp_path / ".cache" / "heartwood" / "hf"
    cache_dir = model_cache._default_cache_dir()
    assert cache_dir == expected
    cache_dir.mkdir(parents=True)
    probe = cache_dir / "heartwood-write-probe"
    probe.write_text("ok", encoding="utf-8")
    assert probe.read_text(encoding="utf-8") == "ok"


def test_hf_home_override_is_unchanged(tmp_path):
    configured = tmp_path / "operator-hf-home"
    env = os.environ.copy()
    env["HF_HOME"] = str(configured)

    imported = _import_default_cache_dir(env)

    assert Path(str(imported["path"])) == configured
    assert imported["writable"] is True
