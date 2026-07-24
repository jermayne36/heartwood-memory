"""Pinned Hugging Face model cache helpers for the recall daemon."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


def _user_cache_home() -> Path:
    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        return (
            Path(local_app_data)
            if local_app_data
            else Path.home() / "AppData" / "Local"
        )
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches"
    xdg_cache_home = os.environ.get("XDG_CACHE_HOME")
    return Path(xdg_cache_home) if xdg_cache_home else Path.home() / ".cache"


def _default_cache_dir() -> Path:
    if "HF_HOME" in os.environ:
        return Path(os.environ["HF_HOME"])
    return _user_cache_home() / "heartwood" / "hf"


DEFAULT_CACHE_DIR = _default_cache_dir()
DEFAULT_MANIFEST = DEFAULT_CACHE_DIR / "heartwood-model-manifest.json"


@dataclass(frozen=True)
class ModelSpec:
    key: str
    repo_id: str
    revision: str
    trust_remote_code: bool = False


MODEL_SPECS: dict[str, ModelSpec] = {
    "minilm-embedder": ModelSpec(
        key="minilm-embedder",
        repo_id="sentence-transformers/all-MiniLM-L6-v2",
        revision="1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
    ),
    "ms-marco-minilm-reranker": ModelSpec(
        key="ms-marco-minilm-reranker",
        repo_id="cross-encoder/ms-marco-MiniLM-L-6-v2",
        revision="c5ee24cb16019beea0893ab7796b1df96625c6b8",
    ),
    "embeddinggemma": ModelSpec(
        key="embeddinggemma",
        repo_id="google/embeddinggemma-300m",
        revision="57c266a740f537b4dc058e1b0cda161fd15afa75",
        trust_remote_code=True,
    ),
    "bge-m3": ModelSpec(
        key="bge-m3",
        repo_id="BAAI/bge-m3",
        revision="5617a9f61b028005a4858fdac845db406aefb181",
        trust_remote_code=True,
    ),
    "qwen3": ModelSpec(
        key="qwen3",
        repo_id="Qwen/Qwen3-Embedding-0.6B",
        revision="97b0c614be4d77ee51c0cef4e5f07c00f9eb65b3",
        trust_remote_code=True,
    ),
    "bge-v2": ModelSpec(
        key="bge-v2",
        repo_id="BAAI/bge-reranker-v2-m3",
        revision="953dc6f6f85a1b2dbfca4c34a2796e7dde08d41e",
        trust_remote_code=True,
    ),
    "mxbai": ModelSpec(
        key="mxbai",
        repo_id="mixedbread-ai/mxbai-rerank-base-v2",
        revision="3ea9d4dffa7d12a4f366be8e275c349de9fc9865",
        trust_remote_code=True,
    ),
}

DAEMON_MODEL_KEYS = ("minilm-embedder", "ms-marco-minilm-reranker")


def model_spec(key: str) -> ModelSpec:
    try:
        return MODEL_SPECS[key]
    except KeyError as exc:
        raise ValueError(f"unknown Heartwood model key: {key}") from exc


def resolve_model_source(
    spec: ModelSpec,
    *,
    cache_dir: str | Path | None = None,
    local_files_only: bool | None = None,
) -> str:
    """Return a local snapshot path for a pinned model revision."""
    if local_files_only is None:
        local_files_only = _offline_mode()
    from huggingface_hub import snapshot_download

    path = snapshot_download(
        repo_id=spec.repo_id,
        revision=spec.revision,
        cache_dir=str(cache_dir or DEFAULT_CACHE_DIR),
        local_files_only=local_files_only,
    )
    return str(path)


def download_models(
    keys: Iterable[str],
    *,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    manifest_path: Path = DEFAULT_MANIFEST,
) -> dict[str, object]:
    models = []
    for key in keys:
        spec = model_spec(key)
        snapshot_dir = Path(resolve_model_source(spec, cache_dir=cache_dir, local_files_only=False))
        models.append(_manifest_entry(spec, snapshot_dir))
    manifest = {
        "version": 1,
        "models": models,
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def verify_manifest(manifest_path: Path = DEFAULT_MANIFEST) -> dict[str, object]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    failures: list[str] = []
    for model in manifest.get("models", []):
        snapshot_dir = Path(str(model["snapshot_dir"]))
        for expected in model.get("files", []):
            rel = Path(str(expected["path"]))
            path = snapshot_dir / rel
            if not path.is_file():
                failures.append(f"missing:{model['key']}:{rel}")
                continue
            size = path.stat().st_size
            digest = _sha256(path)
            if size != int(expected["bytes"]) or digest != expected["sha256"]:
                failures.append(f"mismatch:{model['key']}:{rel}")
    if failures:
        raise SystemExit("HF model cache integrity check failed: " + ", ".join(failures[:10]))
    return manifest


def _manifest_entry(spec: ModelSpec, snapshot_dir: Path) -> dict[str, object]:
    files = []
    for path in sorted(_snapshot_files(snapshot_dir)):
        files.append(
            {
                "path": str(path.relative_to(snapshot_dir)),
                "bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
        )
    return {
        **asdict(spec),
        "snapshot_dir": str(snapshot_dir),
        "files": files,
    }


def _snapshot_files(snapshot_dir: Path) -> Iterable[Path]:
    for path in snapshot_dir.rglob("*"):
        if path.is_file():
            yield path


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _offline_mode() -> bool:
    return os.environ.get("HF_HUB_OFFLINE") == "1" or os.environ.get("TRANSFORMERS_OFFLINE") == "1"


def _parse_keys(raw: str | None) -> tuple[str, ...]:
    if raw in (None, "", "daemon"):
        return DAEMON_MODEL_KEYS
    if raw == "all":
        return tuple(MODEL_SPECS)
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage pinned Heartwood Hugging Face model cache")
    sub = parser.add_subparsers(dest="command", required=True)

    download = sub.add_parser("download")
    download.add_argument("--models", default="daemon")
    download.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    download.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)

    verify = sub.add_parser("verify")
    verify.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)

    args = parser.parse_args(argv)
    if args.command == "download":
        manifest = download_models(
            _parse_keys(args.models),
            cache_dir=args.cache_dir,
            manifest_path=args.manifest,
        )
        print(json.dumps({"ok": True, "models": len(manifest["models"]), "manifest": str(args.manifest)}))
        return 0
    if args.command == "verify":
        manifest = verify_manifest(args.manifest)
        print(json.dumps({"ok": True, "models": len(manifest["models"]), "manifest": str(args.manifest)}))
        return 0
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
