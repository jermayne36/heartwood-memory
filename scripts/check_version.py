from __future__ import annotations

import argparse
import ast
import json
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def pyproject_version(path: Path) -> str:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    value = data.get("project", {}).get("version")
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"missing [project].version in {path}")
    return value


def runtime_version(path: Path) -> str:
    module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    values: list[str] = []
    for node in module.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets):
            continue
        value = ast.literal_eval(node.value)
        if not isinstance(value, str) or not value:
            raise RuntimeError(f"__version__ must be a non-empty string literal in {path}")
        values.append(value)
    if len(values) != 1:
        raise RuntimeError(f"expected exactly one __version__ assignment in {path}; found {len(values)}")
    return values[0]


def server_versions(path: Path) -> tuple[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    manifest = data.get("version")
    if not isinstance(manifest, str) or not manifest:
        raise RuntimeError(f"missing top-level version in {path}")

    matching_packages = [
        item
        for item in data.get("packages", [])
        if isinstance(item, dict)
        and item.get("registryType") == "pypi"
        and item.get("identifier") == "heartwood-memory"
    ]
    if len(matching_packages) != 1:
        raise RuntimeError(
            f"expected exactly one PyPI heartwood-memory package in {path}; "
            f"found {len(matching_packages)}"
        )
    package = matching_packages[0].get("version")
    if not isinstance(package, str) or not package:
        raise RuntimeError(f"missing PyPI package version in {path}")
    return manifest, package


def assert_versions_match(pyproject_path: Path, init_path: Path, server_path: Path) -> str:
    package = pyproject_version(pyproject_path)
    runtime = runtime_version(init_path)
    manifest, registry_package = server_versions(server_path)
    if len({package, runtime, manifest, registry_package}) != 1:
        raise RuntimeError(
            "version drift: "
            f"pyproject.toml={package!r}, "
            f"heartwood.__version__={runtime!r}, "
            f"server.json.version={manifest!r}, "
            f"server.json PyPI package={registry_package!r}"
        )
    return package


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify Heartwood package/runtime version consistency.")
    parser.add_argument("--pyproject", type=Path, default=ROOT / "pyproject.toml")
    parser.add_argument("--init", type=Path, default=ROOT / "heartwood" / "__init__.py")
    parser.add_argument("--server", type=Path, default=ROOT / "server.json")
    args = parser.parse_args()
    version = assert_versions_match(args.pyproject, args.init, args.server)
    print(f"version guard: OK ({version})")


if __name__ == "__main__":
    main()
