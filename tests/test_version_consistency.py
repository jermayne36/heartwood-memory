import tomllib
from pathlib import Path

import pytest

from scripts.check_version import assert_versions_match


ROOT = Path(__file__).resolve().parents[1]


def write_server(path: Path, *, manifest: str, package: str) -> None:
    path.write_text(
        "{\n"
        f'  "version": "{manifest}",\n'
        '  "packages": [\n'
        '    {\n'
        '      "registryType": "pypi",\n'
        '      "identifier": "heartwood-memory",\n'
        f'      "version": "{package}"\n'
        '    }\n'
        '  ]\n'
        '}\n',
        encoding="utf-8",
    )


def test_package_and_runtime_versions_match():
    assert assert_versions_match(
        ROOT / "pyproject.toml",
        ROOT / "heartwood" / "__init__.py",
        ROOT / "server.json",
    ) == "0.2.5"


def test_package_metadata_links_public_source():
    with (ROOT / "pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)["project"]

    assert project["urls"] == {
        "Homepage": "https://heartwoodmemory.com/",
        "Repository": "https://github.com/jermayne36/heartwood-memory",
        "Documentation": "https://github.com/jermayne36/heartwood-memory/tree/main/docs",
        "Issues": "https://github.com/jermayne36/heartwood-memory/issues",
    }


def test_version_guard_rejects_runtime_drift(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    package_init = tmp_path / "__init__.py"
    server = tmp_path / "server.json"
    pyproject.write_text('[project]\nversion = "0.2.2"\n', encoding="utf-8")
    package_init.write_text('__version__ = "0.2.1"\n', encoding="utf-8")
    write_server(server, manifest="0.2.2", package="0.2.2")

    with pytest.raises(RuntimeError, match="version drift"):
        assert_versions_match(pyproject, package_init, server)


@pytest.mark.parametrize(
    ("manifest", "package"),
    [("0.2.4", "0.2.5"), ("0.2.5", "0.2.4")],
)
def test_version_guard_rejects_server_manifest_drift(tmp_path, manifest, package):
    pyproject = tmp_path / "pyproject.toml"
    package_init = tmp_path / "__init__.py"
    server = tmp_path / "server.json"
    pyproject.write_text('[project]\nversion = "0.2.5"\n', encoding="utf-8")
    package_init.write_text('__version__ = "0.2.5"\n', encoding="utf-8")
    write_server(server, manifest=manifest, package=package)

    with pytest.raises(RuntimeError, match="version drift"):
        assert_versions_match(pyproject, package_init, server)
