from pathlib import Path

import pytest

from scripts.check_version import assert_versions_match


ROOT = Path(__file__).resolve().parents[1]


def test_package_and_runtime_versions_match():
    assert assert_versions_match(
        ROOT / "pyproject.toml",
        ROOT / "heartwood" / "__init__.py",
    ) == "0.2.5"


def test_version_guard_rejects_runtime_drift(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    package_init = tmp_path / "__init__.py"
    pyproject.write_text('[project]\nversion = "0.2.2"\n', encoding="utf-8")
    package_init.write_text('__version__ = "0.2.1"\n', encoding="utf-8")

    with pytest.raises(RuntimeError, match="version drift"):
        assert_versions_match(pyproject, package_init)
