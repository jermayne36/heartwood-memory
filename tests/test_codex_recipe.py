"""Codex MCP recipe and positioning guardrails."""
import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

from heartwood.adapters.mcp_server import allowed_tools_from_env  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
CODEX_DOCS = [
    ROOT / "docs" / "integrations" / "codex-quickstart.md",
    ROOT / "docs" / "integrations" / "codex-AGENTS.md.template",
]
BANNED_STRINGS = [
    "Codex-native",
    "zero-knowledge",
    "end-to-end encrypted",
    "E2EE",
    "official",
    "verified integration",
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_codex_docs_exist_and_avoid_banned_positioning():
    combined = "\n".join(_read(path) for path in CODEX_DOCS)
    lowered = combined.lower()
    for banned in BANNED_STRINGS:
        assert banned.lower() not in lowered


def test_codex_quickstart_contains_required_recipe_contract():
    text = _read(ROOT / "docs" / "integrations" / "codex-quickstart.md")
    assert "Minimum Codex CLI version for this recipe: `0.141.0`." in text
    assert "codex mcp add heartwood" in text
    assert '-- "$PYBIN" -m heartwood.adapters.mcp_server' in text
    assert "codex mcp list --json" in text
    assert "[mcp_servers.heartwood]" in text
    assert 'command = "/absolute/path/to/heartwood-memory/.venv/bin/python"' in text
    assert "startup_timeout_sec = 45" in text
    assert 'enabled_tools = ["recall", "explain_recall", "health"]' in text
    assert "disable_on_external_context = true" in text
    assert "generate_memories = false" in text
    assert 'mkdir -p "$HEARTWOOD_DATA_DIR"' in text
    assert '--env HEARTWOOD_DB_PATH="$HEARTWOOD_DB_PATH"' in text
    assert "HEARTWOOD_DB_PATH=.heartwood/heartwood.db" not in text


def test_codex_agents_template_names_memory_verbs():
    text = _read(ROOT / "docs" / "integrations" / "codex-AGENTS.md.template")
    for tool in ("recall", "remember", "explain_recall", "forget"):
        assert tool in text
    assert "Never store secrets" in text


def test_codex_safe_allowlist_contract():
    # ASA A4: unset/empty env fails closed to the read-only subset.
    assert allowed_tools_from_env("") == {"recall", "explain_recall", "health"}
    assert allowed_tools_from_env("recall,explain_recall,health") == {
        "recall",
        "explain_recall",
        "health",
    }
    assert allowed_tools_from_env("recall,explain_recall,remember,forget,health") == {
        "recall",
        "explain_recall",
        "remember",
        "forget",
        "health",
    }
    try:
        allowed_tools_from_env("recall,codex_memory")
        raise AssertionError("unknown allowlist entries should fail closed")
    except ValueError as exc:
        assert "codex_memory" in str(exc)


async def _start_documented_server(db_path: Path) -> tuple[list[str], dict]:
    env = {
        key: os.environ[key]
        for key in ("HOME", "PATH", "TMPDIR", "SYSTEMROOT")
        if key in os.environ
    }
    env.update(
        {
            "HEARTWOOD_DB_PATH": str(db_path),
            "HEARTWOOD_TENANT": "tenant:ops",
            "HEARTWOOD_MCP_ALLOWED_TOOLS": "recall,explain_recall,health",
            "HF_HUB_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1",
        }
    )
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "heartwood.adapters.mcp_server"],
        env=env,
        cwd=ROOT,
    )
    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            health_result = await session.call_tool("health", {})
            health = health_result.structuredContent
            if health is None:
                health = json.loads(health_result.content[0].text)
            return sorted(tool.name for tool in tools.tools), health


def _assert_documented_server_starts(db_path: Path) -> None:
    assert db_path.is_absolute()
    assert db_path.parent.is_dir()
    tools, health = asyncio.run(_start_documented_server(db_path))
    assert tools == ["explain_recall", "health", "recall"]
    assert health["ok"] is True
    assert health["service"] == "heartwood-mcp"
    assert db_path.is_file()


def test_codex_documented_server_starts(tmp_path):
    _assert_documented_server_starts(tmp_path / "heartwood.db")


def main():
    test_codex_docs_exist_and_avoid_banned_positioning()
    test_codex_quickstart_contains_required_recipe_contract()
    test_codex_agents_template_names_memory_verbs()
    test_codex_safe_allowlist_contract()
    configured_path = os.environ.get("HEARTWOOD_DB_PATH")
    if configured_path:
        _assert_documented_server_starts(Path(configured_path))
    else:
        with tempfile.TemporaryDirectory() as temp_dir:
            _assert_documented_server_starts(Path(temp_dir) / "heartwood.db")
    print("CODEX RECIPE TESTS PASSED")


if __name__ == "__main__":
    main()
