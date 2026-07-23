"""Model-route adapters for the rotation-continuity demo.

Heartwood performs the governed read/write operations. Each live provider gets a
route-specific environment allowlist, and the harness persists only a closed
decision schema. The Codex route disables its shell and external-tool features;
Claude receives an empty tool list; Ollama uses its plain local generation
command.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


DECISION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "decision": {"type": "string", "enum": ["BLOCK"]},
        "region": {"type": "string", "enum": ["us-west"]},
        "control": {
            "type": "string",
            "enum": ["security_approval_required"],
        },
    },
    "required": ["decision", "region", "control"],
    "additionalProperties": False,
}

EXPECTED_CORE = {
    "decision": "BLOCK",
    "region": "us-west",
    "control": "security_approval_required",
}

CODEX_DISABLED_FEATURES = (
    "apps",
    "browser_use",
    "browser_use_external",
    "browser_use_full_cdp_access",
    "code_mode_host",
    "computer_use",
    "hooks",
    "image_generation",
    "in_app_browser",
    "memories",
    "multi_agent",
    "plugins",
    "remote_plugin",
    "shell_snapshot",
    "shell_tool",
    "tool_call_mcp_elicitation",
    "unified_exec",
)
PROVIDER_ENV_ALLOWLISTS = {
    "codex-cli": (
        "CODEX_API_KEY",
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
    ),
    "claude-code": (
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_BASE_URL",
        "CLAUDE_CODE_OAUTH_TOKEN",
    ),
    "ollama-local": (
        "OLLAMA_HOST",
        "OLLAMA_MODELS",
    ),
}


@dataclass(frozen=True)
class RouteSpec:
    route_id: str
    route_class: str
    provider: str
    model: str
    command: str


@dataclass(frozen=True)
class RouteResult:
    route_id: str
    route_class: str
    provider: str
    model: str
    execution: str
    command: list[str]
    duration_ms: int
    output: dict[str, str]
    environment_keys: tuple[str, ...] = ()
    tool_boundary: str = ""
    provider_streams_clear: bool = True
    fallback_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "route_id": self.route_id,
            "route_class": self.route_class,
            "provider": self.provider,
            "model": self.model,
            "execution": self.execution,
            "command": self.command,
            "duration_ms": self.duration_ms,
            "output": self.output,
            "environment_keys": list(self.environment_keys),
            "tool_boundary": self.tool_boundary,
            "provider_streams_clear": self.provider_streams_clear,
            "fallback_reason": self.fallback_reason,
        }


class RouteExecutionError(RuntimeError):
    """Raised when a live route cannot produce the demo decision contract."""


class RouteBoundaryError(RuntimeError):
    """Raised when a route violates a non-negotiable containment control."""


def default_route_specs(
    *,
    gpt_model: str,
    claude_model: str,
    open_weights_model: str,
) -> list[RouteSpec]:
    return [
        RouteSpec(
            route_id="route-a",
            route_class="gpt-class",
            provider="codex-cli",
            model=gpt_model,
            command="codex",
        ),
        RouteSpec(
            route_id="route-b",
            route_class="claude-class",
            provider="claude-code",
            model=claude_model,
            command="claude",
        ),
        RouteSpec(
            route_id="route-c",
            route_class="open-weights",
            provider="ollama-local",
            model=open_weights_model,
            command="ollama",
        ),
    ]


def decision_prompt(
    *,
    route_id: str,
    scenario: str | None,
    recalled_context: list[str],
) -> str:
    context = "\n".join(f"- {line}" for line in recalled_context) or "- none"
    scenario_block = f"\nScenario:\n{scenario}\n" if scenario else ""
    return f"""You are one backend route for the same enterprise release agent.
Return one JSON object and no other text. It must contain exactly these keys:
decision, region, control.

Route: {route_id}
{scenario_block}

Governed Heartwood context available to this route:
{context}

The exact required values are decision=BLOCK, region=us-west, and
control=security_approval_required. Do not invent facts.
"""


def run_route(
    spec: RouteSpec,
    prompt: str,
    *,
    mode: str,
    timeout_seconds: int,
    forbidden_values: tuple[str, ...] = (),
) -> RouteResult:
    """Run one route live, or use a disclosed deterministic stub.

    ``auto`` attempts the live route and falls back only when the executable,
    existing authentication, or local model is unavailable. ``live`` fails
    closed. ``stub`` never invokes a provider.
    """
    if mode == "stub":
        return _stub_result(spec, "stub_mode_requested")

    runner: Callable[[RouteSpec, str, int, str, tuple[str, ...]], RouteResult]
    if spec.provider == "codex-cli":
        runner = _run_codex
    elif spec.provider == "claude-code":
        runner = _run_claude
    elif spec.provider == "ollama-local":
        runner = _run_ollama
    else:  # pragma: no cover - route specs are fixed by this demo
        raise RouteExecutionError(f"unknown provider: {spec.provider}")

    resolved_command = (
        spec.command
        if spec.provider == "ollama-local"
        else shutil.which(spec.command)
    )
    if resolved_command is None:
        if mode == "auto":
            return _stub_result(spec, "executable_unavailable")
        raise RouteExecutionError(f"{spec.provider} executable unavailable")

    attempts = 2 if spec.provider in {"codex-cli", "ollama-local"} else 1
    for attempt in range(attempts):
        try:
            return runner(
                spec,
                prompt,
                timeout_seconds,
                resolved_command,
                forbidden_values,
            )
        except RouteBoundaryError:
            raise
        except (OSError, subprocess.SubprocessError, RouteExecutionError):
            if attempt + 1 < attempts:
                continue
            if mode == "auto":
                return _stub_result(spec, "live_route_failed")
            raise
    raise AssertionError("route retry loop exited without a result")


def _run_codex(
    spec: RouteSpec,
    prompt: str,
    timeout_seconds: int,
    resolved_command: str,
    forbidden_values: tuple[str, ...],
) -> RouteResult:
    with tempfile.TemporaryDirectory(prefix="heartwood-demo-codex-") as temp_dir:
        temp_path = Path(temp_dir)
        env = _route_environment(spec, resolved_command, temp_path)
        schema_path = temp_path / "decision-schema.json"
        output_path = temp_path / "decision.json"
        schema_path.write_text(json.dumps(DECISION_SCHEMA), encoding="utf-8")
        command = [
            resolved_command,
            "exec",
            "--ephemeral",
            "--ignore-user-config",
            "--ignore-rules",
            "--strict-config",
            "--skip-git-repo-check",
            "--sandbox",
            "read-only",
            "-c",
            'web_search="disabled"',
            "--json",
            "--model",
            spec.model,
            "--output-schema",
            str(schema_path),
            "--output-last-message",
            str(output_path),
        ]
        for feature in CODEX_DISABLED_FEATURES:
            command.extend(("--disable", feature))
        command.append("-")
        started = time.monotonic()
        completed = subprocess.run(
            command,
            input=prompt,
            text=True,
            capture_output=True,
            cwd=temp_dir,
            env=env,
            timeout=timeout_seconds,
            check=False,
        )
        duration_ms = round((time.monotonic() - started) * 1000)
        _assert_forbidden_absent(
            forbidden_values,
            completed.stdout,
            completed.stderr,
        )
        if completed.returncode != 0:
            raise RouteExecutionError("Codex route failed")
        if not output_path.exists():
            raise RouteExecutionError("Codex did not write its structured output")
        raw_output = output_path.read_text(encoding="utf-8")
        _assert_forbidden_absent(forbidden_values, raw_output)
        _assert_no_codex_tool_events(completed.stdout)
        output = _validated_output(_parse_json_text(raw_output))
        return RouteResult(
            route_id=spec.route_id,
            route_class=spec.route_class,
            provider=spec.provider,
            model=spec.model,
            execution="live",
            command=_receipt_command(command, prompt_marker="-"),
            duration_ms=duration_ms,
            output=output,
            environment_keys=tuple(sorted(env)),
            tool_boundary="codex_shell_and_external_tools_disabled",
        )


def _run_claude(
    spec: RouteSpec,
    prompt: str,
    timeout_seconds: int,
    resolved_command: str,
    forbidden_values: tuple[str, ...],
) -> RouteResult:
    with tempfile.TemporaryDirectory(prefix="heartwood-demo-claude-") as temp_dir:
        env = _route_environment(spec, resolved_command, Path(temp_dir))
        command = [
            resolved_command,
            "--print",
            "--safe-mode",
            "--no-session-persistence",
            "--tools",
            # Verified live with Claude Code on 2026-07-22: a discrete empty value
            # means the route receives no tools while structured output stays enabled.
            "",
            "--permission-mode",
            "dontAsk",
            "--model",
            spec.model,
            "--effort",
            "low",
            "--max-budget-usd",
            "0.25",
            "--output-format",
            "json",
            "--json-schema",
            json.dumps(DECISION_SCHEMA, separators=(",", ":")),
        ]
        started = time.monotonic()
        completed = subprocess.run(
            command,
            input=prompt,
            text=True,
            capture_output=True,
            cwd=temp_dir,
            env=env,
            timeout=timeout_seconds,
            check=False,
        )
        duration_ms = round((time.monotonic() - started) * 1000)
        _assert_forbidden_absent(
            forbidden_values,
            completed.stdout,
            completed.stderr,
        )
        if completed.returncode != 0:
            raise RouteExecutionError("Claude route failed")
        envelope = _parse_json_text(completed.stdout)
        candidate: Any = envelope
        if isinstance(envelope, dict) and isinstance(
            envelope.get("structured_output"),
            dict,
        ):
            candidate = envelope["structured_output"]
        elif isinstance(envelope, dict) and isinstance(envelope.get("result"), str):
            candidate = _parse_json_text(envelope["result"])
        output = _validated_output(candidate)
        return RouteResult(
            route_id=spec.route_id,
            route_class=spec.route_class,
            provider=spec.provider,
            model=spec.model,
            execution="live",
            command=_receipt_command(command),
            duration_ms=duration_ms,
            output=output,
            environment_keys=tuple(sorted(env)),
            tool_boundary="claude_empty_tool_allowlist",
        )


def _run_ollama(
    spec: RouteSpec,
    prompt: str,
    timeout_seconds: int,
    _resolved_command: str,
    forbidden_values: tuple[str, ...],
) -> RouteResult:
    host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
    if "://" not in host:
        host = f"http://{host}"
    parsed_host = urllib.parse.urlparse(host)
    if parsed_host.scheme != "http" or parsed_host.hostname not in {
        "127.0.0.1",
        "::1",
        "localhost",
    }:
        raise RouteBoundaryError("Ollama route requires a loopback HTTP endpoint")
    url = f"{host.rstrip('/')}/api/generate"
    payload = {
        "model": spec.model,
        "prompt": prompt,
        "stream": False,
        "format": DECISION_SCHEMA,
        "think": False,
        "keep_alive": "5m",
        "options": {"temperature": 0},
    }
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    started = time.monotonic()
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        raw_envelope = response.read().decode("utf-8")
    duration_ms = round((time.monotonic() - started) * 1000)
    _assert_forbidden_absent(forbidden_values, raw_envelope)
    envelope = _parse_json_text(raw_envelope)
    raw_output = envelope.get("response") if isinstance(envelope, dict) else None
    if not isinstance(raw_output, str):
        raise RouteExecutionError("Ollama response omitted structured output")
    _assert_forbidden_absent(forbidden_values, raw_output)
    output = _validated_output(_parse_json_text(raw_output))
    return RouteResult(
        route_id=spec.route_id,
        route_class=spec.route_class,
        provider=spec.provider,
        model=spec.model,
        execution="live",
        command=["POST", url, "<closed-schema-request>"],
        duration_ms=duration_ms,
        output=output,
        environment_keys=("OLLAMA_HOST",) if "OLLAMA_HOST" in os.environ else (),
        tool_boundary="ollama_local_structured_api_no_tools",
    )


def _validated_output(candidate: Any) -> dict[str, str]:
    if not isinstance(candidate, dict):
        raise RouteExecutionError("route output was not a JSON object")
    missing = sorted(set(DECISION_SCHEMA["required"]) - set(candidate))
    if missing:
        raise RouteExecutionError(f"route output missing closed fields: {missing}")
    output = {key: str(candidate[key]) for key in DECISION_SCHEMA["required"]}
    actual_core = {key: output[key] for key in EXPECTED_CORE}
    if actual_core != EXPECTED_CORE:
        raise RouteExecutionError(
            f"route decision mismatch: expected={EXPECTED_CORE}, actual={actual_core}"
        )
    return output


def _stub_result(spec: RouteSpec, reason: str) -> RouteResult:
    return RouteResult(
        route_id=spec.route_id,
        route_class=spec.route_class,
        provider=spec.provider,
        model=spec.model,
        execution="stub",
        command=[],
        duration_ms=0,
        output={**EXPECTED_CORE},
        environment_keys=(),
        tool_boundary="deterministic_stub_no_provider_process",
        fallback_reason=reason,
    )


def _route_environment(
    spec: RouteSpec,
    resolved_command: str,
    temp_path: Path,
) -> dict[str, str]:
    """Build a replacement environment from a small route-specific allowlist."""
    synthetic_home = temp_path / "home"
    synthetic_home.mkdir()
    env = {
        "CLICOLOR": "0",
        "HOME": str(synthetic_home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "PATH": _minimal_path(resolved_command),
        "TERM": "dumb",
        "TMPDIR": str(temp_path),
    }
    for name in PROVIDER_ENV_ALLOWLISTS[spec.provider]:
        value = os.environ.get(name)
        if value:
            env[name] = value

    real_home = Path.home()
    if spec.provider == "codex-cli":
        codex_home = Path(os.environ.get("CODEX_HOME", real_home / ".codex"))
        if codex_home.exists():
            env["CODEX_HOME"] = str(codex_home)
    elif spec.provider == "claude-code":
        claude_home = Path(
            os.environ.get("CLAUDE_CONFIG_DIR", real_home / ".claude")
        )
        if claude_home.exists():
            env["CLAUDE_CONFIG_DIR"] = str(claude_home)
    return env


def _minimal_path(resolved_command: str) -> str:
    directories = [str(Path(resolved_command).resolve().parent)]
    node = shutil.which("node")
    if node:
        directories.append(str(Path(node).resolve().parent))
    directories.extend(os.defpath.split(os.pathsep))
    return os.pathsep.join(dict.fromkeys(directories))


def _assert_forbidden_absent(
    forbidden_values: tuple[str, ...],
    *channels: str,
) -> None:
    if any(
        value and value in channel
        for value in forbidden_values
        for channel in channels
    ):
        raise RouteBoundaryError(
            "negative-control sentinel reached a provider output channel"
        )


def _assert_no_codex_tool_events(jsonl: str) -> None:
    for line in jsonl.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RouteBoundaryError("Codex emitted a non-JSON event") from exc
        if event.get("type") not in {"item.started", "item.completed"}:
            continue
        item_type = event.get("item", {}).get("type")
        if item_type not in {"agent_message", "reasoning"}:
            raise RouteBoundaryError(
                "Codex emitted a tool or non-message item despite the no-tools gate"
            )


def _parse_json_text(value: str) -> Any:
    text = value.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            # Some local GGUF templates emit a literal newline inside a JSON
            # string even under ``ollama run --format json``. Accept control
            # characters only at the parser boundary; _validated_output still
            # enforces the exact closed decision contract.
            return json.loads(text, strict=False)
        except json.JSONDecodeError:
            pass
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(text[start : end + 1], strict=False)
            except json.JSONDecodeError as exc:
                raise RouteExecutionError("route returned invalid JSON") from exc
        raise RouteExecutionError("route returned no JSON object")


def _receipt_command(command: list[str], prompt_marker: str | None = None) -> list[str]:
    """Return a non-secret command receipt.

    The Claude JSON schema is long but non-sensitive; replace it with a marker
    to keep receipts readable. Prompts are always delivered over stdin.
    """
    receipt = list(command)
    if "--json-schema" in receipt:
        index = receipt.index("--json-schema") + 1
        receipt[index] = "<decision-schema-json>"
    if prompt_marker and receipt and receipt[-1] == prompt_marker:
        receipt[-1] = "<prompt-via-stdin>"
    return receipt
