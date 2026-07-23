"""Model-route adapters for the rotation-continuity demo.

The adapters deliberately expose no tools to the model. Heartwood performs the
governed read/write operations; each route receives only the approved demo
scenario or the policy-filtered recall context and returns one small decision.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
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
        "evidence": {"type": "string", "minLength": 1, "maxLength": 240},
    },
    "required": ["decision", "region", "control", "evidence"],
    "additionalProperties": False,
}

EXPECTED_CORE = {
    "decision": "BLOCK",
    "region": "us-west",
    "control": "security_approval_required",
}

ANSI_ESCAPE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


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
            "fallback_reason": self.fallback_reason,
        }


class RouteExecutionError(RuntimeError):
    """Raised when a live route cannot produce the demo decision contract."""


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


def decision_prompt(*, route_id: str, scenario: str, recalled_context: list[str]) -> str:
    context = "\n".join(f"- {line}" for line in recalled_context) or "- none"
    return f"""You are one backend route for the same enterprise release agent.
Return one JSON object and no other text. It must contain exactly these keys:
decision, region, control, evidence.

Route: {route_id}
Scenario:
{scenario}

Governed Heartwood context available to this route:
{context}

The exact required values are decision=BLOCK, region=us-west, and
control=security_approval_required. Do not invent facts. Keep evidence under 240
characters.
"""


def run_route(
    spec: RouteSpec,
    prompt: str,
    *,
    mode: str,
    timeout_seconds: int,
) -> RouteResult:
    """Run one route live, or use a disclosed deterministic stub.

    ``auto`` attempts the live route and falls back only when the executable,
    existing authentication, or local model is unavailable. ``live`` fails
    closed. ``stub`` never invokes a provider.
    """
    if mode == "stub":
        return _stub_result(spec, "stub mode requested")

    runner: Callable[[RouteSpec, str, int], RouteResult]
    if spec.provider == "codex-cli":
        runner = _run_codex
    elif spec.provider == "claude-code":
        runner = _run_claude
    elif spec.provider == "ollama-local":
        runner = _run_ollama
    else:  # pragma: no cover - route specs are fixed by this demo
        raise RouteExecutionError(f"unknown provider: {spec.provider}")

    if shutil.which(spec.command) is None:
        reason = f"{spec.command} executable not found"
        if mode == "auto":
            return _stub_result(spec, reason)
        raise RouteExecutionError(reason)

    try:
        return runner(spec, prompt, timeout_seconds)
    except (OSError, subprocess.SubprocessError, RouteExecutionError) as exc:
        if mode == "auto":
            return _stub_result(spec, _safe_error(exc))
        raise


def _run_codex(spec: RouteSpec, prompt: str, timeout_seconds: int) -> RouteResult:
    with tempfile.TemporaryDirectory(prefix="heartwood-demo-codex-") as temp_dir:
        temp_path = Path(temp_dir)
        schema_path = temp_path / "decision-schema.json"
        output_path = temp_path / "decision.json"
        schema_path.write_text(json.dumps(DECISION_SCHEMA), encoding="utf-8")
        command = [
            spec.command,
            "exec",
            "--ephemeral",
            "--ignore-user-config",
            "--ignore-rules",
            "--skip-git-repo-check",
            "--sandbox",
            "read-only",
            "--model",
            spec.model,
            "--output-schema",
            str(schema_path),
            "--output-last-message",
            str(output_path),
            "-",
        ]
        started = time.monotonic()
        completed = subprocess.run(
            command,
            input=prompt,
            text=True,
            capture_output=True,
            cwd=temp_dir,
            timeout=timeout_seconds,
            check=False,
        )
        duration_ms = round((time.monotonic() - started) * 1000)
        if completed.returncode != 0:
            raise RouteExecutionError(
                f"Codex exited {completed.returncode}: {_stderr_tail(completed.stderr)}"
            )
        if not output_path.exists():
            raise RouteExecutionError("Codex did not write its structured output")
        output = _validated_output(_parse_json_text(output_path.read_text(encoding="utf-8")))
        return RouteResult(
            route_id=spec.route_id,
            route_class=spec.route_class,
            provider=spec.provider,
            model=spec.model,
            execution="live",
            command=_receipt_command(command, prompt_marker="-"),
            duration_ms=duration_ms,
            output=output,
        )


def _run_claude(spec: RouteSpec, prompt: str, timeout_seconds: int) -> RouteResult:
    command = [
        spec.command,
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
        timeout=timeout_seconds,
        check=False,
    )
    duration_ms = round((time.monotonic() - started) * 1000)
    if completed.returncode != 0:
        raise RouteExecutionError(
            f"Claude exited {completed.returncode}: {_stderr_tail(completed.stderr)}"
        )
    envelope = _parse_json_text(completed.stdout)
    candidate: Any = envelope
    if isinstance(envelope, dict) and isinstance(envelope.get("structured_output"), dict):
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
    )


def _run_ollama(spec: RouteSpec, prompt: str, timeout_seconds: int) -> RouteResult:
    command = [
        spec.command,
        "run",
        spec.model,
        "--format",
        "json",
        "--hidethinking",
        "--think=false",
        "--keepalive",
        "5m",
    ]
    env = os.environ.copy()
    env["OLLAMA_NOHISTORY"] = "1"
    env["TERM"] = "dumb"
    env["NO_COLOR"] = "1"
    env["CLICOLOR"] = "0"
    started = time.monotonic()
    completed = subprocess.run(
        command,
        input=prompt,
        text=True,
        capture_output=True,
        env=env,
        timeout=timeout_seconds,
        check=False,
    )
    duration_ms = round((time.monotonic() - started) * 1000)
    if completed.returncode != 0:
        raise RouteExecutionError(
            f"Ollama exited {completed.returncode}: {_stderr_tail(completed.stderr)}"
        )
    output = _validated_output(_parse_json_text(completed.stdout))
    return RouteResult(
        route_id=spec.route_id,
        route_class=spec.route_class,
        provider=spec.provider,
        model=spec.model,
        execution="live",
        command=_receipt_command(command),
        duration_ms=duration_ms,
        output=output,
    )


def _validated_output(candidate: Any) -> dict[str, str]:
    if not isinstance(candidate, dict):
        raise RouteExecutionError("route output was not a JSON object")
    missing = sorted(set(DECISION_SCHEMA["required"]) - set(candidate))
    extras = sorted(set(candidate) - set(DECISION_SCHEMA["properties"]))
    if missing or extras:
        raise RouteExecutionError(
            f"route output contract mismatch: missing={missing}, extras={extras}"
        )
    output = {key: str(candidate[key]) for key in DECISION_SCHEMA["required"]}
    output["evidence"] = " ".join(
        ANSI_ESCAPE.sub("", output["evidence"]).split()
    )
    actual_core = {key: output[key] for key in EXPECTED_CORE}
    if actual_core != EXPECTED_CORE:
        raise RouteExecutionError(
            f"route decision mismatch: expected={EXPECTED_CORE}, actual={actual_core}"
        )
    if not output["evidence"].strip() or len(output["evidence"]) > 240:
        raise RouteExecutionError("route evidence must be 1..240 characters")
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
        output={
            **EXPECTED_CORE,
            "evidence": "Disclosed deterministic stub preserves the route handoff contract.",
        },
        fallback_reason=reason,
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
            # enforces the exact decision contract and normalizes evidence.
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


def _safe_error(exc: BaseException) -> str:
    message = " ".join(str(exc).split())
    return message[:400] or exc.__class__.__name__


def _stderr_tail(value: str) -> str:
    return " ".join(value.strip().split())[-400:] or "no stderr"


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
