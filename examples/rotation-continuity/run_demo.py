#!/usr/bin/env python3
"""Run one governed agent session across GPT, Claude, and open-weight routes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from heartwood import Heartwood  # noqa: E402
from heartwood.adapters.mcp_server import MCPMemoryAPI  # noqa: E402
from demo_models import EMBEDDER_NAME, RERANKER_NAME, embed, rerank  # noqa: E402
from routes import (  # noqa: E402
    EXPECTED_CORE,
    RouteResult,
    decision_prompt,
    default_route_specs,
    run_route,
)


TENANT = "tenant:rotation-continuity-demo"
AGENT_ID = "agent:rotation-continuity-demo"
SUBJECT = "project:juniper"
MEMORY_ID = "mem:rotation-demo:juniper-region"
POLICY_ID = "mem:rotation-demo:juniper-release-policy"
SCENARIO = (
    "Project Juniper may deploy only in us-west. Security approval SEC-417 is "
    "still pending. The release control requires the decision BLOCK until "
    "security approval exists; its stable token is security_approval_required."
)
QUERY = "Project Juniper release decision security approval region"
NEGATIVE_CONTROL_ENV_NAME = "HEARTWOOD_ROTATION_SENTINEL"
# "after" means after swapping to a route; "before" means before leaving it.
CHECKPOINTS = (
    ("route-a-before-swap", "route-a"),
    ("route-b-after-swap", "route-b"),
    ("route-b-before-swap", "route-b"),
    ("route-c-after-swap", "route-c"),
)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Prove Heartwood memory, policy, and audit continuity across three "
            "mid-session model routes."
        )
    )
    parser.add_argument(
        "--route-mode",
        choices=("auto", "live", "stub"),
        default="auto",
        help="auto attempts live routes then discloses stubs; live fails closed",
    )
    parser.add_argument(
        "--require-live",
        type=int,
        choices=range(0, 4),
        default=2,
        help="minimum live route count required for PASS (default: 2)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="empty destination for store, receipts, and transcript",
    )
    parser.add_argument(
        "--gpt-model",
        default="gpt-5.6-sol",
        help="Codex model id for route A",
    )
    parser.add_argument(
        "--claude-model",
        default="sonnet",
        help="Claude Code model alias/id for route B",
    )
    parser.add_argument(
        "--open-weights-model",
        default=(
            "kwangsuklee/Qwen3.5-9B-Claude-4.6-Opus-Reasoning-Distilled-GGUF:latest"
        ),
        help="local Ollama model for route C",
    )
    parser.add_argument(
        "--route-timeout-seconds",
        type=int,
        default=300,
        help="per-provider subprocess timeout",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_dir = _prepare_output_dir(args.output_dir)
    receipts_dir = output_dir / "receipts"
    receipts_dir.mkdir()
    db_path = output_dir / "heartwood-demo.db"
    boundary_temp = tempfile.TemporaryDirectory(
        prefix="heartwood-rotation-negative-control-"
    )
    sentinel_file = Path(boundary_temp.name) / "readable-sentinel.txt"
    sentinel_values = (
        f"HW_ENV_{secrets.token_hex(24)}",
        f"HW_FILE_{secrets.token_hex(24)}",
    )
    sentinel_file.write_text(sentinel_values[1], encoding="utf-8")
    previous_sentinel = os.environ.get(NEGATIVE_CONTROL_ENV_NAME)
    os.environ[NEGATIVE_CONTROL_ENV_NAME] = sentinel_values[0]

    db = Heartwood(
        path=db_path,
        tenant=TENANT,
        embedder=(embed, EMBEDDER_NAME),
        reranker=(rerank, RERANKER_NAME),
    )
    api = MCPMemoryAPI(db)
    route_results: list[RouteResult] = []
    checkpoint_receipts: list[dict[str, Any]] = []
    try:
        specs = default_route_specs(
            gpt_model=args.gpt_model,
            claude_model=args.claude_model,
            open_weights_model=args.open_weights_model,
        )
        spec_by_id = {spec.route_id: spec for spec in specs}

        route_a = run_route(
            specs[0],
            decision_prompt(
                route_id=specs[0].route_id,
                scenario=SCENARIO,
                recalled_context=[],
            ),
            mode=args.route_mode,
            timeout_seconds=args.route_timeout_seconds,
            forbidden_values=sentinel_values,
        )
        route_results.append(route_a)
        _append_route_event(
            db,
            action="route_select",
            route=route_a,
            from_route=None,
        )
        _write_route_a_state(db, route_a)

        reference_fingerprint: str | None = None
        route_context: dict[str, list[str]] = {}
        for checkpoint_name, route_id in CHECKPOINTS:
            if checkpoint_name == "route-b-after-swap":
                _append_route_event(
                    db,
                    action="route_swap",
                    route=RouteResult(
                        route_id=route_id,
                        route_class=spec_by_id[route_id].route_class,
                        provider=spec_by_id[route_id].provider,
                        model=spec_by_id[route_id].model,
                        execution="pending",
                        command=[],
                        duration_ms=0,
                        output={},
                    ),
                    from_route="route-a",
                )
            elif checkpoint_name == "route-c-after-swap":
                _append_route_event(
                    db,
                    action="route_swap",
                    route=RouteResult(
                        route_id=route_id,
                        route_class=spec_by_id[route_id].route_class,
                        provider=spec_by_id[route_id].provider,
                        model=spec_by_id[route_id].model,
                        execution="pending",
                        command=[],
                        duration_ms=0,
                        output={},
                    ),
                    from_route="route-b",
                )

            receipt = _checkpoint(api, db, checkpoint_name=checkpoint_name, route_id=route_id)
            checkpoint_receipts.append(receipt)
            route_context[checkpoint_name] = receipt["authorized"]["contents"]
            _write_json(
                receipts_dir / f"{checkpoint_name}.json",
                receipt,
            )
            if reference_fingerprint is None:
                reference_fingerprint = receipt["continuity_fingerprint"]
            elif receipt["continuity_fingerprint"] != reference_fingerprint:
                raise AssertionError(
                    f"continuity fingerprint drifted at {checkpoint_name}"
                )

            if checkpoint_name == "route-b-after-swap":
                route_b = run_route(
                    specs[1],
                    decision_prompt(
                        route_id=specs[1].route_id,
                        scenario=None,
                        recalled_context=receipt["authorized"]["contents"],
                    ),
                    mode=args.route_mode,
                    timeout_seconds=args.route_timeout_seconds,
                    forbidden_values=sentinel_values,
                )
                route_results.append(route_b)
            elif checkpoint_name == "route-c-after-swap":
                route_c = run_route(
                    specs[2],
                    decision_prompt(
                        route_id=specs[2].route_id,
                        scenario=None,
                        recalled_context=receipt["authorized"]["contents"],
                    ),
                    mode=args.route_mode,
                    timeout_seconds=args.route_timeout_seconds,
                    forbidden_values=sentinel_values,
                )
                route_results.append(route_c)

        route_status = _route_status_receipt(args, route_results)
        _assert_sentinels_absent(
            sentinel_values,
            json.dumps(route_status, sort_keys=True),
        )
        _write_json(output_dir / "route-status.json", route_status)
        summary = _build_summary(
            args=args,
            output_dir=output_dir,
            db_path=db_path,
            db=db,
            route_results=route_results,
            checkpoint_receipts=checkpoint_receipts,
            reference_fingerprint=reference_fingerprint or "",
        )
        if any(
            NEGATIVE_CONTROL_ENV_NAME in result.environment_keys
            for result in route_results
        ):
            raise AssertionError("ambient sentinel variable entered a route environment")
        if not sentinel_file.is_file() or not os.access(sentinel_file, os.R_OK):
            raise AssertionError("negative-control sentinel file was not readable")
        if not all(result.provider_streams_clear for result in route_results):
            raise AssertionError("provider stream negative control failed")
        summary["negative_controls"] = {
            "ambient_environment_sentinel_excluded": True,
            "readable_sentinel_file_created": True,
            "provider_streams_clear": True,
            "persisted_artifacts_clear": True,
        }
        summary["route_status_receipt"] = "route-status.json"
        transcript = _render_transcript(summary)
        console = _console_summary(summary)
        _assert_sentinels_absent(
            sentinel_values,
            json.dumps(summary, sort_keys=True),
            json.dumps(summary["audit_chain"], sort_keys=True),
            json.dumps(route_status, sort_keys=True),
            transcript,
            console,
        )
        _write_json(output_dir / "session.json", summary)
        _write_json(output_dir / "audit-chain.json", summary["audit_chain"])
        (output_dir / "transcript.md").write_text(
            transcript,
            encoding="utf-8",
        )
        print(console)
        return 0
    finally:
        if previous_sentinel is None:
            os.environ.pop(NEGATIVE_CONTROL_ENV_NAME, None)
        else:
            os.environ[NEGATIVE_CONTROL_ENV_NAME] = previous_sentinel
        boundary_temp.cleanup()
        api.close()


def _prepare_output_dir(requested: Path | None) -> Path:
    if requested is None:
        return Path(tempfile.mkdtemp(prefix="heartwood-rotation-continuity-"))
    output_dir = requested.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    if any(output_dir.iterdir()):
        raise SystemExit(f"output directory must be empty: {output_dir}")
    return output_dir


def _route_status_receipt(
    args: argparse.Namespace,
    route_results: list[RouteResult],
) -> dict[str, Any]:
    live_count = sum(result.execution == "live" for result in route_results)
    return {
        "status": "PASS" if live_count >= args.require_live else "FAIL",
        "required_live_routes": args.require_live,
        "observed_live_routes": live_count,
        "routes": [
            {
                "route_id": result.route_id,
                "provider": result.provider,
                "model": result.model,
                "execution": result.execution,
                "environment_keys": list(result.environment_keys),
                "tool_boundary": result.tool_boundary,
                "provider_streams_clear": result.provider_streams_clear,
                "fallback_reason": result.fallback_reason,
            }
            for result in route_results
        ],
    }


def _assert_sentinels_absent(
    sentinel_values: tuple[str, ...],
    *artifacts: str,
) -> None:
    if any(
        value and value in artifact
        for value in sentinel_values
        for artifact in artifacts
    ):
        raise AssertionError(
            "negative-control sentinel reached a persisted or displayed artifact"
        )


def _write_route_a_state(db: Heartwood, route: RouteResult) -> None:
    output = route.output
    memory_content = (
        f"Project Juniper's approved deployment region is {output['region']}."
    )
    policy_content = (
        f"Project Juniper release decision is {output['decision']} until security "
        f"approval exists; control={output['control']}."
    )
    db.remember(
        memory_content,
        memory_id=MEMORY_ID,
        subject=SUBJECT,
        created_by=AGENT_ID,
        kind="semantic",
        epistemic="user-stated",
        source={"kind": "demo-scenario", "uri": "demo://juniper/session"},
        source_ids=("demo://juniper/session",),
        policy=db.policy(classification="internal"),
        policy_scope="rotation-demo",
        model_version=f"{route.provider}:{route.model}",
    )
    db.remember(
        policy_content,
        memory_id=POLICY_ID,
        subject=SUBJECT,
        created_by=AGENT_ID,
        kind="procedural",
        epistemic="model-generated",
        source={"kind": "demo-scenario", "uri": "demo://juniper/release-control"},
        source_ids=("demo://juniper/release-control",),
        policy=db.policy(
            classification="confidential",
            roles=("release-manager",),
        ),
        policy_scope="release-control",
        model_version=f"{route.provider}:{route.model}",
    )
    db.approve(
        POLICY_ID,
        db.principal(
            id=AGENT_ID,
            roles=("approver", "release-manager"),
            clearance="confidential",
        ),
    )


def _append_route_event(
    db: Heartwood,
    *,
    action: str,
    route: RouteResult,
    from_route: str | None,
) -> None:
    detail = {
        "from_route": from_route,
        "to_route": route.route_id,
        "route_class": route.route_class,
        "provider": route.provider,
        "model": route.model,
    }
    db.audit.append(TENANT, AGENT_ID, action, route.route_id, detail)


def _checkpoint(
    api: MCPMemoryAPI,
    db: Heartwood,
    *,
    checkpoint_name: str,
    route_id: str,
) -> dict[str, Any]:
    authorized = api.recall(
        QUERY,
        tenant=TENANT,
        principal_id=AGENT_ID,
        roles=["release-manager"],
        clearance="confidential",
        subject=SUBJECT,
        k=5,
        topc=10,
    )
    authorized_explain = api.explain_recall(
        authorized["recall_id"],
        tenant=TENANT,
    )
    unauthorized = api.recall(
        QUERY,
        tenant=TENANT,
        principal_id=AGENT_ID,
        roles=[],
        clearance="internal",
        subject=SUBJECT,
        k=5,
        topc=10,
    )
    unauthorized_explain = api.explain_recall(
        unauthorized["recall_id"],
        tenant=TENANT,
    )

    authorized_ids = sorted(row["id"] for row in authorized["results"])
    unauthorized_ids = sorted(row["id"] for row in unauthorized["results"])
    if authorized_ids != sorted((MEMORY_ID, POLICY_ID)):
        raise AssertionError(f"authorized result drift: {authorized_ids}")
    if unauthorized_ids != [MEMORY_ID]:
        raise AssertionError(f"policy decision leaked or memory disappeared: {unauthorized_ids}")
    if not all(
        row["provenance_valid"] is True and row["content_hash_match"] is True
        for row in authorized["results"]
    ):
        raise AssertionError("provenance or content-hash verification failed")
    if authorized["index_lag"] != 0 or unauthorized["index_lag"] != 0:
        raise AssertionError("demo requires read-your-writes (index_lag=0)")
    if db.verify_audit() is not True:
        raise AssertionError("audit chain failed verification at checkpoint")

    stable_state = {
        "tenant": TENANT,
        "agent_id": AGENT_ID,
        "authorized_result_ids": authorized_ids,
        "unauthorized_result_ids": unauthorized_ids,
        "authorized_contents_sha256": {
            row["id"]: hashlib.sha256(row["content"].encode()).hexdigest()
            for row in authorized["results"]
        },
        "authorized_policy": {
            row["id"]: {
                "classification": row["classification"],
                "truth_status": row["truth_status"],
                "source_ids": list(row["source_ids"]),
            }
            for row in authorized["results"]
        },
        "authorized_explain": _stable_explain(authorized_explain),
        "unauthorized_explain": _stable_explain(unauthorized_explain),
    }
    fingerprint = hashlib.sha256(
        json.dumps(stable_state, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    audit_rows = _audit_rows(db)
    return {
        "checkpoint": checkpoint_name,
        "route_id": route_id,
        "continuity_fingerprint": fingerprint,
        "authorized": {
            "recall_id": authorized["recall_id"],
            "result_ids": authorized_ids,
            "contents": [row["content"] for row in authorized["results"]],
            "provenance_valid": {
                row["id"]: row["provenance_valid"] for row in authorized["results"]
            },
            "content_hash_match": {
                row["id"]: row["content_hash_match"] for row in authorized["results"]
            },
            "explain_recall": authorized_explain,
        },
        "unauthorized": {
            "recall_id": unauthorized["recall_id"],
            "result_ids": unauthorized_ids,
            "policy_memory_visible": POLICY_ID in unauthorized_ids,
            "explain_recall": unauthorized_explain,
        },
        "audit": {
            "verify_chain": True,
            "event_count": len(audit_rows),
            "head_hash": audit_rows[-1]["row_hash"],
        },
        "stable_state": stable_state,
    }


def _stable_explain(explanation: dict[str, Any]) -> dict[str, Any]:
    if "error" in explanation:
        raise AssertionError(f"explain_recall failed: {explanation['error']}")
    if "denied" in explanation or "denied_reasons" in explanation:
        raise AssertionError("public explain receipt exposed denied-candidate details")
    return {
        "candidates_considered": explanation["candidates_considered"],
        "visible": explanation["visible"],
        "index_lag": explanation["index_lag"],
        "result_ids": sorted(explanation["result_ids"]),
        "review_states": explanation["review_states"],
        "hidden_review_states": explanation["hidden_review_states"],
        "validity_enforced": explanation["validity_enforced"],
    }


def _audit_rows(db: Heartwood) -> list[dict[str, Any]]:
    rows = db.store.conn.execute(
        "SELECT seq, ts, tenant, principal, action, target, body, prev_hash, row_hash "
        "FROM audit_log ORDER BY seq"
    ).fetchall()
    result: list[dict[str, Any]] = []
    for row in rows:
        body = json.loads(row["body"])
        metadata_matches = (
            body.get("tenant") == row["tenant"]
            and body.get("principal") == row["principal"]
            and body.get("action") == row["action"]
            and body.get("target") == row["target"]
        )
        if not metadata_matches:
            raise AssertionError(
                "displayed audit metadata diverged from the hash-bound event body"
            )
        result.append(
            {
                "seq": row["seq"],
                "ts": row["ts"],
                "tenant": row["tenant"],
                "principal": row["principal"],
                "action": row["action"],
                "target": row["target"],
                "metadata_matches_hash_bound_body": True,
                "prev_hash": row["prev_hash"],
                "row_hash": row["row_hash"],
            }
        )
    return result


def _build_summary(
    *,
    args: argparse.Namespace,
    output_dir: Path,
    db_path: Path,
    db: Heartwood,
    route_results: list[RouteResult],
    checkpoint_receipts: list[dict[str, Any]],
    reference_fingerprint: str,
) -> dict[str, Any]:
    route_core = [
        {key: result.output[key] for key in EXPECTED_CORE}
        for result in route_results
    ]
    if not route_core or any(core != EXPECTED_CORE for core in route_core):
        raise AssertionError("route decisions were not identical")
    live_count = sum(result.execution == "live" for result in route_results)
    if live_count < args.require_live:
        raise AssertionError(
            f"required at least {args.require_live} live routes, observed {live_count}"
        )

    audit_rows = _audit_rows(db)
    if db.verify_audit() is not True:
        raise AssertionError("final audit chain verification failed")
    if any(row["tenant"] != TENANT for row in audit_rows):
        raise AssertionError("more than one tenant entered the demo audit chain")
    if any(row["principal"] != AGENT_ID for row in audit_rows):
        raise AssertionError("more than one agent principal entered the demo audit chain")
    if not all(
        row["metadata_matches_hash_bound_body"] is True
        for row in audit_rows
    ):
        raise AssertionError("displayed audit metadata did not match hash-bound bodies")
    linkage_ok = all(
        row["prev_hash"] == ("genesis" if index == 0 else audit_rows[index - 1]["row_hash"])
        for index, row in enumerate(audit_rows)
    )
    if not linkage_ok:
        raise AssertionError("audit prev_hash/row_hash linkage failed")

    fingerprints = {
        receipt["continuity_fingerprint"] for receipt in checkpoint_receipts
    }
    if fingerprints != {reference_fingerprint}:
        raise AssertionError("checkpoint fingerprints were not identical")
    model_version_rows = db.store.conn.execute(
        "SELECT id, model_version, classification, epistemic "
        "FROM memories ORDER BY id"
    ).fetchall()

    return {
        "status": "PASS",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": {
            "agent_id": AGENT_ID,
            "tenant": TENANT,
            "store_path": str(db_path),
            "isolated_from_live_team_daemon": True,
            "scenario": SCENARIO,
            "route_mode": args.route_mode,
            "required_live_routes": args.require_live,
            "live_route_count": live_count,
            "output_dir": str(output_dir),
        },
        "claims": {
            "shipped_continuity_proved": (
                "Heartwood memory, policy filtering, explain receipts, and the "
                "hash-chained audit remain stable across route swaps."
            ),
            "model_outputs_compared": (
                "Only the structured decision core is compared; prose identity "
                "is not claimed."
            ),
            "not_claimed": (
                "This is not a capability-contract or model-quality rotation "
                "receipt, and it does not prove constrained-org Copilot policy."
            ),
        },
        "routes": [result.to_dict() for result in route_results],
        "route_decision_core": route_core,
        "memory_rows": [
            {
                "id": row["id"],
                "model_version": row["model_version"],
                "classification": row["classification"],
                "epistemic": row["epistemic"],
            }
            for row in model_version_rows
        ],
        "continuity": {
            "fingerprint": reference_fingerprint,
            "checkpoint_count": len(checkpoint_receipts),
            "all_checkpoint_fingerprints_identical": True,
            "policy_memory_denied_without_release_manager": all(
                not receipt["unauthorized"]["policy_memory_visible"]
                for receipt in checkpoint_receipts
            ),
            "all_provenance_valid": all(
                all(receipt["authorized"]["provenance_valid"].values())
                for receipt in checkpoint_receipts
            ),
            "all_content_hashes_match": all(
                all(receipt["authorized"]["content_hash_match"].values())
                for receipt in checkpoint_receipts
            ),
            "checkpoints": checkpoint_receipts,
        },
        "audit_chain": {
            "verify_audit": True,
            "linkage_ok": linkage_ok,
            "displayed_metadata_matches_hash_bound_body": True,
            "event_count": len(audit_rows),
            "genesis_prev_hash": audit_rows[0]["prev_hash"],
            "head_hash": audit_rows[-1]["row_hash"],
            "events": audit_rows,
        },
    }


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _render_transcript(summary: dict[str, Any]) -> str:
    lines = [
        "# Heartwood rotation-continuity session transcript",
        "",
        f"- Status: **{summary['status']}**",
        f"- Agent: `{summary['scope']['agent_id']}`",
        f"- Tenant: `{summary['scope']['tenant']}`",
        f"- Isolated store: `{summary['scope']['store_path']}`",
        f"- Live routes: `{summary['scope']['live_route_count']}/3`",
        (
            "- Continuity fingerprint: "
            f"`{summary['continuity']['fingerprint']}`"
        ),
        "",
        "## Route decisions",
        "",
        "| Route | Class | Provider/model | Execution | Decision | Region | Control |",
        "|---|---|---|---|---|---|---|",
    ]
    for route in summary["routes"]:
        output = route["output"]
        lines.append(
            f"| {route['route_id']} | {route['route_class']} | "
            f"{route['provider']} / {route['model']} | {route['execution']} | "
            f"{output['decision']} | {output['region']} | {output['control']} |"
        )
        if route["fallback_reason"]:
            lines.append(f"\nStub disclosure for `{route['route_id']}`: {route['fallback_reason']}\n")

    lines.extend(
        [
            "",
            "## Route boundary receipt",
            "",
            "| Route | Environment keys only | Tool boundary | Provider streams clear |",
            "|---|---|---|---|",
        ]
    )
    for route in summary["routes"]:
        environment_keys = ",".join(route["environment_keys"]) or "none"
        lines.append(
            f"| {route['route_id']} | `{environment_keys}` | "
            f"{route['tool_boundary']} | {route['provider_streams_clear']} |"
        )
    lines.extend(
        [
            "",
            "Negative controls: ambient sentinel excluded; readable sentinel file "
            "not observed; provider streams and persisted artifacts clear.",
        ]
    )

    lines.extend(["", "## Explain-recall receipts", ""])
    for checkpoint in summary["continuity"]["checkpoints"]:
        authorized = checkpoint["authorized"]
        unauthorized = checkpoint["unauthorized"]
        lines.extend(
            [
                f"### {checkpoint['checkpoint']}",
                "",
                f"- Route: `{checkpoint['route_id']}`",
                f"- Fingerprint: `{checkpoint['continuity_fingerprint']}`",
                f"- Authorized result IDs: `{authorized['result_ids']}`",
                f"- Unauthorized result IDs: `{unauthorized['result_ids']}`",
                (
                    "- Policy decision visible without `release-manager`: "
                    f"`{unauthorized['policy_memory_visible']}`"
                ),
                (
                    "- Authorized explain: "
                    f"`{json.dumps(_stable_explain(authorized['explain_recall']), sort_keys=True)}`"
                ),
                (
                    "- Unauthorized explain: "
                    f"`{json.dumps(_stable_explain(unauthorized['explain_recall']), sort_keys=True)}`"
                ),
                (
                    "- Audit at checkpoint: "
                    f"`verify_chain={checkpoint['audit']['verify_chain']}, "
                    f"events={checkpoint['audit']['event_count']}, "
                    f"head={checkpoint['audit']['head_hash']}`"
                ),
                "",
            ]
        )

    audit = summary["audit_chain"]
    lines.extend(
        [
            "## Final audit-chain receipt",
            "",
            f"- `verify_audit={audit['verify_audit']}`",
            f"- `prev_hash_linkage={audit['linkage_ok']}`",
            (
                "- `displayed_metadata_matches_hash_bound_body="
                f"{audit['displayed_metadata_matches_hash_bound_body']}`"
            ),
            f"- `event_count={audit['event_count']}`",
            f"- `genesis_prev_hash={audit['genesis_prev_hash']}`",
            f"- `head_hash={audit['head_hash']}`",
            "",
            "| Seq | Tenant | Principal | Action | Target | Metadata/body | Previous hash | Row hash |",
            "|---:|---|---|---|---|---|---|---|",
        ]
    )
    for event in audit["events"]:
        lines.append(
            f"| {event['seq']} | {event['tenant']} | {event['principal']} | "
            f"{event['action']} | {event['target']} | "
            f"{event['metadata_matches_hash_bound_body']} | "
            f"`{event['prev_hash'][:16]}` | `{event['row_hash'][:16]}` |"
        )

    lines.extend(
        [
            "",
            "## Honest boundary",
            "",
            summary["claims"]["not_claimed"],
            "",
        ]
    )
    return "\n".join(lines)


def _console_summary(summary: dict[str, Any]) -> str:
    executions = ", ".join(
        f"{route['route_id']}={route['execution']}:{route['provider']}:{route['model']}"
        for route in summary["routes"]
    )
    return "\n".join(
        [
            "ROTATION_CONTINUITY_DEMO=PASS",
            f"LIVE_ROUTES={summary['scope']['live_route_count']}/3",
            f"ROUTES={executions}",
            (
                "CONTINUITY_FINGERPRINT="
                f"{summary['continuity']['fingerprint']}"
            ),
            "POLICY_DENIAL_IDENTICAL=true",
            "EXPLAIN_RECEIPTS=4",
            f"AUDIT_CHAIN_VERIFY={str(summary['audit_chain']['verify_audit']).lower()}",
            "AUDIT_METADATA_MATCH=true",
            "NEGATIVE_CONTROLS=PASS",
            f"AUDIT_EVENTS={summary['audit_chain']['event_count']}",
            f"OUTPUT_DIR={summary['scope']['output_dir']}",
            f"TRANSCRIPT={Path(summary['scope']['output_dir']) / 'transcript.md'}",
            f"ROUTE_STATUS={Path(summary['scope']['output_dir']) / 'route-status.json'}",
        ]
    )


if __name__ == "__main__":
    raise SystemExit(main())
