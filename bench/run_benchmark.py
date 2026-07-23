#!/usr/bin/env python3
"""Trust-receipts benchmark v1 runner.

Runs the five probe classes against the installed Heartwood release through the
substrate-neutral adapter, records competitor adapters as honest stubs, scans
all benchmark-facing text against the locked claim anchors, and emits a
machine-readable JSON receipt — including any failures found.

Usage:
    python bench/run_benchmark.py --out bench/results/heartwood-0.2.5-baseline.json
    python bench/run_benchmark.py --print
    python bench/run_benchmark.py --check-deterministic

Exit code is non-zero if any guarantee/positive-control case failed or the
claim-anchor scan found a violation. Documented boundaries never fail the run.
"""
from __future__ import annotations

import argparse
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

_BENCH_DIR = Path(__file__).resolve().parent
if str(_BENCH_DIR) not in sys.path:
    sys.path.insert(0, str(_BENCH_DIR))

import heartwood  # noqa: E402
from trust_benchmark import BENCHMARK_VERSION, TARGET_HEARTWOOD_VERSION  # noqa: E402
from trust_benchmark import claim_scan  # noqa: E402
from trust_benchmark.adapters import HeartwoodAdapter, competitor_stub_adapters  # noqa: E402
from trust_benchmark.model import BOUNDARY, FAIL, PASS, SKIPPED  # noqa: E402
from trust_benchmark.probes import ALL_PROBES  # noqa: E402

_PACIFIC = ZoneInfo("America/Los_Angeles")


def run_suite() -> list[dict]:
    adapter = HeartwoodAdapter()
    try:
        return [probe(adapter).to_dict() for probe in ALL_PROBES]
    finally:
        adapter.cleanup()


def _summarize(probes: list[dict]) -> dict:
    contract_ok = contract_fail = boundaries = 0
    status_counts: dict[str, int] = {}
    for probe in probes:
        status_counts[probe["status"]] = status_counts.get(probe["status"], 0) + 1
        for case in probe["cases"]:
            if case["case_type"] == BOUNDARY:
                boundaries += 1
            elif case["matches_contract"]:
                contract_ok += 1
            else:
                contract_fail += 1
    return {
        "probe_status_counts": status_counts,
        "contract_cases_upheld": contract_ok,
        "contract_cases_failed": contract_fail,
        "boundaries_published": boundaries,
        "overall": FAIL if contract_fail else PASS,
    }


def _competitors() -> list[dict]:
    out = []
    for adapter in competitor_stub_adapters():
        out.append({
            "name": adapter.name,
            "status": "stub",
            "capabilities": adapter.capabilities(),
            "requirements": adapter.requirements(),
        })
    return out


def _now() -> dict:
    utc = datetime.now(timezone.utc)
    return {
        "generated_at_utc": utc.isoformat(),
        "generated_at_pacific": utc.astimezone(_PACIFIC).strftime("%Y-%m-%d %H:%M:%S %Z"),
    }


def _probe_prose(probes: list[dict]) -> str:
    """Human-facing prose from the probe results (descriptions, expectations,
    notes) — the text that could overclaim. Structural enum labels such as the
    ``case_type`` value 'guarantee' are deliberately excluded."""
    lines: list[str] = []
    for probe in probes:
        lines.extend(probe.get("notes", []))
        for case in probe["cases"]:
            lines.append(case.get("description", ""))
            lines.append(case.get("expectation", ""))
    return "\n".join(lines)


def build_receipt(probes: list[dict]) -> dict:
    measured_version = heartwood.__version__
    competitors = _competitors()
    scan_targets = [_BENCH_DIR / "DESIGN.md", _BENCH_DIR / "README.md"]
    violations = claim_scan.scan_files(scan_targets)
    violations += claim_scan.scan_text(_probe_prose(probes), label="<probe-prose>")
    receipt = {
        "benchmark": {
            "name": "heartwood-trust-receipts-benchmark",
            "version": BENCHMARK_VERSION,
            "target_heartwood_version": TARGET_HEARTWOOD_VERSION,
        },
        "system_under_test": {
            "adapter": "heartwood",
            "heartwood_version_measured": measured_version,
            "version_match": measured_version == TARGET_HEARTWOOD_VERSION,
        },
        "reproducibility": {
            "deterministic_models": "heartwood dev hashing embedder + lexical reranker",
            "fixed_fixtures": True,
            "offline": True,
            "note": "governance behavior is embedder-independent; retrieval "
                    "quality is not measured",
        },
        "spend_receipt": {
            "usd_spent": 0,
            "third_party_network_calls": 0,
            "new_credentials_or_signups": 0,
            "new_runtime_dependencies": 0,
            "notes": "stdlib + numpy (a Heartwood dependency) only; competitor "
                     "adapters are stubs; PyPI installation of Heartwood's own "
                     "declared dependencies is not a third-party service call",
        },
        "run_metadata": {
            **_now(),
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "probes": probes,
        "summary": _summarize(probes),
        "competitors": competitors,
    }
    receipt["claim_scan"] = {
        "clean": not violations,
        "violation_count": len(violations),
        "violations": [v.to_dict() for v in violations],
    }
    return receipt


def _deterministic_view(probes: list[dict]) -> str:
    # Everything in probes is deterministic (no timestamps/ids/paths), so the
    # full serialization is the reproducibility fingerprint.
    return json.dumps(probes, sort_keys=True)


def check_deterministic() -> int:
    first = _deterministic_view(run_suite())
    second = _deterministic_view(run_suite())
    identical = first == second
    print(json.dumps({"deterministic": identical}))
    return 0 if identical else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Heartwood trust-receipts benchmark v1")
    parser.add_argument("--out", type=Path, default=None,
                        help="write the JSON receipt to this path")
    parser.add_argument("--print", action="store_true", dest="print_receipt",
                        help="print the JSON receipt to stdout")
    parser.add_argument("--check-deterministic", action="store_true",
                        help="run twice and confirm identical probe results")
    parser.add_argument("--no-fail", action="store_true",
                        help="always exit 0 (report-only; failures still recorded)")
    args = parser.parse_args(argv)

    if args.check_deterministic:
        return check_deterministic()

    receipt = build_receipt(run_suite())
    text = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
    if args.print_receipt or not args.out:
        sys.stdout.write(text)

    summary = receipt["summary"]
    scan = receipt["claim_scan"]
    skipped = summary["probe_status_counts"].get(SKIPPED, 0)
    sys.stderr.write(
        f"[trust-bench] overall={summary['overall']} "
        f"contract_upheld={summary['contract_cases_upheld']} "
        f"contract_failed={summary['contract_cases_failed']} "
        f"boundaries={summary['boundaries_published']} "
        f"skipped_probes={skipped} claim_scan_clean={scan['clean']}\n"
    )
    if args.no_fail:
        return 0
    failed = summary["overall"] == FAIL or not scan["clean"]
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
