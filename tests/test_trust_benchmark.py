"""Repo-gated self-tests for the trust-receipts benchmark (bench/).

These run under scripts/check.sh so the benchmark stays correct and offline as
Heartwood evolves. They import the harness from ``bench/`` (which is not part of
the shipped wheel) and exercise every probe against the live adapter.
"""
import os
import sys
from pathlib import Path

os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

_BENCH = Path(__file__).resolve().parent.parent / "bench"
if str(_BENCH) not in sys.path:
    sys.path.insert(0, str(_BENCH))

import pytest  # noqa: E402

import heartwood  # noqa: E402
import run_benchmark  # noqa: E402
from trust_benchmark import TARGET_HEARTWOOD_VERSION, claim_scan  # noqa: E402
from trust_benchmark.adapters import (  # noqa: E402
    HeartwoodAdapter,
    competitor_stub_adapters,
)
from trust_benchmark.adapters.base import AdapterNotAvailable  # noqa: E402
from trust_benchmark.model import (  # noqa: E402
    BOUNDARY,
    CONTRACT,
    PASS,
    POSITIVE_CONTROL,
    SKIPPED,
)
from trust_benchmark.probes import ALL_PROBES, run_forgery  # noqa: E402


@pytest.fixture()
def adapter():
    a = HeartwoodAdapter()
    try:
        yield a
    finally:
        a.cleanup()


def test_target_version_is_current_release():
    # The benchmark is pinned; if the release moves, the target must move with it.
    assert heartwood.__version__ == TARGET_HEARTWOOD_VERSION


def test_every_probe_passes_against_live_heartwood(adapter):
    for probe in ALL_PROBES:
        result = probe(adapter)
        hard = [c for c in result.cases
                if c.case_type in (CONTRACT, POSITIVE_CONTROL)]
        assert hard, f"{result.probe_class} has no guarantee cases"
        for case in hard:
            assert case.matches_contract, (
                f"{result.probe_class}/{case.case_id} did not uphold its "
                f"documented contract; measured={case.measured}"
            )
        assert result.status == PASS, f"{result.probe_class} -> {result.status}"


def test_every_probe_publishes_a_boundary(adapter):
    # The "publish our own limits too" posture: each probe measures at least one
    # documented boundary and it must behave exactly as documented.
    for probe in ALL_PROBES:
        result = probe(adapter)
        boundaries = [c for c in result.cases if c.case_type == BOUNDARY]
        assert boundaries, f"{result.probe_class} publishes no boundary"
        for case in boundaries:
            assert case.matches_contract, (
                f"{result.probe_class}/{case.case_id} boundary diverged from "
                f"documented behavior; measured={case.measured}"
            )


def test_results_are_deterministic(adapter):
    first = [probe(adapter).to_dict() for probe in ALL_PROBES]
    second = [probe(adapter).to_dict() for probe in ALL_PROBES]
    assert first == second


def test_forgery_boundary_signature_survives_metadata_edit(adapter):
    result = run_forgery(adapter)
    boundary = next(c for c in result.cases
                    if c.case_id == "forgery_boundary_unsigned_metadata")
    # A metadata edit must NOT invalidate the content signature — the documented
    # provenance scope is content, not metadata.
    assert boundary.measured["signature_valid"] is True
    assert boundary.measured["content_hash_match"] is True
    assert boundary.claim_anchor == "NOT_CLAIMED:authorization_integrity"


def test_competitor_adapters_are_honest_stubs():
    stubs = competitor_stub_adapters()
    assert {a.name for a in stubs} == {"mem0", "zep", "supermemory"}
    for stub in stubs:
        with pytest.raises(AdapterNotAvailable):
            stub.session()
        assert stub.requirements().get("needs")
        # A stub run of any probe is SKIPPED, never a fabricated comparison.
        result = run_forgery(stub)
        assert result.status == SKIPPED


def test_claim_anchor_scan_is_clean_on_benchmark_text():
    violations = claim_scan.scan_files([_BENCH / "DESIGN.md", _BENCH / "README.md"])
    probes = run_benchmark.run_suite()
    violations += claim_scan.scan_text(
        run_benchmark._probe_prose(probes), label="<probe-prose>"
    )
    assert not violations, [v.to_dict() for v in violations]


def test_claim_scan_catches_overclaims():
    # Negative control: the scanner must catch a real overclaim and must NOT
    # flag the legitimate measured term "tamper-evident".
    assert claim_scan.scan_text("Heartwood is tamper-proof and unbreakable.")
    assert claim_scan.scan_text("We guarantee zero-knowledge storage.")
    assert not claim_scan.scan_text("The audit log is tamper-evident.")
    assert not claim_scan.scan_text(
        "This does not provide authorization-integrity (NOT_CLAIMED)."
    )


def test_receipt_shape_and_spend_gate():
    receipt = run_benchmark.build_receipt(run_benchmark.run_suite())
    assert receipt["system_under_test"]["version_match"] is True
    assert receipt["spend_receipt"]["usd_spent"] == 0
    assert receipt["spend_receipt"]["third_party_network_calls"] == 0
    assert receipt["spend_receipt"]["new_credentials_or_signups"] == 0
    assert len(receipt["competitors"]) == 3
    assert receipt["claim_scan"]["clean"] is True
    assert receipt["summary"]["overall"] == PASS
    assert receipt["summary"]["contract_cases_failed"] == 0
