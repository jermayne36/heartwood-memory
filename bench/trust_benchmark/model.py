"""Verdict model for the trust-receipts benchmark.

A probe runs one or more *cases*. Each case declares a documented
*expectation* (the guarantee or the honest boundary the docs state) and
records the *measured* outcome plus whether the measurement matched the
documented contract.

Case types
----------
- ``contract``: the docs state this holds (a documented contract). If measured
  != documented, the probe FAILs (a real defect to report, not to fix here).
- ``positive_control``: a case proving the mechanism is not vacuously "deny
  everything" (e.g. a cleared principal DOES see a restricted record). Treated
  like a contract case for status purposes.
- ``boundary``: a documented non-claim / honest limit (e.g. unsigned metadata
  is not authenticated). Informational and always published; it never fails a
  probe, because the boundary is the weakest documented position.

Status
------
- ``FAIL``  if any contract/positive_control case did not match its documentation.
- ``PASS``  otherwise.
- ``DEGRADED`` is reserved for a boundary case whose measured behavior diverged
  from the documented boundary (surfaced for human review; not expected).
- ``SKIPPED`` when the adapter cannot run the probe (e.g. competitor stub, or
  the underlying primitive is absent).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

CONTRACT = "contract"
POSITIVE_CONTROL = "positive_control"
BOUNDARY = "boundary"

PASS = "PASS"
FAIL = "FAIL"
DEGRADED = "DEGRADED"
SKIPPED = "SKIPPED"


@dataclass
class Case:
    case_id: str
    case_type: str
    description: str
    expectation: str
    measured: dict
    matches_contract: bool
    claim_anchor: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ProbeResult:
    probe_class: str
    receipt_name: str
    status: str
    cases: list[Case] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "probe_class": self.probe_class,
            "receipt_name": self.receipt_name,
            "status": self.status,
            "cases": [c.to_dict() for c in self.cases],
            "notes": list(self.notes),
        }


def status_from_cases(cases: list[Case]) -> str:
    """Derive a probe status from its cases (see module docstring)."""
    hard = [c for c in cases if c.case_type in (CONTRACT, POSITIVE_CONTROL)]
    if any(not c.matches_contract for c in hard):
        return FAIL
    soft = [c for c in cases if c.case_type == BOUNDARY]
    if any(not c.matches_contract for c in soft):
        return DEGRADED
    return PASS


def make_probe(probe_class: str, receipt_name: str, cases: list[Case],
               notes: list[str] | None = None) -> ProbeResult:
    return ProbeResult(
        probe_class=probe_class,
        receipt_name=receipt_name,
        status=status_from_cases(cases),
        cases=cases,
        notes=list(notes or []),
    )


def skipped_probe(probe_class: str, receipt_name: str, reason: str,
                  requirements: dict | None = None) -> ProbeResult:
    note = f"SKIPPED: {reason}"
    result = ProbeResult(
        probe_class=probe_class,
        receipt_name=receipt_name,
        status=SKIPPED,
        cases=[],
        notes=[note],
    )
    if requirements:
        result.notes.append("real-run requirements: " + _compact(requirements))
    return result


def _compact(mapping: dict) -> str:
    return "; ".join(f"{k}={v}" for k, v in mapping.items())
