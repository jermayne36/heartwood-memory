"""Claim-anchor / locked-vocabulary scanner for benchmark-facing text.

Mechanical gate (Rule 46 spirit): benchmark docs, README, and result text must
stay inside Heartwood's documented claim scope. The scope is
``content_provenance_authenticity``; the NOT-claimed capabilities are
recall-exclusion, authorization-integrity, tamper-proof RBAC/visibility, and
database-compromise resistance (see ``docs/api/continuity.md``).

Two rule classes:

- **Hard-banned** tokens must never appear (overclaim vocabulary): "guarantee",
  "tamper-proof", "zero-knowledge", "unbreakable", "provable erasure", etc. The
  benchmark speaks in measured/evidence language only.
- **Claim-guarded** capability phrases (the NOT-claimed set) may appear ONLY in
  a disclaimer context on the same line (a negation marker or the literal
  ``NOT_CLAIMED`` anchor). A bare positive use is a violation.

``tamper-evident`` and ``tamper evidence`` are explicitly allowed — they are the
receipt's real, measured property and are never treated as overclaims.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_HARD_BANNED = [
    r"guarantee[ds]?",
    r"guaranteed",
    r"unbreakable",
    r"zero[\s_-]?knowledge",
    r"provabl[ey][\s_-]+eras",
    r"military[\s_-]?grade",
    r"100%\s+secure",
    r"cannot\s+be\s+decrypted",
    r"not\s+a\s+single\s+byte",
]

# NOT-claimed capability phrases (flexible separator). Allowed only with a
# disclaimer marker on the same line.
_CLAIM_GUARDED = [
    r"recall[\s_-]?exclusion",
    r"authorization[\s_-]?integrity",
    r"tamper[\s_-]?proof",
    r"db[\s_-]?compromise[\s_-]?resistance",
    r"database[\s_-]?compromise[\s_-]?resistance",
]

# A line disclaims (rather than claims) a NOT-claimed capability when it carries
# a negation or the NOT_CLAIMED anchor. Word boundaries so "NOT-claimed",
# "does not", and "cannot" all count.
_DISCLAIMER_RE = re.compile(
    r"\bnot\b|\bno\b|\bnor\b|\bcannot\b|\bwithout\b|\boutside\b|\bnon\b|\bnever\b"
    r"|not_claimed|non-claim|boundary|\bassume",
    re.IGNORECASE,
)

_ALLOWED_NEAR = ["tamper-evident", "tamper evident", "tamper_evidence", "tamper evidence"]


@dataclass
class Violation:
    file: str
    line_no: int
    term: str
    line: str

    def to_dict(self) -> dict:
        return {"file": self.file, "line_no": self.line_no, "term": self.term,
                "line": self.line.strip()[:200]}


def _has_disclaimer(line: str) -> bool:
    return bool(_DISCLAIMER_RE.search(line))


def scan_text(text: str, *, label: str = "<text>") -> list[Violation]:
    violations: list[Violation] = []
    lines = text.splitlines()
    for i, raw_line in enumerate(lines, start=1):
        lower = raw_line.lower()
        # Prose wraps: a disclaimer on the previous line still governs this one.
        context = (lines[i - 2].lower() + " " if i >= 2 else "") + lower
        for pattern in _HARD_BANNED:
            if re.search(pattern, lower):
                violations.append(Violation(label, i, f"hard-banned:{pattern}", raw_line))
        for pattern in _CLAIM_GUARDED:
            for match in re.finditer(pattern, lower):
                window = lower[max(0, match.start() - 40): match.end() + 40]
                if any(a in window for a in _ALLOWED_NEAR):
                    continue
                if not _has_disclaimer(context):
                    violations.append(
                        Violation(label, i, f"unguarded-claim:{pattern}", raw_line)
                    )
    return violations


def scan_files(paths: list[str | Path]) -> list[Violation]:
    violations: list[Violation] = []
    for path in paths:
        p = Path(path)
        if not p.exists():
            continue
        violations.extend(scan_text(p.read_text(encoding="utf-8"), label=str(p)))
    return violations
