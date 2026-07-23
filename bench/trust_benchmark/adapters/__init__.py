"""Adapter layer for the trust-receipts benchmark.

The benchmark measures governance *receipts* through a substrate-neutral
adapter interface (``MemoryAdapter`` / ``Session``). Heartwood implements it
live; competitor adapters are honest stubs that declare what a real run would
require. A probe describes an attack semantically (e.g. "flip a signed record's
content hash"); the adapter knows how to execute it on its own substrate. A
system that lacks a primitive (no signed provenance, no hash-chained audit)
simply cannot implement the corresponding adversary op — the probe then records
the primitive as absent rather than inventing a comparison.
"""
from .base import AdapterNotAvailable, MemoryAdapter, RecallView, Session
from .heartwood_adapter import HeartwoodAdapter
from .stubs import STUB_ADAPTERS, competitor_stub_adapters

__all__ = [
    "AdapterNotAvailable",
    "MemoryAdapter",
    "RecallView",
    "Session",
    "HeartwoodAdapter",
    "STUB_ADAPTERS",
    "competitor_stub_adapters",
]
