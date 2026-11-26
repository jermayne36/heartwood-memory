"""Thin Hermes directory plugin backed by the public Heartwood Memory 0.2.11 package."""
from typing import Any

from heartwood.adapters.hermes import HeartwoodHermesMemoryProvider


def register(ctx: Any) -> None:
    ctx.register_memory_provider(HeartwoodHermesMemoryProvider())
