"""Thin Hermes directory plugin backed by the public Heartwood evaluation package."""
from typing import Any

from heartwood.adapters.hermes import HeartwoodHermesMemoryProvider as _Provider


class HeartwoodHermesMemoryProvider(_Provider):
    """Keep the published 0.2.10 adapter compatible with Hermes session switches."""

    def on_session_switch(self, new_session_id: str, **kwargs: Any) -> None:
        # 0.2.10 predates this hook; keep the shim until the next package release.
        self.session_id = new_session_id or "default"


def register(ctx: Any) -> None:
    ctx.register_memory_provider(HeartwoodHermesMemoryProvider())
