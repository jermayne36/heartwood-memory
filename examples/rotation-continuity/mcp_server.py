#!/usr/bin/env python3
"""Run the standard Heartwood MCP adapter with the demo's offline models."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from demo_models import EMBEDDER_NAME, RERANKER_NAME, embed, rerank  # noqa: E402
from heartwood import Heartwood, Principal  # noqa: E402
from heartwood.adapters.mcp_server import build_server  # noqa: E402


def main() -> None:
    db_path = os.environ.get("HEARTWOOD_DB_PATH", ":memory:")
    tenant = os.environ.get(
        "HEARTWOOD_TENANT",
        "tenant:rotation-continuity-demo",
    )
    db = Heartwood(
        path=db_path,
        tenant=tenant,
        embedder=(embed, EMBEDDER_NAME),
        reranker=(rerank, RERANKER_NAME),
    )
    # The IDE client recalls as the demo's release manager. MCP clients cannot
    # choose their own tenant, roles or clearance; the server binds them here.
    mcp, _db, _backend = build_server(
        db=db,
        name="heartwood-rotation-continuity-demo",
        principal=Principal(
            id="agent:rotation-continuity-demo",
            tenant=db.tenant,
            roles=("release-manager",),
            clearance="confidential",
        ),
    )
    mcp.run()


if __name__ == "__main__":
    main()
