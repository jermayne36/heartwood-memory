# Strict mode and audit-anchor quickstart

Use this scratch-only walkthrough to exercise `FILTER`, `ENFORCE`, and
`heartwood verify-audit` against a new local store. Run it from an activated
Python 3.11 environment after installing `heartwood-memory[recall,mcp]`.
Keep production stores, custody roots, and anchor sinks out of this walkthrough.

## Keep the existing claim boundary

Use the locked vocabulary from
[Continuity capability contracts and rotation receipts](continuity.md#security-claim-scope-and-deployment-assumptions):

```text
HEARTWOOD_CLAIM_SCOPE=content_provenance_authenticity
HEARTWOOD_NOT_CLAIMED=recall_exclusion
HEARTWOOD_NOT_CLAIMED=authorization_integrity
HEARTWOOD_NOT_CLAIMED=tamper_proof_rbac_or_visibility
HEARTWOOD_NOT_CLAIMED=db_compromise_resistance
```

Retain this existing anchored claim when describing the receipt:

> A successful verification establishes authenticity only for the signed
> receipt content and the content/provenance bindings named in its payload,
> subject to the verification-root assumption above. It does not establish
> recall exclusion, authorization integrity, tamper-proof RBAC or visibility,
> or resistance to a principal that can rewrite the database.

Do not extend that claim when presenting this operator walk.

## Create the scratch store and exercise strict modes

Copy and run this block in a Bash-compatible shell:

```bash
export HEARTWOOD_DEMO_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/heartwood-strict-anchor.XXXXXX")"

python - <<'PY'
import json
import os
from pathlib import Path
import sqlite3

import numpy as np

from heartwood import (
    Heartwood,
    LocalFileAnchorSink,
    LocalKmsCustodian,
    Principal,
    StrictMode,
    StrictSignatureError,
    anchor_root_fingerprint,
)

root = Path(os.environ["HEARTWOOD_DEMO_ROOT"])
db_path = root / "audit.db"
anchor_path = root / "anchors.jsonl"
tenant = "tenant:strict-anchor-quickstart"
custodian = LocalKmsCustodian(os.urandom(32), key_id="quickstart-root-v1")


def embed(texts):
    rows = np.zeros((len(texts), 4), dtype=np.float32)
    for index, text in enumerate(texts):
        lowered = text.lower()
        rows[index] = [
            1.0,
            float("forged" in lowered),
            float("provenance" in lowered),
            float("signature" in lowered),
        ]
    return rows


def rerank(query, texts):
    query_tokens = set(query.lower().split())
    return np.asarray(
        [
            len(query_tokens & set(text.lower().split()))
            for text in texts
        ],
        dtype=np.float32,
    )


models = (
    (embed, "quickstart-embedder"),
    (rerank, "quickstart-reranker"),
)

bootstrap = Heartwood(
    path=db_path,
    tenant=tenant,
    embedder=models[0],
    reranker=models[1],
    key_custodian=custodian,
)
chain_id = bootstrap.store.chain_id()
bootstrap.close()

sink = LocalFileAnchorSink(anchor_path)
fingerprint = anchor_root_fingerprint(
    custodian,
    chain_id=chain_id,
    sink_id=sink.sink_id,
)


def open_db(mode):
    return Heartwood(
        path=db_path,
        tenant=tenant,
        embedder=models[0],
        reranker=models[1],
        key_custodian=custodian,
        strict_signatures=mode,
        anchor_sink=sink,
        anchor_root_fingerprints=fingerprint,
        anchor_every_n_rows=1,
    )


writer = open_db(StrictMode.OFF)
memory_id = writer.remember(
    "Strict verification rejects a forged provenance signature.",
    subject="subject:strict-anchor-quickstart",
    created_by="agent:quickstart",
    source={"uri": "doc://strict-anchor-quickstart"},
)
writer.close()

with sqlite3.connect(db_path) as conn:
    signature = conn.execute(
        "SELECT producer_sig FROM memories WHERE id=?",
        (memory_id,),
    ).fetchone()[0]
    algorithm, public_key, signature_bytes = signature.split(":", 2)
    replacement = "A" if signature_bytes[0] != "A" else "B"
    forged = f"{algorithm}:{public_key}:{replacement}{signature_bytes[1:]}"
    conn.execute(
        "UPDATE memories SET producer_sig=?, sig_valid=1 WHERE id=?",
        (forged, memory_id),
    )

principal = Principal(
    id="agent:quickstart-reader",
    tenant=tenant,
    clearance="internal",
)

filtered_db = open_db(StrictMode.FILTER)
filtered = filtered_db.recall(
    "forged provenance signature",
    principal=principal,
    k=3,
)
filtered_explanation = filtered_db.explain_recall(filtered["recall_id"])
filtered_db.close()
assert filtered["results"] == []
assert filtered_explanation["strict_dropped"]["reason_buckets"] == {
    "signature_invalid": 1,
}

enforced_db = open_db(StrictMode.ENFORCE)
try:
    enforced_db.recall(
        "forged provenance signature",
        principal=principal,
        filters={"strict_signatures": "off"},
        k=3,
    )
except StrictSignatureError as exc:
    enforced = {
        "raised_StrictSignatureError": True,
        "reason_buckets": exc.reason_buckets,
    }
else:
    raise AssertionError("ENFORCE returned forged provenance")
finally:
    enforced_db.close()

assert enforced["reason_buckets"] == {"signature_invalid": 1}
(root / "anchor-root.txt").write_text(fingerprint + "\n", encoding="utf-8")
print(json.dumps({
    "filter": {
        "result_count": len(filtered["results"]),
        "strict_dropped": filtered_explanation["strict_dropped"],
    },
    "enforce": enforced,
}, indent=2, sort_keys=True))
print("STRICT_MODE_WALK=PASS")
PY
```

Accept the strict-mode step only when it prints `STRICT_MODE_WALK=PASS`, the
`filter.result_count` is `0`, and
`enforce.raised_StrictSignatureError` is `true`.

## Verify the audit anchor

Run the receipt CLI against the same scratch store:

```bash
heartwood verify-audit \
  --db "$HEARTWOOD_DEMO_ROOT/audit.db" \
  --anchors "$HEARTWOOD_DEMO_ROOT/anchors.jsonl" \
  --anchor-root-fingerprint "$(cat "$HEARTWOOD_DEMO_ROOT/anchor-root.txt")" \
  --every-n-rows 1 \
  | tee "$HEARTWOOD_DEMO_ROOT/verify-audit.json"

python - "$HEARTWOOD_DEMO_ROOT/verify-audit.json" <<'PY'
import json
from pathlib import Path
import sys

receipt = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert receipt["ok"] is True
assert receipt["chain_ok"] is True
assert receipt["anchors_ok"] is True
assert receipt["anchor_fresh"] is True
assert receipt["sink_healthy"] is True
print("VERIFY_AUDIT_OK=true")
PY
```

Accept the anchor step only when the CLI exits `0` and the final check prints
`VERIFY_AUDIT_OK=true`. Keep the printed `HEARTWOOD_DEMO_ROOT` path with the
demo receipt, or remove that scratch directory after inspection.
