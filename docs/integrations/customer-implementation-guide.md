# Customer Implementation Guide

Welcome to Heartwood Memory. This guide takes you from zero to a working recall
integration, then shows the safety patterns we recommend before you wire recall
into a real agent, hook, or app. It is written for customers who are evaluating
or onboarding and want a confident first run — no prior Heartwood experience
assumed.

## What Heartwood Does

Heartwood gives your agents and apps fast, tenant-scoped recall over knowledge
you already have. It is a derived memory layer that sits *beside* your existing
source of truth, not a replacement for it: you keep your Markdown, JSONL,
database, or app records as the source, and Heartwood adds provenance-first
recall on top. Every result can be traced back to where it came from.

## What You Will Have At The End

- A local recall service running on your own machine.
- A small memory corpus imported and queryable.
- A verified, healthy first recall query.
- A safe integration pattern that never crashes your app when recall is
  unavailable.

## Before You Begin

- Python 3.11 or newer (see `docs/platform-support.md`).
- A terminal. The commands in this guide are written for bash or zsh.
- **Windows users:** Heartwood supports Windows. For PowerShell equivalents of
  the path and environment-variable steps, see `docs/platform-support.md`.

The Quickstart below takes about five minutes and runs entirely on your own
machine, so you can explore it with confidence before connecting anything real.

> **Downstream Git safety:** this repository's ignore rules do not propagate into
> another checkout. Before using real memory inputs or import reports in your own
> repository, add equivalent ignores for root-local `*.jsonl` and
> `*-report.json` files (plus local databases, sidecars, tokens, and config), or
> keep them under a project-local ignored `.heartwood/` directory. Deliberate
> fixtures below non-root paths should remain trackable.

## Quickstart

This path uses a local SQLite store, the warm recall service, and a bearer token
stored outside your command history, so the token never lands in shell logs.

### 1. Install

Install the package with the recall and MCP extras, then confirm the CLI is on
your path:

```bash
python -m pip install "heartwood-memory[recall,mcp]"
heartwood --help
```

For a source checkout instead of the published package:

```bash
python -m pip install -e ".[recall,mcp]"
```

### 2. Prepare A Small Memory Corpus

This sample corpus exists only to prove the flow end to end — you will point
Heartwood at your real source later. Create a folder with one or more Markdown
files:

```bash
mkdir -p ./memory
cat > ./memory/acme-audit.md <<'EOF'
---
tenant: acme
subject: acme:audit
classification: internal
epistemic: imported-source
---

Acme audit work should preserve source IDs, reviewer notes, and approval dates.
EOF
```

`tenant:` is normalized to `tenant:<slug>`, so `acme` becomes `tenant:acme`.
If you do not provide frontmatter or a tenant map, the importer uses
`tenant:ops`.

### 3. Import Markdown Into Heartwood

Importing turns your Markdown into recallable memory, tenant by tenant:

```bash
install -d -m 700 .heartwood
heartwood import-markdown ./memory \
  --db ./.heartwood/heartwood.db \
  --default-tenant tenant:ops \
  --tenant-map-json '{"acme":"tenant:acme"}' \
  --output ./heartwood-import-report.json
```

For fast smoke tests without external embedding models:

```bash
heartwood import-markdown ./memory --db ./.heartwood/heartwood.db --dev-models
```

Check the report. A healthy first import has `source_lag_count` equal to `0` and
`source_coverage_count` equal to `source_count`.

### 4. Start Warm Recall

Use an environment variable or token file. Prefer a token file for local agents
and supervised services because process arguments can be visible to other
processes.

```bash
umask 077
printf '%s' "$(openssl rand -hex 24)" > ./.heartwood/heartwood-recall.token

heartwood serve-recall \
  --db ./.heartwood/heartwood.db \
  --tenant tenant:ops \
  --warm-tenant tenant:ops \
  --warm-tenant tenant:acme \
  --host 127.0.0.1 \
  --port 8765 \
  --token-file ./.heartwood/heartwood-recall.token
```

Keep this terminal open for the first smoke test.

### 5. Run The First Recall Query

This is the moment of truth. Leave the service running and, in another terminal,
ask Heartwood a question:

```bash
heartwood recall \
  --url http://127.0.0.1:8765 \
  --token-file ./.heartwood/heartwood-recall.token \
  --tenant tenant:acme \
  --principal-id agent:app \
  --query "what should the agent remember about Acme audit work?" \
  --k 5 \
  --json
```

A healthy response has `ok: true`, the tenant you queried, `latency_ms`,
`recall_id`, `index_lag`, `result_count`, `results`, and model names.

### 6. Confirm Health

One last check confirms the service is up. Public health is intentionally
liveness-only:

```bash
curl -s http://127.0.0.1:8765/health | python -m json.tool
```

Expected shape:

```json
{
  "ok": true,
  "service": "heartwood-recall"
}
```

Do not depend on `/health` for warmed-tenants, model, or key-custody metadata.

If you need local model and readiness diagnostics, enable
`HEARTWOOD_RECALL_LOCAL_DIAGNOSTICS=1` before starting the daemon and call the
loopback-only readiness endpoint with the bearer token:

```bash
curl -s \
  -H "Authorization: Bearer $(tr -d '\n' < ./.heartwood/heartwood-recall.token)" \
  http://127.0.0.1:8765/local/readiness | python -m json.tool
```

Expected diagnostic shape:

```json
{
  "ok": true,
  "service": "heartwood-recall",
  "local_only": true,
  "embedder": {
    "name": "sentence-transformers/all-MiniLM-L6-v2@1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
    "dimension": 384,
    "dev_fallback": false
  },
  "reranker": {
    "name": "cross-encoder/ms-marco-MiniLM-L-6-v2@c5ee24cb16019beea0893ab7796b1df96625c6b8",
    "dev_fallback": false
  },
  "index": "numpy",
  "db_embedding_dimensions": [384],
  "checks": {
    "non_dev_embedder": true,
    "non_dev_reranker": true,
    "db_dimension_match": true
  }
}
```

`/local/readiness` is only available from loopback when local diagnostics are
enabled. When bearer auth is configured, the readiness request must include the
same bearer token used for recall calls.

## Worked Example: Safe Integration

Do not make your app, hook, or agent crash just because recall is unavailable.
Treat Heartwood as progressive enhancement:

1. Call `POST /recall` with a short timeout.
2. Parse and validate the response shape before reading nested fields.
3. If anything is missing, malformed, slow, or unauthorized, return a safe local
   fallback.
4. Never log the bearer token or raw secrets.

The runnable example is in:

```bash
examples/safe-recall-client/safe_recall_client.py
```

Run it against the service:

```bash
python examples/safe-recall-client/safe_recall_client.py \
  --query "what should the agent remember about Acme audit work?" \
  --memory-root ./memory \
  --url http://127.0.0.1:8765 \
  --token-file ./.heartwood/heartwood-recall.token \
  --tenant tenant:acme
```

Run the same example with the service down. It still exits 0 and returns
`source: "keyword_fallback"`:

```bash
python examples/safe-recall-client/safe_recall_client.py \
  --query "Acme audit work" \
  --memory-root ./memory \
  --url http://127.0.0.1:9
```

The important guards are:

```python
if not isinstance(data, dict) or not data.get("ok", False):
    return []

results = data.get("results", [])
if not isinstance(results, list):
    return []

for result in results:
    if not isinstance(result, dict):
        continue
```

For nested maps, do not use `obj.get("nested") or {}` as a type guard. A truthy
string or list will pass that expression and crash at the next `.get()`. Normalize
each nested map explicitly:

```python
provenance = result.get("provenance")
provenance = provenance if isinstance(provenance, dict) else {}
source = provenance.get("source")
source = source if isinstance(source, dict) else {}
```

## Worked Example: Supervise The Service

For a developer laptop or a local agent runner, supervise warm recall so model
warmup and the SQLite store survive terminal restarts.

### macOS LaunchAgent

Use an application-data path instead of Desktop, Documents, Downloads, or iCloud
Drive. LaunchAgents can fail under macOS privacy controls when they run from
protected folders.

```bash
mkdir -p "$HOME/Library/Application Support/Heartwood"
mkdir -p "$HOME/Library/Logs/Heartwood"
cp ./.heartwood/heartwood.db "$HOME/Library/Application Support/Heartwood/heartwood.db"
install -m 600 ./.heartwood/heartwood-recall.token "$HOME/Library/Application Support/Heartwood/recall.token"
python -c "import sys; print(sys.executable)"
```

Save this as `~/Library/LaunchAgents/com.heartwood.recall.plist`, replacing the
interpreter and user paths:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.heartwood.recall</string>
  <key>ProgramArguments</key>
  <array>
    <string>/absolute/path/to/.venv/bin/python</string>
    <string>-m</string>
    <string>heartwood.cli</string>
    <string>serve-recall</string>
    <string>--db</string>
    <string>/Users/alex/Library/Application Support/Heartwood/heartwood.db</string>
    <string>--tenant</string>
    <string>tenant:ops</string>
    <string>--host</string>
    <string>127.0.0.1</string>
    <string>--port</string>
    <string>8765</string>
    <string>--token-file</string>
    <string>/Users/alex/Library/Application Support/Heartwood/recall.token</string>
  </array>
  <key>WorkingDirectory</key>
  <string>/Users/alex/Library/Application Support/Heartwood</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/Users/alex/Library/Logs/Heartwood/recall.out.log</string>
  <key>StandardErrorPath</key>
  <string>/Users/alex/Library/Logs/Heartwood/recall.err.log</string>
</dict>
</plist>
```

Load and verify:

```bash
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.heartwood.recall.plist"
launchctl kickstart -k "gui/$(id -u)/com.heartwood.recall"
curl -s http://127.0.0.1:8765/health | python -m json.tool
```

Unload:

```bash
launchctl bootout "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.heartwood.recall.plist"
```

### Linux systemd User Service

The OSS repo does not currently ship a systemd unit. Use the same durable shape:

- absolute Python interpreter path;
- application-data working directory;
- database and token file outside the repo checkout;
- restart-on-failure policy;
- `HEARTWOOD_KEY_CUSTODY_ROOT_B64` supplied from your secret manager when using
  custody mode.

The `ExecStart` command should be the same `python -m heartwood.cli
serve-recall ... --token-file ...` command shown above.

## Worked Example: Keep Memory Fresh

Keep your source corpus as the source of truth. Re-run `import-markdown` after
source changes, then run a recall smoke.

```bash
heartwood import-markdown ./memory \
  --db ./.heartwood/heartwood.db \
  --default-tenant tenant:ops \
  --tenant-map-json '{"acme":"tenant:acme"}' \
  --output ./heartwood-import-report.json

python - <<'PY'
import json
report = json.load(open("heartwood-import-report.json", encoding="utf-8"))
assert report["source_lag_count"] == 0, report
assert report["source_coverage_count"] == report["source_count"], report
print("IMPORT_FRESH")
PY

heartwood recall \
  --url http://127.0.0.1:8765 \
  --token-file ./.heartwood/heartwood-recall.token \
  --tenant tenant:acme \
  --query "Acme audit work" \
  --k 5 \
  --json
```

If your recall service runs from a copied runtime database, copy or back up the
updated store into the runtime location and restart the supervised service.

## Tips And Good Habits

A few habits keep your integration calm and predictable as you move toward
production:

- Guard every response shape. Transport errors, JSON parse errors, non-dict
  bodies, non-list `results`, non-dict result rows, and malformed nested
  `provenance.source` values should all fall back cleanly.
- `obj.get("nested") or {}` is not a type guard. Use `isinstance(value, dict)`
  before reading child keys.
- Keep timeout layering explicit. A hook or app call should have a short recall
  timeout, such as 1.5 seconds, inside any larger application-level timeout.
- Prefer `--token-file`, `HEARTWOOD_RECALL_TOKEN_FILE`, or
  `HEARTWOOD_RECALL_TOKEN`. Do not print bearer tokens in logs, tickets, or
  command output.
- Keep the service bound to `127.0.0.1` unless you have explicit network auth
  and isolation. The warm recall HTTP service is designed for local use.
- Use tenant IDs deliberately. Frontmatter `tenant: acme` and CLI
  `--tenant tenant:acme` refer to the same normalized tenant.
- Use the import report for freshness. Database file mtimes can change because
  of WAL/checkpoint activity without a new source import.
- Run a recall quality gate before cutover. At minimum, keep a small set of
  representative prompts and require a stable hit@5 floor.

## Verify-It-Works Checklist

Run these commands top to bottom. If each one passes, your local setup is sound
and you are ready to integrate with confidence:

```bash
heartwood --help
test -f ./.heartwood/heartwood.db
test -f ./heartwood-import-report.json
python - <<'PY'
import json
report = json.load(open("heartwood-import-report.json", encoding="utf-8"))
print({
    "source_count": report["source_count"],
    "source_lag_count": report["source_lag_count"],
    "source_coverage_count": report["source_coverage_count"],
})
assert report["source_lag_count"] == 0
assert report["source_coverage_count"] == report["source_count"]
PY
curl -s http://127.0.0.1:8765/health | python -m json.tool
heartwood recall --url http://127.0.0.1:8765 --token-file ./.heartwood/heartwood-recall.token --tenant tenant:acme --query "Acme audit work" --k 5 --json
heartwood bench-recall --url http://127.0.0.1:8765 --token-file ./.heartwood/heartwood-recall.token --tenant tenant:acme --query "Acme audit work" --repeat 10 --max-p95-ms 500 --require-pass
python examples/safe-recall-client/safe_recall_client.py --query "Acme audit work" --memory-root ./memory --url http://127.0.0.1:9
```

The final command intentionally points at a closed port. It should still exit 0
and return `source: "keyword_fallback"`.

## Source Receipts

These are the source-of-truth checks used for this guide:

- Package install and script name: `pyproject.toml:5-10`,
  `pyproject.toml:38-53`, and `pyproject.toml:66-67`.
- README quickstart commands: `README.md:60-64` and `README.md:102-106`.
- `import-markdown` CLI flags: `heartwood/cli.py:317-342`.
- Markdown importer tenant/frontmatter/idempotency behavior:
  `heartwood/importers/markdown.py:105-127`,
  `heartwood/importers/markdown.py:337-407`, and
  `heartwood/importers/markdown.py:492-555`.
- `recall`, `serve-recall`, token, and benchmark CLI flags:
  `heartwood/cli.py:198-219`, `heartwood/cli.py:286-300`,
  `heartwood/cli.py:359-382`, and `heartwood/cli.py:403-415`.
- Warm recall request, response, health, auth, and routes:
  `heartwood/recall_service.py:125-156`,
  `heartwood/recall_service.py:175-186`,
  `heartwood/recall_service.py:222-265`,
  `heartwood/recall_service.py:283-318`, and
  `heartwood/recall_service.py:321-350`.
- Existing warm recall docs and HTTP examples:
  `docs/integrations/warm-recall.md:17-90`,
  `docs/integrations/warm-recall.md:110-179`, and
  `docs/integrations/warm-recall.md:181-217`.
- Existing macOS supervision guidance:
  `docs/integrations/macos-launchd.md:1-79`.
- Key-custody environment and mode guidance:
  `docs/security/key-custody.md:1-49`.
- Fail-safe response-shape and fallback reference integration:
  `examples/safe-recall-client/safe_recall_client.py:72-135`.
- Supervised runtime reference:
  `docs/integrations/macos-launchd.md:6-29` and
  `docs/integrations/macos-launchd.md:31-86`.
- Recall quality gate reference:
  `heartwood/cli.py:144-195` and `heartwood/cli.py:403-415`.
