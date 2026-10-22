# Heartwood Memory for Hermes

A thin directory plugin for the public Heartwood evaluation package. Tested on
Hermes **v0.22.4**, commit `4d04303818b61bf3aa09278af48356315515965b`,
on 2026-10-22. This is a **staged Community catalog submission**, not an
approved or official Hermes integration.

Completed conversation turns are stored in local SQLite. The provider recalls
context and exposes `heartwood_recall`, `heartwood_remember`, and
`heartwood_forget`. It uses the existing Heartwood package; no private engine,
hosted service, account, or API key is bundled here.

## Setup

Use Hermes v0.22.4 or newer. After the implementation commit is merged, install
its reviewed 40-character SHA using Hermes's normal dependency preparation:

```sh
hermes plugins install 'jermayne36/heartwood-memory#plugins/hermes' --ref REVIEWED_COMMIT_SHA
hermes plugins enable heartwood
hermes memory setup
```

In the setup picker, select **heartwood**, then accept or change the local
SQLite path and tenant. The default path is `$HERMES_HOME/heartwood.sqlite`;
non-secret settings are saved to `$HERMES_HOME/heartwood.json`.
Start a new Hermes session, then check `hermes memory status`.
The plugin declares `heartwood-memory==0.2.10`; Hermes prepares that dependency
in its managed environment. Do not pip-install into an existing managed Hermes
environment. The tiny session-switch shim supports the published 0.2.10 adapter.

The entry is not in the live catalog yet. Only after maintainer approval and
upstream acceptance will `hermes plugins install heartwood` resolve by name. Community
entries do not receive curated desktop onboarding placement.

## Behaviour and limits

- Hermes keeps its built-in MEMORY/USER memory alongside one external provider.
- Completed turns are retained automatically; do not send data you do not want
  persisted. Already-injected `<memory-context>` blocks are stripped.
- Recall first tries the current session, then the configured tenant. Sessions
  in one tenant are not isolation boundaries. Use separate Hermes profiles and
  database paths for separate stores.
- `heartwood_forget` erases the **whole named subject**, potentially several
  memories. Check the subject before invoking it.
- The SQLite file and its key material live on this machine. Existing Heartwood
  policy and provenance checks apply; this plugin adds no identity verification.
- Default embedding and reranking models may be downloaded from Hugging Face
  on first use. The memory session smoke used the cached pinned models with
  network access disabled. No remote chat model was used.
- `turn_author` is accepted by the source adapter for interface compatibility;
  participant identity is not promoted to a trusted Heartwood principal.

## Release contract check

Use an isolated development venv. Hermes now distributes source installs rather
than a PyPI wheel, and its source distribution metadata reads `0.0.0`; the test
checks the **actual imported checkout commit**, not that placeholder version.

```sh
python3.14 -m venv --copies /tmp/heartwood-hermes-check
. /tmp/heartwood-hermes-check/bin/activate
# Use a fresh external source directory, never the live Hermes installation.
git clone --depth 1 --branch v0.22.4 https://github.com/NousResearch/hermes-agent.git /tmp/hermes-v0.22.4
python -m pip install -e /tmp/hermes-v0.22.4 -e '.[dev]'
bash plugins/hermes/check_release.sh python
HEARTWOOD_TEST_HERMES=1 python -m pytest -q
```

The supported contract lane uses Python 3.14, which installs Hermes's current
runtime dependencies. `--copies` also keeps the existing rotation-demo MCP
subprocess in this venv when it resolves the interpreter path. Python 3.11 source installs omit those dependencies.
Without `HEARTWOOD_TEST_HERMES=1`, the optional contract file reports a named
skip. With it set, missing Hermes or a different checkout fails. A subprocess
positive control proves missing Hermes produces a collection error, not a skip.

`check_release.sh` runs lint and the opted-in real-Hermes contract. The repository
release workflow must invoke this check before publishing a release. Automatic
release-workflow enforcement is pending; current release CI does not yet require
the integration contract.

## Catalog staging

`catalog/heartwood.yaml` is a draft for upstream `plugin-catalog/heartwood.yaml`.
Replace `REPLACE_WITH_REVIEWED_MERGED_COMMIT_SHA` with the reviewed merge commit
containing this plugin, then validate the YAML and plugin admission against that
exact source. The placeholder deliberately prevents treating the draft as an
admission-ready entry. Do not reuse an earlier implementation pin.
`SUBMISSION.md` contains the proposed upstream PR text. Nothing has been sent
upstream. The declared general tools/hooks lists are empty because Hermes
registers memory-provider tools separately; the three actual memory tools are
listed explicitly in the entry's disclosure.

Sources: [provider interface](https://hermes-agent.nousresearch.com/docs/developer-guide/memory-provider-plugin),
[catalog schema and tiers](https://hermes-agent.nousresearch.com/docs/user-guide/features/plugin-catalog),
[v0.22.4 release](https://github.com/NousResearch/hermes-agent/releases/tag/v0.22.4).
