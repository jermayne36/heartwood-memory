# Staged upstream PR — not submitted

Maintainer approval is required before opening this PR in NousResearch/hermes-agent.
This draft has not been submitted upstream.

**Proposed title:** Add Heartwood local memory provider (Community)

**Proposed body:**

Adds `plugin-catalog/heartwood.yaml`, pointing at the reviewed Heartwood plugin
implementation commit in `jermayne36/heartwood-memory`, subdirectory
`plugins/hermes`.

The plugin uses the public Heartwood evaluation package (`heartwood-memory==0.2.10`).
It persists completed conversation turns in local SQLite and provides recall,
remember and subject-erasure tools through Hermes's memory-provider interface.
It requires no account or API key. Default embedding/reranking models may be
downloaded from Hugging Face on first use. Recall can include other sessions in
the configured tenant. The forget tool erases all memories for the named subject.

Requested tier: **Community**. No official/verified badge or desktop onboarding
placement is requested. Hermes's general plugin tool/hook/middleware capability
lists are empty because the entry point registers a MemoryProvider; its memory
tools are explicitly disclosed in the entry description and README.

Validation performed against Hermes v0.22.4, upstream commit
`4d04303818b61bf3aa09278af48356315515965b`:

- Real upstream `MemoryProvider`, plugin discovery and `MemoryManager` round trip.
- Opted-in contract: **8 passed**, including missing-dependency fail-closed control.
- Cross-session store/recall with the published Heartwood 0.2.10 package and cached
  pinned embedding/reranking models; audit verification passed. No chat-model
  account was used; this is a memory lifecycle transcript, not an LLM chat test.
- Upstream plugin admission: **15 checks passed, zero warnings**.
- Final catalog YAML validation remains pending replacement of the draft SHA.

**Before sending:** confirm the Heartwood implementation PR is merged and reviewed,
replace the catalog SHA placeholder with that reviewed merge commit, rerun admission
against the pin, and attach the current contract/full-suite totals from the
maintainer note. Automatic release-workflow enforcement remains pending.

**File to copy:** `plugins/hermes/catalog/heartwood.yaml` → upstream
`plugin-catalog/heartwood.yaml`. Do not submit this whole plugin directory upstream.
