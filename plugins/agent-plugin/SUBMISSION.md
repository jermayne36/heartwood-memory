# Staged awesome-copilot submission — NOT SENT

Maintainer approval is required before any issue, PR, or comment is posted outside
this repository. Heartwood is not listed in awesome-copilot yet.

The current [contribution rules](https://github.com/github/awesome-copilot/blob/main/CONTRIBUTING.md)
require new external plugins to use the **External plugin submission** issue
form. Do not open a PR directly adding a new entry to `plugins/external.json`.
Maintainers review the issue, then automation creates the catalog PR on approval.
The catalog entry and PR copy below are staged for that eventual workflow.

## Exact proposed catalog entry

```json
{
  "name": "heartwood",
  "description": "Recall local Heartwood memories with provenance; propose memory writes for user review.",
  "version": "0.1.0",
  "author": {
    "name": "Heartwood Memory",
    "url": "https://github.com/jermayne36"
  },
  "homepage": "https://heartwoodmemory.com/",
  "keywords": [
    "memory",
    "provenance",
    "mcp",
    "read-only"
  ],
  "license": "BUSL-1.1",
  "repository": "https://github.com/jermayne36/heartwood-memory",
  "source": {
    "source": "github",
    "repo": "jermayne36/heartwood-memory",
    "path": "plugins/agent-plugin",
    "sha": "REPLACE_WITH_SQUASH_MERGED_SHA"
  }
}
```

Before submission, replace all three `REPLACE_WITH_SQUASH_MERGED_SHA` placeholders
with the same full 40-character squash-merged commit SHA: the catalog `source.sha`
above, the issue's **Commit SHA to review** below, and its **Reviewed source** URL.
Each placeholder is pending replacement by that squash-merged SHA; none is a
submission-ready pin. Re-run intake checks against the merged revision. Do not
submit a branch name or a pre-merge commit.

## Issue title

[External Plugin]: heartwood

## Exact issue body / issue-form values

<!-- external-plugin-submission -->

### Plugin name
heartwood

### Short description
Recall local Heartwood memories with provenance; propose memory writes for user review.

### GitHub repository
jermayne36/heartwood-memory

### Plugin path inside the repository
plugins/agent-plugin

### Ref to review
_No response_

### Commit SHA to review
REPLACE_WITH_SQUASH_MERGED_SHA

### Version
0.1.0

### License identifier
BUSL-1.1

### Author name
Heartwood Memory

### Author URL
https://github.com/jermayne36

### Homepage URL
https://heartwoodmemory.com/

### Keywords
memory, provenance, mcp, read-only

### Additional notes for reviewers

The public package is an evaluation adapter with one Agent Skills file and one
stdio MCP server configuration. The server installs the published
`heartwood-memory==0.2.10` PyPI package via `uvx`. A small standard-library startup
expression creates a per-user local data directory and calls the published MCP
entry point. The explicit server allowlist exposes only `recall`, `explain_recall`,
and `health`. The skill treats memories as evidence, cites their returned IDs
and sources, and proposes writes for user approval; no write tools are exposed.

No account or hosted API key is required. First launch downloads Python package
dependencies and may download retrieval models. The operator explicitly seeds or
imports local records; the plugin does not ingest workspace content silently.
Read-only describes the memory tool surface: initialization and recall may write
local key files, audit records, and recall traces. The process is not sandboxed
by this plugin. It runs with the local user's permissions.

Both JSON files pass the published Agent Plugins 1.0.0 schemas. macOS VS Code
1.138.0 loaded the local plugin and discovered 3 tools. A real stdio MCP session
using the exact final config listed the three safe tools and successfully called
health, recall, and explain_recall against a synthetic store. Ruff and the wheel/
sdist build passed; the existing suite passed (500 passed, 2 skipped).
A Copilot model-driven chat/skill invocation, Copilot CLI/app, Windows, and an
enterprise rollout were not verified. Managed-settings examples are staged for
use after a listing exists. The plugin is BUSL-1.1 source-available, not OSI open
source. Any paid-service guidance should be reviewed before submission; this
adapter requires no purchase or account.

Reviewed source: https://github.com/jermayne36/heartwood-memory/tree/REPLACE_WITH_SQUASH_MERGED_SHA/plugins/agent-plugin

### Submission checklist
- [x] The plugin lives in a public GitHub repository.
- [ ] The ref and/or sha I provided is immutable (release tag and/or full 40-character commit SHA), not a branch.
- [x] This submission follows this repository's contribution, security, and responsible AI policies.
- [x] This plugin is not already listed in the Awesome Copilot marketplace.

Complete the unchecked item only after replacing every pin with the squash-merged
SHA. Recheck marketplace listing status before submission.

## Staged catalog PR title

Add Heartwood read-only memory plugin

## Exact staged catalog PR body

Add `heartwood` as an external Agent Plugins 1.0 package from the public
`jermayne36/heartwood-memory` evaluation repository, pinned to the reviewed commit.
The package provides one recall skill and a local MCP configuration exposing only
recall, explain_recall, and health. Memory updates are proposed for user approval
and executed separately by the operator.

Validation: published manifest/MCP schemas; macOS VS Code local plugin discovery
and 3 MCP tools; real stdio demo recall and explanation; Ruff; Python wheel/sdist
build; 500 tests passed, 2 skipped. Copilot model-driven chat, CLI/app, Windows,
and enterprise rollout are not verified. License: BUSL-1.1, source-available.

For a new external listing, this PR must be generated through the maintainers'
approved issue workflow rather than sent directly by the submitter.
