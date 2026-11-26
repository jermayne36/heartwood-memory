# Heartwood plugin package pins for 0.2.11

The Agent and Hermes plugins resolve `heartwood-memory==0.2.11` from PyPI. The
Agent plugin launch command and the managed Copilot command example use the same
pin. Hermes registers the published provider directly because the 0.2.11 wheel
implements the session-switch hook.

Both plugin READMEs document the shared-store custody requirement. Every server
that opens a shared store with wrapped keys needs the same custody root and key
ID, including servers that expose only read operations.

## Verification

- The downloaded PyPI wheel matched the signed release manifest and the pinned
  Ed25519 public key.
- The Agent plugin's `uvx` install reported `heartwood-memory 0.2.11`. A stdio
  session launched from its MCP manifest listed `explain_recall`, `health`, and
  `recall` and returned a healthy response.
- The real Hermes v0.22.4 contract passed all eight tests against the source
  tree and again against the installed 0.2.11 wheel.
- The old package version in the staged Hermes submission records historical
  October 2026 validation. Future catalog checks use the reviewed merge commit.
