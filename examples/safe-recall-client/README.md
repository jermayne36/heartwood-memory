# Safe Recall Client Example

This example shows how to call the warm recall HTTP service without making it a
hard dependency. If Heartwood is unavailable or returns a bad JSON shape, the
client falls back to a local keyword scan over Markdown files and exits 0.

```bash
python examples/safe-recall-client/safe_recall_client.py \
  --query "what should the support agent remember about Acme audit details?" \
  --memory-root ./memory \
  --url http://127.0.0.1:8765 \
  --token-file ./heartwood-recall.token \
  --tenant tenant:acme
```

Service-down fallback smoke:

```bash
python examples/safe-recall-client/safe_recall_client.py \
  --query "Acme audit details" \
  --memory-root ./memory \
  --url http://127.0.0.1:9
```

The token is read from `--token-file`, `HEARTWOOD_RECALL_TOKEN_FILE`, or
`HEARTWOOD_RECALL_TOKEN`. The example never prints the token.
