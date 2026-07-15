# Heartwood Python API

Generated from the current package surface by `scripts/generate_api_docs.py`.

## Functions

| Function | Signature |
| --- | --- |
| `normalize_tenant` | `normalize_tenant(value: 'Any', *, default: 'str' = 'tenant:default') -> 'str'` |
| `tenant_slug` | `tenant_slug(tenant: 'Any', *, default: 'str' = 'tenant:default') -> 'str'` |
| `policy_from` | `policy_from(value: 'Policy | Mapping[str, Any] | None' = None, **overrides: 'Any') -> 'Policy'` |
| `principal_from` | `principal_from(value: 'Principal | Mapping[str, Any] | str | None' = None, *, id: 'str | None' = None, tenant: 'str | None' = None, roles: 'Any' = None, attrs: 'Any' = None, clearance: 'str | None' = None, default_tenant: 'str' = 'tenant:default') -> 'Principal'` |

## Classes

### `Heartwood`

| Method | Signature |
| --- | --- |
| `add_provenance_edge` | `add_provenance_edge(self, child, parent, kind='derived_from')` |
| `approve` | `approve(self, mem_id, principal: 'Principal')` |
| `assess_faithfulness` | `assess_faithfulness(self, candidate: 'dict', *, support_threshold: 'float' = 0.72, review_threshold: 'float' = 0.45) -> 'dict'` |
| `close` | `close(self) -> 'None'` |
| `evaluate_egress` | `evaluate_egress(self, request: 'dict', provider_registry: 'dict | None' = None) -> 'dict'` |
| `explain_recall` | `explain_recall(self, recall_id: 'str') -> 'dict'` |
| `flush_index` | `flush_index(self)` |
| `forget` | `forget(self, subject, *, mode='hard', actor='system', reason='', legal_basis='')` |
| `info` | `info(self) -> 'dict'` |
| `key_custody_info` | `key_custody_info(self, subject: 'str') -> 'dict'` |
| `policy` | `policy(self, policy: 'Policy | dict | None' = None, **overrides) -> 'Policy'` |
| `principal` | `principal(self, id: 'str' = 'agent:recall', *, tenant: 'str | None' = None, roles=(), attrs=(), clearance: 'str' = 'internal') -> 'Principal'` |
| `purge` | `purge(self, mem_id: 'str', actor='system') -> 'bool'` |
| `read_content` | `read_content(self, mem_id: 'str') -> 'str | None'` |
| `recall` | `recall(self, cue, *, principal: 'Principal', filters=None, k=8, topc=50)` |
| `recall_for_tenant` | `recall_for_tenant(self, tenant: 'str', cue: 'str', *, principal: 'Principal | dict | str | None' = None, principal_id: 'str' = 'agent:recall', roles=(), attrs=(), clearance: 'str' = 'internal', filters=None, k=8, topc=50) -> 'dict'` |
| `remember` | `remember(self, content, *, subject, created_by, kind='semantic', epistemic='user-stated', confidence=0.8, salience=0.5, source=None, policy=None, model_version=None, derived_from=(), memory_id=None, truth_status=None, policy_scope='default', valid_from=None, valid_until=None, entities=(), source_ids=(), source_spans=(), subject_ids=(), created_at=None)` |
| `remember_generated` | `remember_generated(self, content, *, subject, created_by, claims, source_spans, source_ids=(), egress_request=None, provider_registry=None, policy=None, model_version=None, memory_id=None, kind='generated', confidence=0.8, salience=0.5, support_threshold=0.72, review_threshold=0.45, allow_human_review=False, store_unaccepted=False, **kwargs) -> 'dict'` |
| `remember_many` | `remember_many(self, records: 'Iterable[dict]', *, default_created_by='agent:bulk', default_policy: 'Policy | dict | None' = None, default_tenant: 'str | None' = None, stop_on_error: 'bool' = False) -> 'dict'` |
| `verify_audit` | `verify_audit(self) -> 'bool'` |
| `with_tenant` | `with_tenant(self, tenant: 'str')` |

### `Policy`

Policy(visibility: 'str' = 'tenant', classification: 'str' = 'internal', pii: 'bool' = False, roles: 'tuple' = (), attrs: 'tuple' = (), retention: 'str' = 'decayable', role_groups: 'tuple' = ())

Fields:

- `visibility`
- `classification`
- `pii`
- `roles`
- `attrs`
- `retention`
- `role_groups`

| Method | Signature |
| --- | --- |
| `requirement_groups` | `requirement_groups(self) -> 'list'` |
| `validate` | `validate(self)` |

### `Principal`

Principal(id: 'str', tenant: 'str', roles: 'tuple' = (), attrs: 'tuple' = (), clearance: 'str' = 'internal')

Fields:

- `id`
- `tenant`
- `roles`
- `attrs`
- `clearance`

| Method | Signature |
| --- | --- |
| `attr_map` | `attr_map(self) -> 'dict'` |

### `LocalKmsCustodian`

Local KMS-compatible custodian using HKDF and AES key wrap.

Fields:

- `root_key`
- `key_id`

| Method | Signature |
| --- | --- |
| `info` | `info(self, envelope: 'bytes | None' = None) -> 'dict'` |
| `unwrap` | `unwrap(self, *, tenant: 'str', subject: 'str', envelope: 'bytes') -> 'bytes'` |
| `wrap` | `wrap(self, *, tenant: 'str', subject: 'str', dek: 'bytes') -> 'bytes'` |

### `RawKeyCustodian`

Compatibility custodian: stores raw DEKs exactly like early Phase 0.

| Method | Signature |
| --- | --- |
| `info` | `info(self, envelope: 'bytes | None' = None) -> 'dict'` |
| `unwrap` | `unwrap(self, *, tenant: 'str', subject: 'str', envelope: 'bytes') -> 'bytes'` |
| `wrap` | `wrap(self, *, tenant: 'str', subject: 'str', dek: 'bytes') -> 'bytes'` |

### `MCPMemoryAPI`

Governed MCP-facing facade over one or more tenant-scoped clients.

| Method | Signature |
| --- | --- |
| `assess_faithfulness` | `assess_faithfulness(self, candidate: 'dict', support_threshold: 'float' = 0.72, review_threshold: 'float' = 0.45, tenant: 'str | None' = None) -> 'dict'` |
| `backend` | `backend(self, tenant: 'str | None' = None, *, created_by: 'str' = 'agent:mcp', subject: 'str' = 'memory-tool-user', classification: 'str' = 'internal') -> 'MemoryToolBackend'` |
| `client` | `client(self, tenant: 'str | None' = None) -> 'Heartwood'` |
| `close` | `close(self) -> 'None'` |
| `evaluate_egress` | `evaluate_egress(self, request: 'dict', provider_registry: 'dict | None' = None, tenant: 'str | None' = None) -> 'dict'` |
| `explain_recall` | `explain_recall(self, recall_id: 'str', tenant: 'str | None' = None) -> 'dict'` |
| `forget` | `forget(self, subject: 'str', tenant: 'str | None' = None, mode: 'str' = 'hard', actor: 'str' = 'agent:mcp', reason: 'str' = '', legal_basis: 'str' = '') -> 'dict'` |
| `health` | `health(self) -> 'dict'` |
| `memory` | `memory(self, command: 'str', path: 'str' = '', file_text: 'str' = '', old_str: 'str' = '', new_str: 'str' = '', insert_line: 'int' = 0, insert_text: 'str' = '', old_path: 'str' = '', new_path: 'str' = '', view_range: 'list[int] | None' = None, tenant: 'str | None' = None, created_by: 'str' = 'agent:mcp', subject: 'str' = 'memory-tool-user', classification: 'str' = 'internal') -> 'str'` |
| `recall` | `recall(self, cue: 'str', principal_id: 'str' = 'agent:mcp', tenant: 'str | None' = None, roles: 'list[str] | str | None' = None, attrs: 'dict | list[str] | str | None' = None, clearance: 'str' = 'internal', subject: 'str' = '', k: 'int' = 8, topc: 'int' = 50, filters: 'dict | None' = None, method: 'str' = '', typed: 'bool' = False) -> 'dict'` |
| `remember` | `remember(self, content: 'str', subject: 'str', created_by: 'str' = 'agent:mcp', tenant: 'str | None' = None, kind: 'str' = 'semantic', epistemic: 'str' = 'user-stated', classification: 'str' = 'internal', pii: 'bool' = False, roles: 'list[str] | str | None' = None, attrs: 'dict | list[str] | str | None' = None, visibility: 'str' = 'tenant', source_uri: 'str' = '', source_ids: 'list[str] | str | None' = None, source_spans: 'list[dict] | None' = None, policy_scope: 'str' = '', confidence: 'float' = 0.8, salience: 'float' = 0.5) -> 'dict'` |
