"""Public API helpers for tenant-safe Heartwood usage.

These helpers keep application code from recreating small, security-sensitive
parsing rules for tenants, principals, policies, and bulk memory records.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .envelope import Policy, hash_content
from .policy import Principal


POLICY_FIELDS = {
    "visibility",
    "classification",
    "pii",
    "roles",
    "attrs",
    "retention",
    "role_groups",
}


def normalize_tenant(value: Any, *, default: str = "tenant:default") -> str:
    if not value:
        return default
    text = str(value).strip()
    if not text:
        return default
    return text if ":" in text else f"tenant:{text}"


def tenant_slug(tenant: Any, *, default: str = "tenant:default") -> str:
    return normalize_tenant(tenant, default=default).split(":", 1)[-1]


def list_value(value: Any, *, default: list[Any] | None = None) -> list[Any]:
    if value is None or value == "":
        return list(default or [])
    if isinstance(value, (list, tuple, set)):
        return [item for item in value if str(item)]
    if isinstance(value, str) and "," in value:
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, str):
        stripped = value.strip()
        return [stripped] if stripped else list(default or [])
    return [value]


def bool_value(value: Any, *, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def attr_pairs(value: Any) -> tuple[tuple[str, str], ...]:
    if value is None or value == "":
        return ()
    if isinstance(value, Mapping):
        return tuple((str(key), str(val)) for key, val in sorted(value.items()))
    pairs: list[tuple[str, str]] = []
    items = value if isinstance(value, (list, tuple, set)) else list_value(value)
    for item in items:
        if isinstance(item, Mapping):
            pairs.extend((str(key), str(val)) for key, val in sorted(item.items()))
            continue
        if isinstance(item, (list, tuple)) and len(item) == 2:
            pairs.append((str(item[0]), str(item[1])))
            continue
        text = str(item)
        if "=" in text:
            key, val = text.split("=", 1)
        elif ":" in text:
            key, val = text.split(":", 1)
        else:
            raise ValueError(f"attribute must be key=value, got {item!r}")
        pairs.append((key.strip(), val.strip()))
    return tuple(pairs)


def role_groups_value(value: Any) -> tuple[tuple[str, ...], ...]:
    if value is None or value == "":
        return ()
    groups = value if isinstance(value, (list, tuple, set)) else (value,)
    out: list[tuple[str, ...]] = []
    for group in groups:
        roles = tuple(str(item) for item in list_value(group))
        if roles:
            out.append(roles)
    return tuple(out)


def policy_from(value: Policy | Mapping[str, Any] | None = None, **overrides: Any) -> Policy:
    fields = {
        "visibility": "tenant",
        "classification": "internal",
        "pii": False,
        "roles": (),
        "attrs": (),
        "retention": "decayable",
        "role_groups": (),
    }
    if isinstance(value, Policy):
        fields.update(
            {
                "visibility": value.visibility,
                "classification": value.classification,
                "pii": value.pii,
                "roles": value.roles,
                "attrs": value.attrs,
                "retention": value.retention,
                "role_groups": value.role_groups,
            }
        )
    elif isinstance(value, Mapping):
        for key in POLICY_FIELDS:
            if key in value:
                fields[key] = value[key]
    elif value is not None:
        raise TypeError(f"policy must be a Policy or mapping, got {type(value).__name__}")

    for key in POLICY_FIELDS:
        if key in overrides and overrides[key] is not None:
            fields[key] = overrides[key]

    policy = Policy(
        visibility=str(fields["visibility"]),
        classification=str(fields["classification"]),
        pii=bool_value(fields["pii"], default=False),
        roles=tuple(str(item) for item in list_value(fields["roles"])),
        attrs=attr_pairs(fields["attrs"]),
        retention=str(fields["retention"]),
        role_groups=role_groups_value(fields["role_groups"]),
    )
    policy.validate()
    return policy


def principal_from(
    value: Principal | Mapping[str, Any] | str | None = None,
    *,
    id: str | None = None,  # noqa: A002
    tenant: str | None = None,
    roles: Any = None,
    attrs: Any = None,
    clearance: str | None = None,
    default_tenant: str = "tenant:default",
) -> Principal:
    fields = {
        "id": "agent:recall",
        "tenant": normalize_tenant(default_tenant),
        "roles": (),
        "attrs": (),
        "clearance": "internal",
    }
    if isinstance(value, Principal):
        fields.update(
            {
                "id": value.id,
                "tenant": value.tenant,
                "roles": value.roles,
                "attrs": value.attrs,
                "clearance": value.clearance,
            }
        )
    elif isinstance(value, Mapping):
        fields.update(
            {
                "id": value.get("principal_id") or value.get("principal") or value.get("id") or fields["id"],
                "tenant": value.get("tenant") or fields["tenant"],
                "roles": value.get("roles", fields["roles"]),
                "attrs": value.get("attrs", fields["attrs"]),
                "clearance": value.get("clearance", fields["clearance"]),
            }
        )
    elif value is not None:
        fields["id"] = str(value)

    if id is not None:
        fields["id"] = id
    if tenant is not None:
        fields["tenant"] = tenant
    if roles is not None:
        fields["roles"] = roles
    if attrs is not None:
        fields["attrs"] = attrs
    if clearance is not None:
        fields["clearance"] = clearance

    return Principal(
        id=str(fields["id"]),
        tenant=normalize_tenant(fields["tenant"], default=normalize_tenant(default_tenant)),
        roles=tuple(str(item) for item in list_value(fields["roles"])),
        attrs=attr_pairs(fields["attrs"]),
        clearance=str(fields["clearance"]),
    )


def remember_kwargs(
    record: Mapping[str, Any],
    *,
    default_tenant: str,
    default_created_by: str,
    default_policy: Policy | Mapping[str, Any] | None = None,
    auto_source_span: bool = True,
) -> tuple[str, dict[str, Any], Policy]:
    if not isinstance(record, Mapping):
        raise TypeError(f"bulk memory record must be a mapping, got {type(record).__name__}")

    tenant = normalize_tenant(_first(record, "tenant", "tenant_id"), default=default_tenant)
    content = _first(record, "content", "text", "body")
    if content in (None, ""):
        raise ValueError("bulk memory record requires content")
    subject = _first(record, "subject", "subject_id")
    if not subject:
        subject_ids = list_value(_first(record, "subject_ids"), default=[])
        subject = subject_ids[0] if subject_ids else None
    if not subject:
        raise ValueError("bulk memory record requires subject or subject_id")

    policy = policy_from(default_policy)
    record_policy = record.get("policy")
    if record_policy is not None:
        policy = policy_from(policy, **_policy_overrides(record_policy))
    policy = policy_from(
        policy,
        visibility=_present(record, "visibility"),
        classification=_present(record, "classification"),
        pii=_present(record, "pii", "contains_pii"),
        roles=_present(record, "roles"),
        attrs=_present(record, "attrs"),
        retention=_present(record, "retention"),
        role_groups=_present(record, "role_groups"),
    )

    source = source_from(record)
    source_ids = tuple(str(item) for item in list_value(_first(record, "source_ids", "source_id"), default=[]))
    if not source_ids and source.get("uri"):
        source_ids = (str(source["uri"]),)
    source_spans = tuple(list_value(_first(record, "source_spans", "spans"), default=[]))
    if not source_spans and record.get("source_span"):
        source_spans = (record["source_span"],)
    if auto_source_span and not source_spans and source_ids:
        source_spans = (
            {
                "source_id": source_ids[0],
                "span_id": f"{source_ids[0]}#body",
                "text": str(content),
                "content_hash": hash_content(str(content)),
            },
        )

    kwargs = {
        "content": str(content),
        "subject": str(subject),
        "subject_ids": tuple(str(item) for item in list_value(_first(record, "subject_ids"), default=[])),
        "created_by": str(_first(record, "created_by", "producer", "actor") or default_created_by),
        "kind": str(_first(record, "kind", "memory_type") or "semantic"),
        "epistemic": str(_first(record, "epistemic", "epistemic_class") or "user-stated"),
        "confidence": float(_first(record, "confidence") if _first(record, "confidence") is not None else 0.8),
        "salience": float(_first(record, "salience") if _first(record, "salience") is not None else 0.5),
        "source": source,
        "policy": policy,
        "model_version": _none_or_str(_first(record, "model_version")),
        "derived_from": tuple(str(item) for item in list_value(_first(record, "derived_from"), default=[])),
        "memory_id": _none_or_str(_first(record, "memory_id", "id")),
        "truth_status": _none_or_str(_first(record, "truth_status")),
        "policy_scope": str(_first(record, "policy_scope") or tenant_slug(tenant)),
        "valid_from": _none_or_str(_first(record, "valid_from")),
        "valid_until": _none_or_str(_first(record, "valid_until")),
        "entities": tuple(str(item) for item in list_value(_first(record, "entities"), default=[])),
        "source_ids": source_ids,
        "source_spans": source_spans,
        "created_at": _first(record, "created_at"),
    }
    if not kwargs["subject_ids"]:
        kwargs["subject_ids"] = (kwargs["subject"],)
    return tenant, kwargs, policy


def source_from(record: Mapping[str, Any]) -> dict[str, Any]:
    source = record.get("source")
    if isinstance(source, Mapping):
        return dict(source)
    if isinstance(source, str) and source.strip():
        return {"kind": str(record.get("source_kind") or "bulk"), "uri": source.strip()}
    source_uri = _first(record, "source_uri", "source_id", "uri")
    if not source_uri:
        return {}
    out = {"kind": str(record.get("source_kind") or "bulk"), "uri": str(source_uri)}
    if record.get("source_path") or record.get("path"):
        out["path"] = str(record.get("source_path") or record.get("path"))
    return out


def _first(mapping: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def _present(mapping: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def _none_or_str(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def _policy_overrides(value: Policy | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(value, Policy):
        return {
            "visibility": value.visibility,
            "classification": value.classification,
            "pii": value.pii,
            "roles": value.roles,
            "attrs": value.attrs,
            "retention": value.retention,
            "role_groups": value.role_groups,
        }
    if isinstance(value, Mapping):
        return {key: value[key] for key in POLICY_FIELDS if key in value}
    raise TypeError(f"policy must be a Policy or mapping, got {type(value).__name__}")
