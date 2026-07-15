"""Conservative, additive-only memory consolidation proposals."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable

from .envelope import Epistemic
from .review import ReviewState

PINNED = "pinned"
LOCKED_EPISTEMIC = {"approved-canonical"}
LOCKED_TRUTH = {"human_approved"}
LOCKED_REVIEW = {"disputed"}
CONSOLIDATION_EXEMPT_SCOPES: set[str] = set()
MIN_CLUSTER = 3
STALE_AGE_DAYS = 90


@dataclass(frozen=True)
class Cluster:
    members: tuple[dict[str, Any], ...]
    reason: str
    key: str
    score: float | None = None

    @property
    def ids(self) -> tuple[str, ...]:
        return tuple(member["id"] for member in self.members)

    @property
    def tenant(self) -> str | None:
        return self.members[0].get("tenant") if self.members else None

    @property
    def subject(self) -> str | None:
        return self.members[0].get("subject") if self.members else None


@dataclass(frozen=True)
class ConsolidationProposal:
    id: str
    cluster_ids: tuple[str, ...]
    summary: str
    review_state: str | None
    truth_status: str
    faithfulness: dict[str, Any]
    egress: dict[str, Any] | None


Generator = Callable[..., str | dict[str, Any]]


def find_consolidation_clusters(client, *, subject=None, tenant=None,
                                sim_threshold: float, min_cluster: int = MIN_CLUSTER) -> list[Cluster]:
    """Detect exact and near-duplicate memory clusters without changing stored rows."""
    if sim_threshold is None:
        raise ValueError("sim_threshold is required and must be pre-registered before real runs")
    if min_cluster < 2:
        raise ValueError("min_cluster must be at least 2")

    target_tenant = tenant or client.tenant
    candidates = [
        meta
        for meta in client.store.candidate_meta(target_tenant)
        if subject is None or meta.get("subject") == subject
    ]

    clusters: list[Cluster] = []
    seen: set[frozenset[str]] = set()

    exact_groups: dict[tuple[str | None, str | None, str], list[dict[str, Any]]] = {}
    for meta in candidates:
        content_hash = meta.get("content_hash")
        if content_hash:
            key = (meta.get("tenant"), meta.get("subject"), content_hash)
            exact_groups.setdefault(key, []).append(meta)

    for (_tenant, _subject, content_hash), members in exact_groups.items():
        if len(members) < min_cluster:
            continue
        ordered = _ordered_members(members)
        ids = frozenset(member["id"] for member in ordered)
        seen.add(ids)
        clusters.append(Cluster(tuple(ordered), reason="content_hash", key=content_hash, score=1.0))

    candidate_ids = {meta["id"] for meta in candidates}
    meta_by_id = {meta["id"]: meta for meta in candidates}
    for meta in candidates:
        text = _read_member_content(client, meta)
        if text is None:
            continue
        query_vec = client.embedder([text])[0]
        hits = client.index.search(
            target_tenant,
            query_vec,
            n=len(candidate_ids),
            allowed_ids=candidate_ids,
        )
        near_ids = {
            mem_id
            for mem_id, score in hits
            if score >= sim_threshold and mem_id in meta_by_id
        }
        near_ids.add(meta["id"])
        if len(near_ids) < min_cluster:
            continue
        ids_key = frozenset(near_ids)
        if ids_key in seen:
            continue
        seen.add(ids_key)
        members = _ordered_members(meta_by_id[mem_id] for mem_id in near_ids)
        min_score = min(
            (score for mem_id, score in hits if mem_id in near_ids),
            default=None,
        )
        clusters.append(
            Cluster(tuple(members), reason="near_duplicate", key=meta["id"], score=min_score)
        )

    return sorted(clusters, key=lambda cluster: (cluster.subject or "", cluster.reason, cluster.ids))


def is_member_consolidatable(m: dict[str, Any], *, now: float) -> bool:
    if m.get("retention") == PINNED:
        return False
    if m.get("epistemic") in LOCKED_EPISTEMIC:
        return False
    if m.get("truth_status") in LOCKED_TRUTH:
        return False
    if (m.get("review_state") or "") in LOCKED_REVIEW:
        return False
    if (
        m.get("epistemic") == Epistemic.MODEL_GENERATED.value
        and m.get("review_state") != ReviewState.ACCEPTED.value
    ):
        return False
    if m.get("pii"):
        return False
    if m.get("policy_scope") in CONSOLIDATION_EXEMPT_SCOPES:
        return False
    age_days = max((now - _float_or(m.get("created_at"), now)) / 86400.0, 0.0)
    if age_days < STALE_AGE_DAYS:
        return False
    return True


def _same_policy_envelope(cluster: list[dict[str, Any]] | tuple[dict[str, Any], ...]) -> bool:
    def key(m):
        return (
            m["classification"],
            tuple(sorted(m.get("roles") or ())),
            tuple(sorted(tuple(group) for group in (m.get("role_groups") or ()))),
        )

    return len({key(m) for m in cluster}) == 1


def is_safety_redundant_set(cluster: list[dict[str, Any]] | tuple[dict[str, Any], ...]) -> bool:
    return any(
        m.get("retention") == PINNED
        or m.get("epistemic") in LOCKED_EPISTEMIC
        or m.get("truth_status") in LOCKED_TRUTH
        for m in cluster
    )


def is_safe_consolidation_cluster(cluster, *, now: float) -> bool:
    members = _cluster_members(cluster)
    if len(members) < MIN_CLUSTER:
        return False
    if len({m["tenant"] for m in members}) != 1:
        return False
    if len({m["subject"] for m in members}) != 1:
        return False
    if is_safety_redundant_set(members):
        return False
    if not _same_policy_envelope(members):
        return False
    return all(is_member_consolidatable(m, now=now) for m in members)


def propose_consolidation(client, cluster, *, generator: Generator,
                          principal) -> ConsolidationProposal:
    """Create a proposed summary memory through the generated-memory gate."""
    members = _cluster_members(cluster)
    now = time.time()
    if not is_safe_consolidation_cluster(members, now=now):
        raise ValueError("cluster is not safe for consolidation")

    source_spans = _source_spans(client, members)
    generated = generator(
        cluster=cluster,
        members=members,
        source_spans=source_spans,
        principal=principal,
    )
    summary, claims, model_version, egress_request = _normalize_generated(
        generated,
        source_spans,
    )
    cluster_ids = tuple(member["id"] for member in members)
    egress_request = egress_request or _default_egress_request(
        members,
        source_spans,
        principal,
    )

    stored = client.remember_generated(
        summary,
        subject=members[0]["subject"],
        created_by=_principal_id(principal),
        claims=claims,
        source_spans=source_spans,
        source_ids=cluster_ids,
        egress_request=egress_request,
        model_version=model_version,
        derived_from=cluster_ids,
    )
    meta = client.store.get_meta(stored["id"])
    return ConsolidationProposal(
        id=stored["id"],
        cluster_ids=cluster_ids,
        summary=summary,
        review_state=meta.get("review_state") if meta else None,
        truth_status=stored["truth_status"],
        faithfulness=stored["faithfulness"],
        egress=stored["egress"],
    )


def _cluster_members(cluster) -> tuple[dict[str, Any], ...]:
    if isinstance(cluster, Cluster):
        return cluster.members
    return tuple(cluster)


def _ordered_members(members) -> list[dict[str, Any]]:
    return sorted(members, key=lambda member: member["id"])


def _float_or(value, fallback: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return fallback


def _read_member_content(client, member: dict[str, Any]) -> str | None:
    content_enc, subject = client.store.get_content_enc(member["id"])
    if content_enc is None:
        return None
    key = client.keys.get(member["tenant"], subject)
    if key is None:
        return None
    try:
        return client.cipher.decrypt(content_enc, key)
    except Exception:
        return None


def _source_spans(client, members: tuple[dict[str, Any], ...]) -> list[dict[str, Any]]:
    spans = []
    for member in members:
        text = _read_member_content(client, member)
        if text is None:
            raise ValueError(f"source content unavailable for {member['id']}")
        spans.append(
            {
                "source_id": member["id"],
                "span_id": f"{member['id']}#body",
                "classification": member["classification"],
                "pii_labels": ["pii"] if member.get("pii") else [],
                "content_hash": member.get("content_hash"),
                "text": text,
            }
        )
    return spans


def _normalize_generated(generated, source_spans: list[dict[str, Any]]):
    if isinstance(generated, dict):
        summary = generated.get("summary") or generated.get("content") or generated.get("text")
        claims = generated.get("claims")
        model_version = generated.get("model_version")
        egress_request = generated.get("egress_request")
    else:
        summary = str(generated)
        claims = None
        model_version = None
        egress_request = None

    if not summary or not str(summary).strip():
        raise ValueError("generator returned an empty consolidation summary")
    summary = str(summary).strip()

    if claims is None:
        claims = [
            {
                "claim_id": "summary",
                "text": summary,
                "source_span_ids": [span["span_id"] for span in source_spans],
                "material": True,
            }
        ]
    normalized_claims = []
    all_span_ids = [span["span_id"] for span in source_spans]
    for index, claim in enumerate(claims):
        if isinstance(claim, str):
            normalized_claims.append(
                {
                    "claim_id": f"claim_{index + 1}",
                    "text": claim,
                    "source_span_ids": all_span_ids,
                    "material": True,
                }
            )
            continue
        item = dict(claim)
        item.setdefault("claim_id", f"claim_{index + 1}")
        item.setdefault("source_span_ids", all_span_ids)
        item.setdefault("material", True)
        normalized_claims.append(item)

    return summary, normalized_claims, model_version, egress_request


def _default_egress_request(members: tuple[dict[str, Any], ...],
                            source_spans: list[dict[str, Any]],
                            principal) -> dict[str, Any]:
    return {
        "request_id": f"consolidation:{members[0]['tenant']}:{members[0]['subject']}",
        "actor": _principal_id(principal),
        "model": {
            "runtime": "local",
            "provider": "local",
            "region": "local",
            "retention": "none",
            "training_opt_out": True,
        },
        "policy": {
            "allow_external_models": False,
            "allowed_providers": [],
            "allowed_regions": [],
            "require_zero_retention": False,
            "allow_redaction": False,
            "deny_pii_labels": [],
            "deny_classifications": [],
            "human_review_classifications": [],
        },
        "source_spans": source_spans,
    }


def _principal_id(principal) -> str:
    return str(getattr(principal, "id", principal))
