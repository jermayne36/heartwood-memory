"""The Heartwood client — the cognitive verbs.

remember / recall / explain_recall / forget / approve, wired over the store,
hybrid retrieval, policy enforcer, provenance signer, crypto-shred keystore, and
audit log. Embedded, in-process, tenant-scoped.
"""
from __future__ import annotations

import base64
import os
import re
import time
from collections import Counter, OrderedDict
from datetime import datetime, timezone
from typing import Iterable

from .audit import AuditLog
from .egress import evaluate_request as evaluate_egress_request, generation_allowed
from .envelope import CLASSIFICATION_RANK, Epistemic, Memory, Policy, default_truth_status, hash_content
from .ergonomics import normalize_tenant, policy_from, principal_from, remember_kwargs
from .erasure import Cipher, KeyStore
from .faithfulness import evaluate_candidate as evaluate_faithfulness_candidate
from .index import make_index
from .key_lifecycle import (
    prove_crypto_erase_store,
    rewrap_tenant_keys,
    rotate_tenant_root,
)
from .policy import Principal, PolicyEnforcer
from .provenance import Signer, chain, verify_meta
from .retrieval import (
    bm25_scores_prepared,
    fuse_rerank,
    get_embedder,
    get_reranker,
    prepare_bm25_corpus,
    tokenize,
)
from .review import (
    DEFAULT_HIDDEN_REVIEW_STATES,
    ReviewState,
    normalize_review_state,
    validate_transition,
)
from .store import Store
from .typed_ranking import parse_dt, typed_adjusted_score, valid_at

def _positive_int_env(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


_TEXT_CACHE_LIMIT = _positive_int_env("HEARTWOOD_TEXT_CACHE_LIMIT", 8192)
_BM25_CORPUS_CACHE_LIMIT = _positive_int_env("HEARTWOOD_BM25_CORPUS_CACHE_LIMIT", 16)
_MIRROR_FAMILY_SOURCE = re.compile(
    r"^markdown://(?P<root>memory|team-memory|team_memory)/(?P<name>.+)$",
    re.IGNORECASE,
)


def _mirror_family(meta: dict) -> tuple[str, int] | None:
    """Return the structural mirror-family key and canonical-source rank."""
    for source_id in meta.get("source_ids") or ():
        match = _MIRROR_FAMILY_SOURCE.match(str(source_id))
        if match is None:
            continue
        root = match.group("root").lower()
        rank = 0 if root == "memory" else 1
        return f"mirror:{match.group('name').casefold()}", rank
    return None


def _gen_id(prefix="mem"):
    return f"{prefix}_" + base64.b32encode(os.urandom(10)).decode("ascii").lower().rstrip("=")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _review_badge(review_state: str | None) -> str | None:
    if review_state == ReviewState.PROPOSED.value:
        return "unreviewed"
    return None


class Heartwood:
    def __init__(self, path=":memory:", tenant="tenant:default", embedder=None, reranker=None,
                 index="numpy", key_custodian=None):
        self.path = str(path)
        self.tenant = str(tenant)
        self._index_spec = index
        self._key_custodian = key_custodian
        self.store = Store(path)
        self.embedder, self.embedder_name = embedder if embedder else get_embedder()
        self.reranker, self.reranker_name = reranker if reranker else get_reranker()
        self._embedder_pair = (self.embedder, self.embedder_name)
        self._reranker_pair = (self.reranker, self.reranker_name)
        self.enforcer = PolicyEnforcer()
        self.keys = KeyStore(self.store, custodian=key_custodian)
        self.signer = Signer(self.store, self.tenant, key_custodian=self.keys.custodian)
        self.cipher = Cipher()
        self.audit = AuditLog(self.store)
        self.index = make_index(index, self.store)
        self.index.rebuild(self.store)   # populate from any pre-existing rows
        self._explain: OrderedDict[str, dict] = OrderedDict()
        self._text_cache: OrderedDict[str, tuple[str, str]] = OrderedDict()
        self._token_cache: OrderedDict[str, tuple[str, tuple[str, ...]]] = OrderedDict()
        self._bm25_corpus_cache: OrderedDict[tuple[str, ...], dict] = OrderedDict()

    # -- public ergonomics ---------------------------------------------- #
    def with_tenant(self, tenant: str):
        """Open a tenant-scoped client over the same store and warm models."""
        return Heartwood(
            path=self.path,
            tenant=normalize_tenant(tenant, default=self.tenant),
            embedder=self._embedder_pair,
            reranker=self._reranker_pair,
            index=self._index_spec,
            key_custodian=self._key_custodian,
        )

    def close(self) -> None:
        self.store.close()

    def principal(self, id: str = "agent:recall", *, tenant: str | None = None,
                  roles=(), attrs=(), clearance: str = "internal") -> Principal:
        return principal_from(
            id=id,
            tenant=tenant or self.tenant,
            roles=roles,
            attrs=attrs,
            clearance=clearance,
            default_tenant=self.tenant,
        )

    def policy(self, policy: Policy | dict | None = None, **overrides) -> Policy:
        return policy_from(policy, **overrides)

    def remember_many(self, records: Iterable[dict], *, default_created_by="agent:bulk",
                      default_policy: Policy | dict | None = None,
                      default_tenant: str | None = None,
                      stop_on_error: bool = False) -> dict:
        """Bulk-write memory records, routing each row to its declared tenant.

        Records still pass through remember(), so provenance signatures,
        encryption keys, lineage, audit, and indexes are produced by the same
        product path as single writes.
        """
        imported = []
        errors = []
        tenants: Counter[str] = Counter()
        clients: dict[str, Heartwood] = {}
        base_tenant = normalize_tenant(default_tenant or self.tenant)
        try:
            for index, record in enumerate(records):
                try:
                    tenant, kwargs, policy = remember_kwargs(
                        record,
                        default_tenant=base_tenant,
                        default_created_by=default_created_by,
                        default_policy=default_policy,
                    )
                    client = self if tenant == self.tenant else clients.get(tenant)
                    if client is None:
                        client = self.with_tenant(tenant)
                        clients[tenant] = client
                    mem_id = client.remember(**kwargs)
                    tenants[tenant] += 1
                    imported.append(
                        {
                            "index": index,
                            "id": mem_id,
                            "tenant": tenant,
                            "subject": kwargs["subject"],
                            "kind": kwargs["kind"],
                            "epistemic": kwargs["epistemic"],
                            "classification": policy.classification,
                            "roles": list(policy.roles),
                            "created_by": kwargs["created_by"],
                            "source_ids": list(kwargs.get("source_ids") or ()),
                            "source_span_count": len(kwargs.get("source_spans") or ()),
                        }
                    )
                except Exception as exc:  # noqa: BLE001
                    error = {"index": index, "error": str(exc)}
                    if isinstance(record, dict):
                        error["tenant"] = normalize_tenant(
                            record.get("tenant") or record.get("tenant_id"),
                            default=base_tenant,
                        )
                        if record.get("subject") or record.get("subject_id"):
                            error["subject"] = str(record.get("subject") or record.get("subject_id"))
                    errors.append(error)
                    if stop_on_error:
                        raise
        finally:
            for tenant, client in clients.items():
                if tenant != self.tenant:
                    client.close()

        return {
            "ok": not errors,
            "imported_count": len(imported),
            "failed_count": len(errors),
            "tenant_counts": dict(sorted(tenants.items())),
            "provenance_coverage": {
                "with_source_ids": sum(1 for row in imported if row["source_ids"]),
                "with_source_spans": sum(1 for row in imported if row["source_span_count"]),
            },
            "records": imported,
            "errors": errors,
        }

    def recall_for_tenant(self, tenant: str, cue: str, *,
                          principal: Principal | dict | str | None = None,
                          principal_id: str = "agent:recall", roles=(), attrs=(),
                          clearance: str = "internal", filters=None, k=8, topc=50) -> dict:
        tenant_id = normalize_tenant(tenant, default=self.tenant)
        actor = principal_from(
            principal,
            id=principal_id if principal is None else None,
            tenant=tenant_id,
            roles=roles if principal is None else None,
            attrs=attrs if principal is None else None,
            clearance=clearance if principal is None else None,
            default_tenant=tenant_id,
        )
        client = self if tenant_id == self.tenant else self.with_tenant(tenant_id)
        try:
            return client.recall(cue, principal=actor, filters=filters, k=k, topc=topc)
        finally:
            if client is not self:
                client.close()

    # -- write ----------------------------------------------------------- #
    def remember(self, content, *, subject, created_by, kind="semantic",
                 epistemic="user-stated", confidence=0.8, salience=0.5,
                 source=None, policy=None, model_version=None, derived_from=(),
                 memory_id=None, truth_status=None, policy_scope="default",
                 valid_from=None, valid_until=None, entities=(), source_ids=(),
                 source_spans=(), subject_ids=(), created_at=None, review_state=None,
                 index_text=None):
        if epistemic == Epistemic.APPROVED_CANONICAL.value:
            raise PermissionError("approved-canonical requires approve(), not remember()")
        policy = policy or Policy()
        source = source or {}
        # High-water-mark: a derived memory inherits the policy of its most-
        # restrictive parent (classification + role gate + pii). A summary of a
        # restricted source is itself restricted — it must not be readable by a
        # principal who could not read the source.
        if derived_from:
            top_rank, pii = CLASSIFICATION_RANK[policy.classification], policy.pii
            groups = {tuple(sorted(set(g))) for g in policy.requirement_groups()}
            for p in derived_from:
                pm = self.store.get_meta(p)
                if not pm:
                    continue
                pii = pii or pm["pii"]
                top_rank = max(top_rank, CLASSIFICATION_RANK[pm["classification"]])
                if pm["roles"]:
                    groups.add(tuple(sorted(set(pm["roles"]))))
                for g in pm.get("role_groups", ()):
                    if g:
                        groups.add(tuple(sorted(set(g))))
            top_class = next(k for k, v in CLASSIFICATION_RANK.items() if v == top_rank)
            # all accumulated gates become conjunctive role_groups (AND across parents)
            policy = Policy(visibility=policy.visibility, classification=top_class, pii=pii,
                            roles=(), role_groups=tuple(sorted(groups)),
                            attrs=policy.attrs, retention=policy.retention)
        ch = hash_content(content)
        mem_id = memory_id or _gen_id()
        truth_status = truth_status or default_truth_status(epistemic)
        review_state = normalize_review_state(review_state)
        created_at_value = created_at if created_at is not None else time.time()
        subject_ids = tuple(subject_ids) if subject_ids else (subject,)
        if not source_ids and source.get("uri"):
            source_ids = (source["uri"],)
        sig = self.signer.sign(created_by, mem_id, ch, source.get("uri"), created_by, epistemic)
        sig_valid = self.signer.verify(sig, created_by, mem_id, ch, source.get("uri"),
                                       created_by, epistemic)

        mem = Memory(id=mem_id, tenant=self.tenant, kind=kind, epistemic=epistemic,
                     content=content, content_hash=ch, subject=subject, confidence=confidence,
                     salience=salience, created_by=created_by, created_at=created_at_value,
                     source=source, derived_from=tuple(derived_from), model_version=model_version,
                     policy=policy, producer_sig=sig, truth_status=truth_status,
                     policy_scope=policy_scope, valid_from=valid_from, valid_until=valid_until,
                     entities=tuple(entities), source_ids=tuple(source_ids),
                     source_spans=tuple(source_spans))
        mem.validate()

        text_to_index = index_text if index_text is not None else content
        emb = self.embedder([text_to_index])[0]
        key = self.keys.get_or_create(self.tenant, subject)
        content_enc = self.cipher.encrypt(content, key)
        index_text_enc = self.cipher.encrypt(index_text, key) if index_text is not None else None

        row = {
            "id": mem_id, "tenant": self.tenant, "kind": kind, "epistemic": epistemic,
            "subject": subject, "confidence": confidence, "salience": salience,
            "created_by": created_by, "created_at": mem.created_at, "content_hash": ch,
            "truth_status": truth_status, "policy_scope": policy_scope,
            "valid_from": valid_from, "valid_until": valid_until,
            "subject_ids": subject_ids, "entities": tuple(entities), "source_ids": tuple(source_ids),
            "source_spans": tuple(source_spans),
            "source": source,
            "model_version": model_version,
            "review_state": review_state,
            "index_text_enc": index_text_enc,
            "policy": {"visibility": policy.visibility, "classification": policy.classification,
                       "pii": policy.pii, "roles": policy.roles, "role_groups": policy.role_groups,
                       "attrs": policy.attrs, "retention": policy.retention},
            "producer_sig": sig, "sig_valid": sig_valid,
        }
        self.store.insert_memory(row, content_enc, emb)
        self._cache_text_pair(mem_id, content, text_to_index)
        self._tokens_for_index_text(mem_id, text_to_index)
        self._bm25_corpus_cache.clear()
        self.index.add(mem_id, self.tenant, emb)
        for p in derived_from:
            self.store.add_edge(mem_id, p)
        self.store.register_lineage(mem_id, "memory", subject, self.tenant)
        self.store.register_lineage(f"emb:{mem_id}", "embedding", subject, self.tenant)
        self.audit.append(self.tenant, created_by, "remember", mem_id,
                          {"kind": kind, "epistemic": epistemic,
                           "classification": policy.classification})
        return mem_id

    def evaluate_egress(self, request: dict, provider_registry: dict | None = None) -> dict:
        """Evaluate whether source spans may leave the deployment boundary.

        This is the product API behind the Phase 0 egress gates. Call it before
        source spans are sent to external model providers.
        """
        decision = evaluate_egress_request(request, provider_registry)
        self.audit.append(
            self.tenant,
            request.get("actor", "agent:egress"),
            "evaluate_egress",
            decision["request_id"],
            {
                "decision": decision["decision"],
                "provider_policy_id": decision.get("provider_policy_id"),
                "payload_span_count": decision.get("payload_span_count"),
            },
        )
        return decision

    def assess_faithfulness(self, candidate: dict, *,
                            support_threshold: float = 0.72,
                            review_threshold: float = 0.45) -> dict:
        """Evaluate generated-memory claims against cited source spans."""
        assessment = evaluate_faithfulness_candidate(
            candidate,
            support_threshold=support_threshold,
            review_threshold=review_threshold,
        )
        self.audit.append(
            self.tenant,
            candidate.get("actor", "agent:faithfulness"),
            "assess_faithfulness",
            assessment["candidate_id"],
            {
                "decision": assessment["decision"],
                "claim_count": assessment["claim_count"],
                "mismatches": len(assessment["expectation_mismatches"]),
            },
        )
        return assessment

    def remember_generated(self, content, *, subject, created_by, claims, source_spans,
                           source_ids=(), egress_request=None, provider_registry=None,
                           policy=None, model_version=None, memory_id=None,
                           kind="generated", confidence=0.8, salience=0.5,
                           support_threshold=0.72, review_threshold=0.45,
                           allow_human_review=False, store_unaccepted=False,
                           **kwargs) -> dict:
        """Store generated memory only after egress and faithfulness checks.

        By default, unsupported, contradicted, not-checkable, or human-review
        required outputs are not persisted. Set ``store_unaccepted=True`` to
        store a review-only generated memory with downweighted truth status.
        """
        egress = None
        if egress_request is not None:
            egress = self.evaluate_egress(egress_request, provider_registry)
            if not generation_allowed(egress, allow_human_review=allow_human_review):
                raise PermissionError(f"model egress blocked: {egress['decision']}")

        candidate_id = memory_id or _gen_id("candidate")
        candidate = {
            "candidate_id": candidate_id,
            "actor": created_by,
            "source_spans": list(source_spans),
            "claims": list(claims),
        }
        faithfulness = self.assess_faithfulness(
            candidate,
            support_threshold=support_threshold,
            review_threshold=review_threshold,
        )
        accepted = faithfulness["decision"] == "accepted"
        if not accepted and not store_unaccepted:
            raise PermissionError(f"generated memory failed faithfulness: {faithfulness['decision']}")

        truth_status = "generated_supported" if accepted else "generated_needs_review"
        kwargs.pop("review_state", None)
        derived_source_ids = tuple(source_ids) or tuple(
            span.get("source_id") or span.get("span_id")
            for span in source_spans
            if span.get("source_id") or span.get("span_id")
        )
        mem_id = self.remember(
            content,
            subject=subject,
            created_by=created_by,
            kind=kind,
            epistemic=Epistemic.MODEL_GENERATED.value,
            confidence=confidence,
            salience=salience,
            source={"kind": "generated-memory", "uri": f"heartwood://generated/{candidate_id}"},
            policy=policy,
            model_version=model_version,
            memory_id=memory_id,
            truth_status=truth_status,
            source_ids=derived_source_ids,
            source_spans=tuple(source_spans),
            review_state=ReviewState.PROPOSED.value,
            **kwargs,
        )
        return {
            "id": mem_id,
            "truth_status": truth_status,
            "faithfulness": faithfulness,
            "egress": egress,
        }

    # -- read ------------------------------------------------------------ #
    def recall(self, cue, *, principal: Principal, filters=None, k=8, topc=50):
        filters = filters or {}
        method = filters.get("method", "hybrid_untyped")
        typed_mode = bool(filters.get("typed")) or method == "typed_router"
        include_review_filter = filters.get("include_review_states", ())
        if isinstance(include_review_filter, str):
            include_review_filter = (include_review_filter,)
        include_review_states = {
            normalize_review_state(state)
            for state in include_review_filter
        }
        hide_review_filter = filters.get("hide_review_states", ())
        if isinstance(hide_review_filter, str):
            hide_review_filter = (hide_review_filter,)
        hide_review_states = {
            normalize_review_state(state)
            for state in hide_review_filter
        }
        if filters.get("hide_proposed"):
            hide_review_states.add(ReviewState.PROPOSED.value)
        hidden_review_states = set(DEFAULT_HIDDEN_REVIEW_STATES) | hide_review_states

        # Validity windows are enforced on every recall. `effective_at` only moves the
        # reference time; an absent or unparseable value falls back to now rather than
        # disabling the filter, so an expired record can never leak through by omission.
        # Resolved once so every candidate is judged against the same instant.
        include_expired = bool(filters.get("include_expired"))
        effective_at = filters.get("effective_at")
        if parse_dt(effective_at) is None:
            effective_at = _utc_now_iso()

        # 1. Policy + filters over lightweight metadata (no content/embeddings).
        def match(m):
            review_state = m.get("review_state")
            if (
                review_state in hidden_review_states
                and review_state not in include_review_states
            ):
                return False
            if "kinds" in filters and m["kind"] not in filters["kinds"]:
                return False
            memory_types = (
                filters.get("memory_types")
                or filters.get("allowed_memory_types")
            )
            if memory_types and m["kind"] not in memory_types:
                return False
            epistemics = (
                filters.get("epistemics")
                or filters.get("allowed_epistemics")
            )
            if epistemics and m["epistemic"] not in epistemics:
                return False
            policy_scopes = (
                filters.get("policy_scopes")
                or filters.get("allowed_policy_scopes")
            )
            if policy_scopes and m.get("policy_scope", "default") not in policy_scopes:
                return False
            if (
                m.get("policy_scope") == "contextual-aux"
                and not filters.get("include_contextual_aux", False)
            ):
                return False
            allowed_classifications = filters.get("allowed_classifications")
            if allowed_classifications and m["classification"] not in allowed_classifications:
                return False
            denied_subjects = set(
                filters.get("denied_subjects")
                or filters.get("denied_subject_ids")
                or ()
            )
            if denied_subjects and (
                m["subject"] in denied_subjects
                or bool(denied_subjects & set(m.get("subject_ids") or ()))
            ):
                return False
            if not include_expired and not valid_at(m, effective_at):
                return False
            if "subject" in filters and m["subject"] != filters["subject"]:
                return False
            return m["indexed"]

        metas = [m for m in self.store.candidate_meta(principal.tenant) if match(m)]
        visible, denied = self.enforcer.allowed_view(principal, metas)
        metas_by_id = {m["id"]: m for m in visible}
        visible_ids = {m["id"] for m in visible}
        lag = self.store.index_lag(principal.tenant)

        # 2. Dense candidates via the VectorIndex (ANN), restricted to the
        #    policy-allowed set so restricted records are never even scored.
        qv = self.embedder([cue])[0]
        dense = self.index.search(principal.tenant, qv, topc, allowed_ids=visible_ids)
        dense_map = {i: s for i, s in dense}

        # 3. Decrypt visible content for returned text/integrity and index text
        #    for lexical scoring + rerank. BM25 keeps full visible-corpus recall
        #    quality, but token lists and corpus stats are cached across queries.
        #    Legacy rows with no index_text_enc fall back to content byte-for-byte.
        content_map = {}
        index_text_map = {}
        for m in visible:
            text_pair = self._text_pair_for_meta(m)
            if text_pair is None:
                continue
            content_map[m["id"]], index_text_map[m["id"]] = text_pair

        lex_ids = list(index_text_map.keys())
        bm = self._bm25_scores(cue, lex_ids, index_text_map)
        lexical_map = {lex_ids[j]: float(bm[j]) for j in range(len(lex_ids))}

        cand_ids = list(dict.fromkeys(
            [i for i, _ in dense if i in content_map]
            + sorted(lexical_map, key=lambda i: -lexical_map[i])[:topc]))
        candidates = [{"id": i, "text": index_text_map[i]} for i in cand_ids]
        collapse_keys = {}
        precedence = {}
        for mem_id in cand_ids:
            family = _mirror_family(metas_by_id[mem_id])
            if family is not None:
                collapse_keys[mem_id], precedence[mem_id] = family
        if not collapse_keys:
            collapse_keys = None
            precedence = None

        if method == "lexical":
            if collapse_keys is None:
                lexical_order = sorted(
                    cand_ids,
                    key=lambda mem_id: -lexical_map.get(mem_id, 0.0),
                )
            else:
                lexical_order = sorted(
                    cand_ids,
                    key=lambda mem_id: (
                        -lexical_map.get(mem_id, 0.0),
                        precedence.get(mem_id, 2),
                        str(mem_id),
                    ),
                )
            ranked = []
            seen_collapse_keys = {}
            for mem_id in lexical_order:
                collapse_key = collapse_keys.get(mem_id) if collapse_keys is not None else None
                if collapse_key is not None and collapse_key in seen_collapse_keys:
                    kept_id, kept_signals = seen_collapse_keys[collapse_key]
                    collapse_signal = kept_signals.setdefault("duplicate_collapse", {
                        "reason": "mirror-family-source-key",
                        "collapse_key": collapse_key,
                        "kept_id": kept_id,
                        "collapsed_ids": [],
                    })
                    collapse_signal["collapsed_ids"].append(mem_id)
                    continue
                signals = {
                    "dense_sim": round(float(dense_map.get(mem_id, 0.0)), 4),
                    "bm25": round(float(lexical_map.get(mem_id, 0.0)), 4),
                    "rrf": 0.0,
                    "rerank_score": round(float(lexical_map.get(mem_id, 0.0)), 4),
                    "final_rank": len(ranked),
                }
                if collapse_key is not None:
                    seen_collapse_keys[collapse_key] = (mem_id, signals)
                ranked.append((mem_id, float(lexical_map[mem_id]), signals))
                if len(ranked) == k:
                    break
        else:
            rerank_k = min(topc, max(k, len(candidates))) if typed_mode else k
            ranked = fuse_rerank(
                self.reranker,
                cue,
                candidates,
                dense_map,
                lexical_map,
                k=rerank_k,
                topc=topc,
                collapse_keys=collapse_keys,
                precedence=precedence,
            )
            if typed_mode:
                adjusted = []
                for mem_id, score, signals in ranked:
                    typed_score, typed_signals = typed_adjusted_score(
                        score,
                        metas_by_id[mem_id],
                        intent=filters.get("intent", "default"),
                        query_entities=filters.get("entities", ()),
                        effective_at=filters.get("effective_at"),
                    )
                    adjusted.append((mem_id, typed_score, {**signals, **typed_signals}))
                ranked = [
                    (mem_id, score, {**signals, "final_rank": rank_pos})
                    for rank_pos, (mem_id, score, signals) in enumerate(
                        sorted(adjusted, key=lambda item: (-item[1], item[0]))[:k]
                    )
                ]
        recall_id = _gen_id("recall")
        results = []
        for mem_id, score, signals in ranked:
            meta = metas_by_id.get(mem_id)
            if meta is None:
                continue
            provenance = chain(self.store, mem_id, self.signer)
            content = content_map[mem_id]
            content_hash_match = (
                bool(meta.get("content_hash"))
                and hash_content(content) == meta["content_hash"]
            )
            content_signature_valid = verify_meta(self.signer, meta, content)
            provenance["signature_valid"] = (
                provenance["signature_valid"] and content_signature_valid
            )
            provenance["content_hash_match"] = content_hash_match
            results.append({
                "id": mem_id, "content": content, "score": round(score, 4),
                "epistemic": meta["epistemic"], "confidence": meta["confidence"],
                "kind": meta["kind"], "truth_status": meta["truth_status"],
                "classification": meta["classification"], "policy_scope": meta["policy_scope"],
                "review_state": meta["review_state"],
                "review_badge": _review_badge(meta["review_state"]),
                "subject_ids": meta["subject_ids"],
                "source_ids": meta["source_ids"],
                "signals": signals,
                "provenance": provenance,
            })
        self._explain[recall_id] = {
            "cue": cue, "candidates_considered": len(candidates),
            "visible": len(visible),
            "index_lag": lag,
            "ranking_signals": {r["id"]: r["signals"] for r in results},
            "duplicate_collapses": [
                r["signals"]["duplicate_collapse"]
                for r in results
                if "duplicate_collapse" in r["signals"]
            ],
            "review_states": {r["id"]: r["review_state"] for r in results},
            "hidden_review_states": sorted(state for state in hidden_review_states if state),
            "effective_at": effective_at,
            "validity_enforced": not include_expired,
            "result_ids": [r["id"] for r in results],
            "graph_paths": self._graph_paths([r["id"] for r in results]),
        }
        if len(self._explain) > 2000:
            self._explain.popitem(last=False)
        self.audit.append(self.tenant, principal.id, "recall", recall_id,
                          {"visible": len(visible), "denied": len(denied), "returned": len(results)})
        return {"recall_id": recall_id, "results": results, "index_lag": lag}

    def explain_recall(self, recall_id: str) -> dict:
        return self._explain.get(recall_id, {"error": "unknown recall_id"})

    def _graph_paths(self, result_ids: list[str]) -> list[dict]:
        if len(result_ids) < 2:
            return []
        placeholders = ",".join("?" for _ in result_ids)
        rows = self.store.conn.execute(
            "SELECT child, parent, kind FROM prov_edges "
            f"WHERE child IN ({placeholders}) AND parent IN ({placeholders}) "
            "ORDER BY kind, child, parent LIMIT 100",
            tuple(result_ids + result_ids),
        ).fetchall()
        return [
            {
                "from": row["child"],
                "to": row["parent"],
                "child": row["child"],
                "parent": row["parent"],
                "kind": row["kind"],
                "path": [row["child"], row["parent"]],
            }
            for row in rows
        ]

    def _cache_text_pair(self, mem_id: str, content: str, index_text: str) -> None:
        self._text_cache[mem_id] = (content, index_text)
        self._text_cache.move_to_end(mem_id)
        while len(self._text_cache) > _TEXT_CACHE_LIMIT:
            self._text_cache.popitem(last=False)

    def _tokens_for_index_text(self, mem_id: str, index_text: str) -> tuple[str, ...]:
        cached = self._token_cache.get(mem_id)
        if cached is not None and cached[0] == index_text:
            self._token_cache.move_to_end(mem_id)
            return cached[1]
        tokens = tuple(tokenize(index_text))
        self._token_cache[mem_id] = (index_text, tokens)
        self._token_cache.move_to_end(mem_id)
        while len(self._token_cache) > _TEXT_CACHE_LIMIT:
            self._token_cache.popitem(last=False)
        return tokens

    def _bm25_scores(self, cue: str, lex_ids: list[str], index_text_map: dict[str, str]):
        cache_key = tuple(lex_ids)
        corpus = self._bm25_corpus_cache.get(cache_key)
        if corpus is None:
            corpus_tokens = [
                self._tokens_for_index_text(mem_id, index_text_map[mem_id])
                for mem_id in lex_ids
            ]
            corpus = prepare_bm25_corpus(corpus_tokens)
            self._bm25_corpus_cache[cache_key] = corpus
            while len(self._bm25_corpus_cache) > _BM25_CORPUS_CACHE_LIMIT:
                self._bm25_corpus_cache.popitem(last=False)
        else:
            self._bm25_corpus_cache.move_to_end(cache_key)
        return bm25_scores_prepared(tokenize(cue), corpus)

    def _text_pair_for_meta(self, meta: dict) -> tuple[str, str] | None:
        mem_id = meta["id"]
        cached = self._text_cache.get(mem_id)
        if cached is not None:
            self._text_cache.move_to_end(mem_id)
            return cached
        key = self.keys.get(self.tenant, meta["subject"])
        if key is None:        # subject erased -> content unrecoverable
            return None
        content_enc, index_text_enc, _ = self.store.get_text_encs(mem_id)
        try:
            content = self.cipher.decrypt(content_enc, key)
        except Exception:
            return None
        index_text = content
        if index_text_enc is not None:
            try:
                index_text = self.cipher.decrypt(index_text_enc, key)
            except Exception:
                index_text = content
        self._cache_text_pair(mem_id, content, index_text)
        return content, index_text

    def warm_recall_cache(self, principal: Principal | None = None) -> int:
        actor = principal or self.principal(id="agent:recall-warm", tenant=self.tenant)
        metas = [
            m for m in self.store.candidate_meta(actor.tenant)
            if m["indexed"] and m.get("review_state") not in DEFAULT_HIDDEN_REVIEW_STATES
        ]
        visible, _ = self.enforcer.allowed_view(actor, metas)
        warmed = 0
        for meta in visible:
            if self._text_pair_for_meta(meta) is not None:
                warmed += 1
        return warmed

    # -- governance ------------------------------------------------------ #
    def approve(self, mem_id, principal: Principal):
        if "approver" not in principal.roles:
            raise PermissionError("approve requires the 'approver' role")
        meta = self.store.get_meta(mem_id)
        if not meta:
            raise KeyError(f"unknown memory id: {mem_id}")
        if meta.get("review_state") in {
            ReviewState.PROPOSED.value,
            ReviewState.REJECTED.value,
            ReviewState.DISPUTED.value,
            ReviewState.SUPERSEDED.value,
        }:
            raise PermissionError("approve requires review_state to be accepted or NULL")
        epistemic = Epistemic.APPROVED_CANONICAL.value
        sig = self.signer.sign(
            principal.id,
            mem_id,
            meta["content_hash"],
            meta.get("source", {}).get("uri"),
            principal.id,
            epistemic,
        )
        sig_valid = self.signer.verify(
            sig,
            principal.id,
            mem_id,
            meta["content_hash"],
            meta.get("source", {}).get("uri"),
            principal.id,
            epistemic,
        )
        self.store.update_epistemic(
            mem_id,
            epistemic,
            created_by=principal.id,
            producer_sig=sig,
            sig_valid=sig_valid,
            truth_status=default_truth_status(epistemic),
        )
        self.audit.append(self.tenant, principal.id, "approve", mem_id,
                          {"epistemic": epistemic})

    def transition_review(self, mem_id, to_state, principal: Principal, reason=""):
        meta = self.store.get_meta(mem_id)
        if not meta:
            raise KeyError(f"unknown memory id: {mem_id}")
        from_state = meta.get("review_state")
        to_state = validate_transition(from_state, to_state, principal)
        if not self.store.update_review_state(mem_id, to_state, expected_from=from_state):
            current = self.store.get_meta(mem_id)
            current_state = None if not current else current.get("review_state")
            raise RuntimeError(
                f"review_state changed during transition: expected {from_state}, got {current_state}"
            )
        self.audit.append(self.tenant, principal.id, "review_transition", mem_id,
                          {"from": from_state, "to": to_state, "reason": reason})
        return {"id": mem_id, "from": from_state, "to": to_state}

    def forget(self, subject, *, mode="hard", actor="system", reason="", legal_basis=""):
        purged = 0
        if mode == "hard":
            self.keys.shred(self.tenant, subject)        # crypto-shred (key destruction)
            seed = sorted(set(self.store.subject_ids(self.tenant, subject))
                          | set(self.store.lineage_memory_ids(self.tenant, subject)))
            cascade = self.store.descendants(seed)       # deletion-lineage: derived artifacts too
            to_purge = set(seed) | cascade
            for m in to_purge:
                self._text_cache.pop(m, None)
                self._token_cache.pop(m, None)
                self.store.delete_memory(m)
                self.index.remove(m)
            self._bm25_corpus_cache.clear()
            purged = len(to_purge)
            cascade_n = len(cascade)
        self.audit.append(self.tenant, actor, "forget", subject,
                          {"mode": mode, "purged": purged,
                           "cascade": cascade_n if mode == "hard" else 0,
                           "reason": reason, "legal_basis": legal_basis})
        return {"subject": subject, "mode": mode, "purged": purged,
                "cascade": cascade_n if mode == "hard" else 0,
                "key_shredded": mode == "hard", "reason": reason, "legal_basis": legal_basis}

    # -- trusted internals (same-process adapters: e.g. memory-tool backend) --- #
    def read_content(self, mem_id: str) -> str | None:
        """Decrypt a memory's content. Trusted, in-process callers only."""
        enc, subject = self.store.get_content_enc(mem_id)
        if enc is None:
            return None
        key = self.keys.get(self.tenant, subject)
        if key is None:
            return None
        try:
            return self.cipher.decrypt(enc, key)
        except Exception:
            return None

    def purge(self, mem_id: str, actor="system") -> bool:
        """Physically remove a single memory row + its derived artifacts (per-file
        delete). Crypto-shred of the shared subject key is reserved for forget()."""
        existed = self.store.get_meta(mem_id) is not None
        self._text_cache.pop(mem_id, None)
        self._token_cache.pop(mem_id, None)
        self._bm25_corpus_cache.clear()
        self.store.delete_memory(mem_id)
        self.index.remove(mem_id)
        self.audit.append(self.tenant, actor, "purge", mem_id, {})
        return existed

    def add_provenance_edge(self, child, parent, kind="derived_from"):
        self.store.add_edge(child, parent, kind)

    # -- ops ------------------------------------------------------------- #
    def flush_index(self):
        """No-op: the scaffold indexes synchronously at remember() time. The
        contract exists so production (async index build) can honor read-your-writes."""
        return {"index_lag": self.store.index_lag(self.tenant)}

    def verify_audit(self) -> bool:
        return self.audit.verify_chain()

    def info(self) -> dict:
        return {"tenant": self.tenant, "embedder": self.embedder_name,
                "reranker": self.reranker_name, "cipher": self.cipher.name,
                "index": self.index.name, "key_custody": self.keys.custodian.name}

    def key_custody_info(self, subject: str) -> dict:
        return self.keys.custody_info(self.tenant, subject)

    def rewrap_keys(self, new_custodian, *, old_custodian=None, max_updates: int | None = None):
        return rewrap_tenant_keys(
            self.store,
            tenant=self.tenant,
            old_custodian=old_custodian or self.keys.custodian,
            new_custodian=new_custodian,
            max_updates=max_updates,
        )

    def rotate_root(self, new_custodian, *, old_custodian=None, max_updates: int | None = None):
        return rotate_tenant_root(
            self.store,
            tenant=self.tenant,
            old_custodian=old_custodian or self.keys.custodian,
            new_custodian=new_custodian,
            max_updates=max_updates,
        )

    def crypto_erase_proof(self, *, root_present: bool):
        return prove_crypto_erase_store(
            self.store,
            tenant=self.tenant,
            root_present=root_present,
            db_path=self.path,
        )
