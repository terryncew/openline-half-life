"""Compiler-neutral candidate admission for OpenLine Half-Life.

This module defines the contract for a compact-state candidate produced by an
*arbitrary external producer* (another context compiler, an LLM, a
deterministic script, a human, anything) and the manifest that binds that
candidate to the exact source checkpoint it claims to compact.

Trust model: the candidate is UNTRUSTED INPUT. Half-Life never trusts a
producer's declarations. Admission is decided solely by comparing the
receiver-relevant decision projection derived from the candidate against the
independent projection reconstructed from the verified source history, under
the existing Half-Life semantics (see `compaction.decision_equivalence_report`
and `reference_replay.reference_projection`).

Half-Life may: parse, schema-check, canonicalize (in the existing
deterministic sense), and add receiver-owned bindings after admission.
Half-Life may NOT: silently restore omitted claims, restore tombstones, add
missing unresolved questions, substitute the internally derived state for a
bad candidate, or rewrite a failing candidate until replay passes.
A rejected candidate remains rejected.
"""
from __future__ import annotations

from typing import Any, Mapping

from .util import canonical_json, sha256_bytes

# Item collections whose per-item evidence_refs count as protected references
# the admitted compact state relies on. Matches the internal compactor's
# used_refs semantics (compaction.py): supported claims, live constraints,
# confirmed outcomes.
EVIDENCE_CITING_COLLECTIONS = ("supported_claims", "current_constraints", "confirmed_outcomes")

CANDIDATE_STATE_SCHEMA = "openline.half-life.candidate-state.v1"
CANDIDATE_MANIFEST_SCHEMA = "openline.half-life.candidate-manifest.v1"
ADMISSION_RECEIPT_SCHEMA = "openline.half-life.candidate-admission.v1"
ADMISSION_REJECTION_SCHEMA = "openline.half-life.candidate-admission-rejection.v1"

HASH256_HEX_LEN = 64

# Top-level fields an external producer must supply. These are exactly the
# fields the decision projection (`compaction.compact_projection`) reads, plus
# identity fields that bind the candidate to its source checkpoint.
CANDIDATE_REQUIRED_FIELDS = frozenset({
    "schema",
    "run_id",
    "checkpoint_turn",
    "supported_claims",
    "current_constraints",
    "confirmed_outcomes",
    "unresolved_questions",
    "contradictions",
    "tombstones",
    "evidence_references",
})
# Allowed but not required. Kept minimal on purpose: the candidate should
# contain only the compacted state material necessary for admission.
CANDIDATE_OPTIONAL_FIELDS = frozenset({"objective"})
# Trusted Half-Life metadata keys. An arbitrary producer must not mint these;
# Half-Life adds them after a successful admission. Their presence in a
# candidate is a hard rejection, not a silent overwrite.
CANDIDATE_FORBIDDEN_FIELDS = frozenset({
    "policy_binding",
    "source_binding",
    "archive",
    "rehydration_conditions",
    "operator_approval_hash",
    "operator_disposition",
    "claim_boundary",
    "compact_state_hash",
    "candidate_hash",
})

MANIFEST_REQUIRED_FIELDS = frozenset({
    "schema",
    "candidate_hash",
    "checkpoint_hash",
    "checkpoint_turn",
    "run_id",
    "source_turns_hash",
})
MANIFEST_OPTIONAL_FIELDS = frozenset({"producer_label"})


class AdmissionRejected(Exception):
    """Deterministic rejection of a candidate. Carries the frozen report."""

    def __init__(self, reason_codes: list[str], details: dict[str, Any], report: dict[str, Any]):
        super().__init__("; ".join(reason_codes))
        self.reason_codes = list(reason_codes)
        self.details = dict(details)
        self.report = dict(report)


def _is_hash256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == HASH256_HEX_LEN
        and all(ch in "0123456789abcdef" for ch in value)
    )


def candidate_state_hash(candidate: Mapping[str, Any]) -> str:
    """Receiver-computed canonical hash of the candidate bytes."""
    return sha256_bytes(canonical_json(dict(candidate)))


def _check_string_list(value: Any, *, allow_empty: bool = True) -> bool:
    return (
        isinstance(value, list)
        and (allow_empty or value)
        and all(isinstance(item, str) for item in value)
    )


def check_candidate(candidate: Any) -> dict[str, Any]:
    """Strict schema check of an untrusted candidate state.

    Rejects unknown top-level fields (frozen rule: extra producer material is
    rejected, never silently carried into trusted artifacts) and any
    trusted-metadata keys. Item-level fields are permissive: only the fields
    the decision projection reads are required, so hand-produced candidates
    are not forced into byte identity with Half-Life's own compactor output.
    """
    errors: list[str] = []
    if not isinstance(candidate, Mapping):
        return {"valid": False, "errors": ["candidate_not_an_object"]}
    fields = set(candidate)
    if candidate.get("schema") != CANDIDATE_STATE_SCHEMA:
        errors.append("candidate_schema_mismatch")
    forbidden = sorted(fields & CANDIDATE_FORBIDDEN_FIELDS)
    if forbidden:
        errors.append("candidate_forbidden_trusted_field:" + ",".join(forbidden))
    unknown = sorted(fields - CANDIDATE_REQUIRED_FIELDS - CANDIDATE_OPTIONAL_FIELDS - CANDIDATE_FORBIDDEN_FIELDS)
    if unknown:
        errors.append("candidate_schema_unknown_field:" + ",".join(unknown))
    missing = sorted(CANDIDATE_REQUIRED_FIELDS - fields)
    if missing:
        errors.append("candidate_missing_field:" + ",".join(missing))
    if not isinstance(candidate.get("run_id"), str) or not candidate.get("run_id"):
        errors.append("candidate_run_id_invalid")
    checkpoint_turn = candidate.get("checkpoint_turn")
    if not isinstance(checkpoint_turn, int) or isinstance(checkpoint_turn, bool) or checkpoint_turn < 1:
        errors.append("candidate_checkpoint_turn_invalid")

    def require_items(key: str, required: set[str]) -> None:
        items = candidate.get(key)
        if not isinstance(items, list):
            errors.append(f"candidate_{key}_not_a_list")
            return
        for index, item in enumerate(items):
            if not isinstance(item, Mapping):
                errors.append(f"candidate_{key}_item_not_object:{index}")
                continue
            absent = sorted(required - set(item))
            if absent:
                errors.append(f"candidate_{key}_item_missing_field:{index}:" + ",".join(absent))

    require_items("supported_claims", {"slot", "value", "evidence_refs"})
    require_items("current_constraints", {"id", "text", "evidence_refs"})
    require_items("confirmed_outcomes", {"id", "text", "evidence_refs"})
    require_items("contradictions", {"id"})
    require_items("tombstones", {"identity", "status"})
    if not _check_string_list(candidate.get("unresolved_questions")):
        errors.append("candidate_unresolved_questions_invalid")
    if not isinstance(candidate.get("evidence_references"), list) or any(
        not isinstance(item, Mapping) for item in candidate.get("evidence_references", [])
    ):
        errors.append("candidate_evidence_references_invalid")
    for key in ("supported_claims", "current_constraints", "confirmed_outcomes"):
        items = candidate.get(key)
        if isinstance(items, list):
            for index, item in enumerate(items):
                if isinstance(item, Mapping) and not _check_string_list(item.get("evidence_refs")):
                    errors.append(f"candidate_{key}_item_evidence_refs_invalid:{index}")
    objective = candidate.get("objective")
    if "objective" in fields and (not isinstance(objective, str) or not objective):
        errors.append("candidate_objective_invalid")
    return {"valid": not errors, "errors": errors}


def build_candidate_manifest(
    candidate: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
    *,
    producer_label: str | None = None,
) -> dict[str, Any]:
    """Build the manifest that binds a candidate to its claimed source.

    No signatures: the receiver re-verifies every binding against the actual
    source/checkpoint supplied at admission. Producer identity is informational.
    """
    body: dict[str, Any] = {
        "schema": CANDIDATE_MANIFEST_SCHEMA,
        "candidate_hash": candidate_state_hash(candidate),
        "checkpoint_hash": checkpoint["checkpoint_hash"],
        "checkpoint_turn": checkpoint["checkpoint_turn"],
        "run_id": checkpoint["run_id"],
        "source_turns_hash": checkpoint["source_turns_hash"],
    }
    if producer_label is not None:
        if not isinstance(producer_label, str) or not producer_label:
            raise ValueError("producer_label must be a non-empty string")
        body["producer_label"] = producer_label
    return body


def check_manifest(manifest: Any) -> dict[str, Any]:
    errors: list[str] = []
    if not isinstance(manifest, Mapping):
        return {"valid": False, "errors": ["manifest_not_an_object"]}
    fields = set(manifest)
    if manifest.get("schema") != CANDIDATE_MANIFEST_SCHEMA:
        errors.append("manifest_schema_mismatch")
    unknown = sorted(fields - MANIFEST_REQUIRED_FIELDS - MANIFEST_OPTIONAL_FIELDS)
    if unknown:
        errors.append("manifest_unknown_field:" + ",".join(unknown))
    missing = sorted(MANIFEST_REQUIRED_FIELDS - fields)
    if missing:
        errors.append("manifest_missing_field:" + ",".join(missing))
    for key in ("candidate_hash", "checkpoint_hash", "source_turns_hash"):
        if key in fields and not _is_hash256(manifest.get(key)):
            errors.append(f"manifest_{key}_invalid")
    checkpoint_turn = manifest.get("checkpoint_turn")
    if "checkpoint_turn" in fields and (
        not isinstance(checkpoint_turn, int) or isinstance(checkpoint_turn, bool) or checkpoint_turn < 1
    ):
        errors.append("manifest_checkpoint_turn_invalid")
    if "run_id" in fields and (not isinstance(manifest.get("run_id"), str) or not manifest.get("run_id")):
        errors.append("manifest_run_id_invalid")
    if "producer_label" in fields and (
        not isinstance(manifest.get("producer_label"), str) or not manifest.get("producer_label")
    ):
        errors.append("manifest_producer_label_invalid")
    return {"valid": not errors, "errors": errors}


def verify_candidate_manifest(
    manifest: Mapping[str, Any],
    candidate: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify the manifest against the actual candidate and checkpoint.

    Every binding is recomputed by the receiver. A candidate built for source A
    cannot be admitted against source B: checkpoint_hash, run_id, and
    source_turns_hash all bind the exact checkpoint derived from the supplied
    history.
    """
    errors: list[str] = []
    if manifest.get("candidate_hash") != candidate_state_hash(candidate):
        errors.append("candidate_hash_mismatch")
    if manifest.get("checkpoint_hash") != checkpoint.get("checkpoint_hash"):
        errors.append("checkpoint_binding_mismatch")
    if manifest.get("checkpoint_turn") != checkpoint.get("checkpoint_turn"):
        errors.append("checkpoint_turn_mismatch")
    if manifest.get("run_id") != checkpoint.get("run_id"):
        errors.append("source_run_id_mismatch")
    if manifest.get("source_turns_hash") != checkpoint.get("source_turns_hash"):
        errors.append("source_turns_binding_mismatch")
    return {"valid": not errors, "errors": errors}


def check_evidence_closure(
    candidate: Mapping[str, Any],
    source_evidence: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Independent evidence-closure check for candidate admission.

    Every evidence ID cited by the candidate's protected state
    (supported_claims, current_constraints, confirmed_outcomes) must resolve
    to an evidence object carried in the candidate's top-level
    `evidence_references` that is content-identical (canonical JSON) to the
    source-bound evidence from the verified source history.

    The comparison is against the source history, never against the
    producer's claims and never against Half-Life's own compactor output:
    ordering and serialization may differ; canonicalization applies.

    Returns {"valid": bool, "errors": [...], "mismatches": [...]}.
    A failing candidate is rejected, never repaired.
    """
    mismatches: list[dict[str, Any]] = []

    cited: set[str] = set()
    for key in EVIDENCE_CITING_COLLECTIONS:
        items = candidate.get(key)
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, Mapping):
                for ref in item.get("evidence_refs") or []:
                    if isinstance(ref, str):
                        cited.add(ref)

    carried: dict[str, list[str]] = {}
    evidence_references = candidate.get("evidence_references")
    if isinstance(evidence_references, list):
        for item in evidence_references:
            if isinstance(item, Mapping) and isinstance(item.get("id"), str):
                carried.setdefault(item["id"], []).append(canonical_json(item))

    for ref in sorted(cited):
        variants = carried.get(ref)
        if not variants:
            mismatches.append({"evidence_id": ref, "reason": "evidence_not_carried"})
            continue
        if len(set(variants)) > 1:
            mismatches.append({"evidence_id": ref, "reason": "evidence_ambiguous"})
            continue
        source = source_evidence.get(ref)
        if source is None:
            mismatches.append({"evidence_id": ref, "reason": "evidence_not_in_source"})
            continue
        if variants[0] != canonical_json(source):
            mismatches.append({"evidence_id": ref, "reason": "evidence_altered"})

    errors = [
        f"evidence_closure:{entry['reason']}:{entry['evidence_id']}"
        for entry in mismatches
    ]
    return {"valid": not mismatches, "errors": errors, "mismatches": mismatches}
