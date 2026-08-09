from __future__ import annotations

import copy
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .receipts import ReceiptSigner, chain_digest, create_receipt, sign_envelope, verify_chain, verify_envelope
from .schema import validate_turn
from .util import canonical_json, safe_relative_path, sha256_bytes, sha256_file, write_json

POLICY_SCHEMA = "openline.half-life.compaction-policy.v2"
APPROVAL_SCHEMA = "openline.half-life.operator-compaction-approval.v1"
CHECKPOINT_SCHEMA = "openline.half-life.checkpoint.v1"
COMPACT_STATE_SCHEMA = "openline.half-life.compact-state.v1"
EQUIVALENCE_SCHEMA = "openline.half-life.decision-equivalence.v1"
ARCHIVE_SCHEMA = "openline.half-life.archive-manifest.v1"
COMPACTION_RECEIPT_SCHEMA = "openline.half-life.compaction.v1"
HASH256 = re.compile(r"^[0-9a-f]{64}$")
PUBLIC_KEY_HEX = re.compile(r"^[0-9a-f]{64}$")
APPROVE = "APPROVE"

KEEP_RULES = {
    "currently_supported_claims",
    "live_constraints",
    "confirmed_outcomes",
    "unresolved_questions",
    "tombstones",
    "evidence_references",
    "source_and_policy_bindings",
    "rehydration_conditions",
}
MERGE_RULES = {
    "exact_duplicates",
    "superseded_versions",
    "settled_intermediate_steps",
}
REHYDRATION_CONDITIONS = [
    "constraint_changed",
    "evidence_revoked",
    "compaction_policy_changed",
    "trusted_key_changed",
    "unresolved_state_changed",
    "decision_mismatch",
]


class CompactionError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CompactionError(message)


def build_policy_body(
    *,
    trusted_source_signer_keys_b64: Sequence[str],
    trusted_operator_approval_public_keys: Sequence[str],
    active_receipt_bytes_budget: int,
    replay_latency_micros_budget: int,
    archive_destination: str = "cold_archive/receipts",
    policy_version: str = "0.4",
) -> dict[str, Any]:
    _require(isinstance(active_receipt_bytes_budget, int) and not isinstance(active_receipt_bytes_budget, bool) and active_receipt_bytes_budget > 0, "active receipt budget must be positive")
    _require(isinstance(replay_latency_micros_budget, int) and not isinstance(replay_latency_micros_budget, bool) and replay_latency_micros_budget > 0, "replay latency budget must be positive")
    _require(bool(trusted_source_signer_keys_b64), "source signer trust set cannot be empty")
    _require(bool(trusted_operator_approval_public_keys), "operator approval trust set cannot be empty")
    _require(all(PUBLIC_KEY_HEX.fullmatch(item) is not None for item in trusted_operator_approval_public_keys), "operator approval keys must be 32-byte lowercase hex")
    destination = PurePosixPath(archive_destination)
    _require(not destination.is_absolute() and destination.parts and ".." not in destination.parts, "archive destination must be safe and relative")
    return {
        "schema": POLICY_SCHEMA,
        "policy_version": policy_version,
        "operator_approval_required": True,
        "self_approval_forbidden": True,
        "automatic_compaction_authorized": False,
        "trigger": {
            "active_receipt_bytes_budget": active_receipt_bytes_budget,
            "replay_latency_micros_budget": replay_latency_micros_budget,
            "rule": "propose_when_either_budget_is_crossed",
        },
        "archive": {
            "destination": archive_destination,
            "hash_algorithm": "sha256",
            "signed_manifest_required": True,
            "source_receipt_deletion_authorized": False,
        },
        "trusted_source_signer_keys_b64": sorted(set(trusted_source_signer_keys_b64)),
        "trusted_operator_approval_public_keys": sorted(set(trusted_operator_approval_public_keys)),
        "keep": sorted(KEEP_RULES),
        "merge": sorted(MERGE_RULES),
        "decision_equivalence_required": True,
        "rehydration_conditions": list(REHYDRATION_CONDITIONS),
        "claim_boundary": "Compaction is allowed only under operator-owned policy, a separately signed approval, complete source-chain verification, recoverable archive custody, and independent decision replay.",
    }


def sign_policy(body: Mapping[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    return sign_envelope(body, private_key)


def verify_policy(policy: Mapping[str, Any], expected_public_keys: set[str] | None) -> dict[str, Any]:
    errors: list[str] = []
    if not expected_public_keys:
        errors.append("trusted_policy_key_required")
    elif not verify_envelope(policy, expected_public_keys):
        errors.append("policy_signature_or_signer_invalid")
    if policy.get("schema") != POLICY_SCHEMA:
        errors.append("unsupported_policy_schema")
    try:
        body = dict(policy)
        body.pop("payload_hash", None)
        body.pop("signature", None)
        required = {
            "schema", "policy_version", "operator_approval_required", "self_approval_forbidden",
            "automatic_compaction_authorized", "trigger", "archive", "trusted_source_signer_keys_b64",
            "trusted_operator_approval_public_keys", "keep", "merge", "decision_equivalence_required",
            "rehydration_conditions", "claim_boundary",
        }
        if set(body) != required:
            errors.append("policy_field_mismatch")
        if body.get("operator_approval_required") is not True:
            errors.append("operator_approval_required")
        if body.get("self_approval_forbidden") is not True:
            errors.append("self_approval_must_remain_forbidden")
        if body.get("automatic_compaction_authorized") is not False:
            errors.append("automatic_compaction_must_remain_forbidden")
        trigger = body.get("trigger", {})
        if set(trigger) != {"active_receipt_bytes_budget", "replay_latency_micros_budget", "rule"}:
            errors.append("trigger_field_mismatch")
        if trigger.get("rule") != "propose_when_either_budget_is_crossed":
            errors.append("trigger_rule_changed")
        for name in ("active_receipt_bytes_budget", "replay_latency_micros_budget"):
            value = trigger.get(name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                errors.append(f"invalid_{name}")
        archive = body.get("archive", {})
        if set(archive) != {"destination", "hash_algorithm", "signed_manifest_required", "source_receipt_deletion_authorized"}:
            errors.append("archive_field_mismatch")
        destination = PurePosixPath(str(archive.get("destination", "")))
        if destination.is_absolute() or not destination.parts or ".." in destination.parts:
            errors.append("archive_destination_invalid")
        if archive.get("hash_algorithm") != "sha256" or archive.get("signed_manifest_required") is not True or archive.get("source_receipt_deletion_authorized") is not False:
            errors.append("archive_policy_invalid")
        if set(body.get("keep", [])) != KEEP_RULES:
            errors.append("keep_rules_changed")
        if set(body.get("merge", [])) != MERGE_RULES:
            errors.append("merge_rules_changed")
        if body.get("decision_equivalence_required") is not True:
            errors.append("decision_equivalence_required")
        if body.get("rehydration_conditions") != REHYDRATION_CONDITIONS:
            errors.append("rehydration_conditions_changed")
        source_keys = body.get("trusted_source_signer_keys_b64")
        if not isinstance(source_keys, list) or not source_keys or not all(isinstance(item, str) and item for item in source_keys):
            errors.append("trusted_source_signer_required")
        approval_keys = body.get("trusted_operator_approval_public_keys")
        if not isinstance(approval_keys, list) or not approval_keys or not all(isinstance(item, str) and PUBLIC_KEY_HEX.fullmatch(item) is not None for item in approval_keys):
            errors.append("trusted_operator_approval_key_required")
        else:
            policy_signer = policy.get("signature", {}).get("public_key")
            if policy_signer in approval_keys:
                errors.append("policy_signer_cannot_approve_its_own_compaction")
            import base64
            for source_key in body.get("trusted_source_signer_keys_b64", []):
                try:
                    source_hex = base64.b64decode(source_key, validate=True).hex()
                except Exception:
                    errors.append("trusted_source_signer_invalid")
                    break
                if source_hex in approval_keys:
                    errors.append("source_signer_cannot_supply_operator_approval")
                    break
    except Exception:
        errors.append("invalid_policy_semantics")
    return {"valid": not errors, "errors": errors, "policy_hash": policy.get("payload_hash"), "public_key": policy.get("signature", {}).get("public_key")}


def build_checkpoint(turns: Sequence[Mapping[str, Any]], checkpoint_turn: int, policy_hash: str) -> dict[str, Any]:
    normalized = [validate_turn(item, expected_turn=index) for index, item in enumerate(turns, 1)]
    selected = [item for item in normalized if int(item["turn"]) <= checkpoint_turn]
    _require(selected and int(selected[-1]["turn"]) == checkpoint_turn, "checkpoint turn not present")
    body = {
        "schema": CHECKPOINT_SCHEMA,
        "run_id": selected[0]["run_id"],
        "checkpoint_turn": checkpoint_turn,
        "source_turn_count": len(selected),
        "source_turns_hash": sha256_bytes(canonical_json(selected)),
        "policy_hash": policy_hash,
        "objective": selected[-1]["objective"],
    }
    return {**body, "checkpoint_hash": sha256_bytes(canonical_json(body))}


def verify_checkpoint(checkpoint: Mapping[str, Any]) -> dict[str, Any]:
    body = dict(checkpoint)
    observed = body.pop("checkpoint_hash", None)
    errors = []
    if checkpoint.get("schema") != CHECKPOINT_SCHEMA:
        errors.append("unsupported_checkpoint_schema")
    if observed != sha256_bytes(canonical_json(body)):
        errors.append("checkpoint_hash_mismatch")
    return {"valid": not errors, "errors": errors, "checkpoint_hash": observed}


def build_operator_approval_body(*, checkpoint: Mapping[str, Any], source_chain: Sequence[Mapping[str, Any]], policy: Mapping[str, Any], disposition: str) -> dict[str, Any]:
    _require(disposition in {"APPROVE", "DENY"}, "invalid operator disposition")
    _require(bool(source_chain), "approval requires source chain")
    return {
        "schema": APPROVAL_SCHEMA,
        "run_id": checkpoint["run_id"],
        "checkpoint_hash": checkpoint["checkpoint_hash"],
        "source_chain_count": len(source_chain),
        "source_chain_tail_hash": source_chain[-1]["receipt_hash"],
        "source_chain_digest": chain_digest(source_chain),
        "compaction_policy_hash": policy["payload_hash"],
        "archive_destination": policy["archive"]["destination"],
        "disposition": disposition,
        "automatic_compaction_authorized": False,
    }


def sign_operator_approval(body: Mapping[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    return sign_envelope(body, key)


def verify_operator_approval(approval: Mapping[str, Any], *, checkpoint: Mapping[str, Any], source_chain: Sequence[Mapping[str, Any]], policy: Mapping[str, Any]) -> dict[str, Any]:
    trusted = set(policy.get("trusted_operator_approval_public_keys", []))
    errors: list[str] = []
    if not verify_envelope(approval, trusted):
        errors.append("approval_signature_or_signer_invalid")
    if approval.get("schema") != APPROVAL_SCHEMA:
        errors.append("approval_schema_mismatch")
    expected = build_operator_approval_body(checkpoint=checkpoint, source_chain=source_chain, policy=policy, disposition=str(approval.get("disposition"))) if approval.get("disposition") in {"APPROVE", "DENY"} else None
    if expected is None:
        errors.append("approval_disposition_invalid")
    else:
        body = dict(approval)
        body.pop("payload_hash", None)
        body.pop("signature", None)
        if body != expected:
            errors.append("approval_binding_mismatch")
    if approval.get("disposition") != APPROVE:
        errors.append("operator_did_not_approve")
    return {"valid": not errors, "errors": errors, "approval_hash": approval.get("payload_hash")}


def _evidence_index(turns: Sequence[Mapping[str, Any]], checkpoint_turn: int) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for turn in turns:
        if int(turn["turn"]) > checkpoint_turn:
            break
        for item in turn["evidence"]:
            index[item["id"]] = dict(item)
    return index


def _fresh(refs: Sequence[str], evidence: Mapping[str, Mapping[str, Any]], checkpoint_turn: int) -> bool:
    if not refs:
        return False
    for ref in refs:
        item = evidence.get(ref)
        if item is None:
            return False
        if checkpoint_turn > int(item["observed_turn"]) + int(item["expires_after_turns"]):
            return False
    return True


def _claim_tombstone(claim: Mapping[str, Any], status: str) -> dict[str, Any]:
    return {
        "identity": f"claim:{claim['slot']}:{sha256_bytes(canonical_json(claim['value']))}:{status}",
        "item_type": "claim",
        "item_id": claim["id"],
        "slot": claim["slot"],
        "value_hash": sha256_bytes(canonical_json(claim["value"])),
        "status": status,
    }


def derive_compact_state(turns: Sequence[Mapping[str, Any]], checkpoint_turn: int) -> dict[str, Any]:
    normalized = [validate_turn(item, expected_turn=index) for index, item in enumerate(turns, 1)]
    selected = [item for item in normalized if int(item["turn"]) <= checkpoint_turn]
    _require(selected and int(selected[-1]["turn"]) == checkpoint_turn, "checkpoint turn not present")
    evidence = _evidence_index(selected, checkpoint_turn)

    claims_by_slot: dict[str, list[Mapping[str, Any]]] = {}
    for turn in selected:
        for claim in turn["claims"]:
            claims_by_slot.setdefault(str(claim["slot"]), []).append(claim)

    supported: list[dict[str, Any]] = []
    tombstones: list[dict[str, Any]] = []
    contradictions: list[dict[str, Any]] = []
    used_refs: set[str] = set()
    for slot, claims in sorted(claims_by_slot.items()):
        eligible: list[Mapping[str, Any]] = []
        for claim in claims:
            if claim["support_status"] != "supported":
                tombstones.append(_claim_tombstone(claim, "rejected" if claim["support_status"] == "unsupported" else "unresolved"))
            elif not _fresh(claim["evidence_refs"], evidence, checkpoint_turn):
                tombstones.append(_claim_tombstone(claim, "stale"))
            else:
                eligible.append(claim)
        if not eligible:
            continue
        latest_turn = max(int(item["last_verified_turn"]) for item in eligible)
        latest = [item for item in eligible if int(item["last_verified_turn"]) == latest_turn]
        values = {canonical_json(item["value"]) for item in latest}
        if len(values) > 1:
            contradictions.append({
                "id": f"claim-slot:{slot}:{latest_turn}", "kind": "conflicting_supported_claims",
                "slot": slot, "claim_ids": sorted(str(item["id"]) for item in latest), "status": "unresolved",
            })
            for item in latest:
                tombstones.append(_claim_tombstone(item, "quarantined"))
            continue
        chosen = sorted(latest, key=lambda item: str(item["id"]))[-1]
        supported.append(copy.deepcopy(dict(chosen)))
        used_refs.update(chosen["evidence_refs"])
        for item in eligible:
            if item is not chosen:
                tombstones.append(_claim_tombstone(item, "superseded"))

    constraints_by_id: dict[str, Mapping[str, Any]] = {}
    for turn in selected:
        for item in turn["constraints"]:
            prior = constraints_by_id.get(item["id"])
            if prior is None or int(item["last_verified_turn"]) >= int(prior["last_verified_turn"]):
                constraints_by_id[item["id"]] = item
    constraints: list[dict[str, Any]] = []
    for item in sorted(constraints_by_id.values(), key=lambda value: str(value["id"])):
        if item["active"] and _fresh(item["evidence_refs"], evidence, checkpoint_turn):
            constraints.append(copy.deepcopy(dict(item)))
            used_refs.update(item["evidence_refs"])
        else:
            tombstones.append({"identity": f"constraint:{item['id']}", "item_type": "constraint", "item_id": item["id"], "status": "inactive" if not item["active"] else "stale"})

    latest_outcomes: dict[str, tuple[int, Mapping[str, Any]]] = {}
    for turn in selected:
        for item in turn["outcomes"]:
            latest_outcomes[item["id"]] = (int(turn["turn"]), item)
    outcomes: list[dict[str, Any]] = []
    for item_id, (_, item) in sorted(latest_outcomes.items()):
        if item["confirmed"] and _fresh(item["evidence_refs"], evidence, checkpoint_turn):
            outcomes.append(copy.deepcopy(dict(item)))
            used_refs.update(item["evidence_refs"])
        else:
            tombstones.append({"identity": f"outcome:{item_id}", "item_type": "outcome", "item_id": item_id, "status": "retracted" if not item["confirmed"] else "stale"})

    questions: list[str] = []
    for turn in selected:
        for question in turn["unresolved_questions"]:
            if question not in questions:
                questions.append(question)

    compact_tombstones: dict[str, dict[str, Any]] = {}
    for item in tombstones:
        current = compact_tombstones.get(item["identity"])
        if current is None:
            compact_tombstones[item["identity"]] = {**item, "source_count": 1}
        else:
            current["source_count"] += 1

    state = {
        "run_id": selected[0]["run_id"],
        "checkpoint_turn": checkpoint_turn,
        "objective": selected[-1]["objective"],
        "supported_claims": sorted(supported, key=lambda item: item["slot"]),
        "current_constraints": constraints,
        "confirmed_outcomes": outcomes,
        "unresolved_questions": questions,
        "contradictions": contradictions,
        "tombstones": sorted(compact_tombstones.values(), key=lambda item: item["identity"]),
        "evidence_references": sorted((copy.deepcopy(evidence[ref]) for ref in used_refs), key=lambda item: item["id"]),
        "merge_summary": {
            "source_turn_count": len(selected),
            "tombstone_group_count": len(compact_tombstones),
            "source_state_hash": sha256_bytes(canonical_json(selected)),
        },
    }
    return state


def compact_projection(compact_state: Mapping[str, Any]) -> dict[str, Any]:
    projection: dict[str, Any] = {}
    for item in compact_state.get("supported_claims", []):
        projection[f"claim:{item['slot']}"] = {"disposition": "COMMIT", "value_hash": sha256_bytes(canonical_json(item["value"])), "evidence_refs": sorted(item["evidence_refs"])}
    for item in compact_state.get("current_constraints", []):
        projection[f"constraint:{item['id']}"] = {"disposition": "COMMIT", "text_hash": sha256_bytes(canonical_json(item["text"])), "evidence_refs": sorted(item["evidence_refs"])}
    for item in compact_state.get("confirmed_outcomes", []):
        projection[f"outcome:{item['id']}"] = {"disposition": "COMMIT", "text_hash": sha256_bytes(canonical_json(item["text"])), "evidence_refs": sorted(item["evidence_refs"])}
    for question in compact_state.get("unresolved_questions", []):
        projection[f"question:{sha256_bytes(question.encode('utf-8'))}"] = {"disposition": "QUARANTINE"}
    for item in compact_state.get("contradictions", []):
        projection[f"contradiction:{item['id']}"] = {"disposition": "QUARANTINE"}
    for item in compact_state.get("tombstones", []):
        projection[f"tombstone:{item['identity']}"] = {"disposition": "DENY", "status": item["status"]}
    return dict(sorted(projection.items()))


def build_compact_state(state: Mapping[str, Any], *, policy: Mapping[str, Any], checkpoint: Mapping[str, Any], source_chain: Sequence[Mapping[str, Any]], source_anchor: Mapping[str, Any], archive_manifest_receipt_hash: str, operator_approval: Mapping[str, Any]) -> dict[str, Any]:
    body = {
        "schema": COMPACT_STATE_SCHEMA,
        **copy.deepcopy(dict(state)),
        "policy_binding": {"policy_hash": policy["payload_hash"], "policy_public_key": policy["signature"]["public_key"], "policy_version": policy["policy_version"]},
        "source_binding": {
            "checkpoint_hash": checkpoint["checkpoint_hash"],
            "source_chain_count": len(source_chain),
            "source_chain_tail_hash": source_chain[-1]["receipt_hash"],
            "source_chain_digest": chain_digest(source_chain),
            "source_anchor_hash": source_anchor["anchor_hash"],
            "source_signer_public_key": source_chain[0]["signer_public_key"],
        },
        "archive": {"destination": policy["archive"]["destination"], "manifest_receipt_hash": archive_manifest_receipt_hash, "source_receipts_permanently_deleted": False},
        "rehydration_conditions": list(policy["rehydration_conditions"]),
        "operator_approval_hash": operator_approval["payload_hash"],
        "operator_disposition": operator_approval["disposition"],
        "claim_boundary": "This compact state preserves decision-relevant state verified from the source history. It is not permission for a protected action and can be rebuilt from the retained archive.",
    }
    return {**body, "compact_state_hash": sha256_bytes(canonical_json(body))}


def decision_equivalence_report(full_projection: Mapping[str, Any], compact_state: Mapping[str, Any], *, source_chain_active_bytes: int) -> dict[str, Any]:
    compact = compact_projection(compact_state)
    keys = sorted(set(full_projection) | set(compact))
    mismatches = [{"decision_key": key, "full_history": full_projection.get(key), "compact_state": compact.get(key)} for key in keys if full_projection.get(key) != compact.get(key)]
    compact_bytes = len(canonical_json(compact_state))
    body = {
        "schema": EQUIVALENCE_SCHEMA,
        "passed": not mismatches,
        "mismatches": mismatches,
        "full_history_decision_hash": sha256_bytes(canonical_json(dict(sorted(full_projection.items())))),
        "compact_state_decision_hash": sha256_bytes(canonical_json(compact)),
        "decision_count": len(keys),
        "source_chain_active_bytes": source_chain_active_bytes,
        "compact_state_active_bytes": compact_bytes,
        "active_size_ratio_micros": 0 if source_chain_active_bytes == 0 else compact_bytes * 1_000_000 // source_chain_active_bytes,
    }
    return {**body, "report_hash": sha256_bytes(canonical_json(body))}


def archive_source_chain(output_dir: Path, source_chain: Sequence[Mapping[str, Any]], source_anchor: Mapping[str, Any], policy: Mapping[str, Any], signer: ReceiptSigner) -> dict[str, Any]:
    destination = str(policy["archive"]["destination"])
    archive_dir = safe_relative_path(output_dir, destination)
    archive_dir.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, Any]] = []
    for receipt in source_chain:
        name = f"{receipt['receipt_hash']}.json"
        path = archive_dir / name
        write_json(path, receipt)
        entries.append({"receipt_hash": receipt["receipt_hash"], "path": f"{destination}/{name}", "file_sha256": sha256_file(path)})
    payload = {
        "schema": ARCHIVE_SCHEMA,
        "run_id": source_chain[0]["payload"]["run_id"],
        "source_chain_count": len(source_chain),
        "source_chain_tail_hash": source_chain[-1]["receipt_hash"],
        "source_chain_digest": chain_digest(source_chain),
        "source_anchor_hash": source_anchor["anchor_hash"],
        "archive_destination": destination,
        "entries": entries,
        "source_receipts_permanently_deleted": False,
    }
    return create_receipt("archive_manifest", payload, signer, index=len(source_chain), parent_hash=source_chain[-1]["receipt_hash"])


def verify_archive(output_dir: Path, archive_receipt: Mapping[str, Any], source_chain: Sequence[Mapping[str, Any]], source_anchor: Mapping[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    payload = archive_receipt.get("payload", {})
    if payload.get("schema") != ARCHIVE_SCHEMA:
        errors.append("archive_schema_mismatch")
    if payload.get("source_chain_count") != len(source_chain) or payload.get("source_chain_tail_hash") != source_chain[-1].get("receipt_hash") or payload.get("source_chain_digest") != chain_digest(source_chain):
        errors.append("archive_source_binding_mismatch")
    if payload.get("source_anchor_hash") != source_anchor.get("anchor_hash"):
        errors.append("archive_anchor_binding_mismatch")
    entries = payload.get("entries", [])
    if not isinstance(entries, list) or len(entries) != len(source_chain):
        errors.append("archive_entry_count_mismatch")
        entries = []
    by_hash = {item.get("receipt_hash"): item for item in entries if isinstance(item, Mapping)}
    for receipt in source_chain:
        entry = by_hash.get(receipt["receipt_hash"])
        if not entry:
            errors.append(f"archive_missing:{receipt['receipt_hash']}")
            continue
        try:
            path = safe_relative_path(output_dir, str(entry["path"]))
            if not path.is_file() or sha256_file(path) != entry.get("file_sha256"):
                errors.append(f"archive_hash_mismatch:{receipt['receipt_hash']}")
                continue
            stored = json.loads(path.read_text(encoding="utf-8"))
            if stored != receipt:
                errors.append(f"archive_content_mismatch:{receipt['receipt_hash']}")
        except Exception:
            errors.append(f"archive_invalid_path:{receipt['receipt_hash']}")
    return {"valid": not errors, "errors": errors, "recovered_receipt_count": len(source_chain) - sum(1 for item in errors if item.startswith("archive_"))}


def candidate_hits_tombstone(compact_state: Mapping[str, Any], candidate: Mapping[str, Any]) -> bool:
    item_type = candidate.get("item_type")
    item_id = candidate.get("item_id")
    slot = candidate.get("slot")
    value_hash = sha256_bytes(canonical_json(candidate.get("value"))) if "value" in candidate else None
    for tombstone in compact_state.get("tombstones", []):
        if tombstone.get("item_type") != item_type:
            continue
        if item_type == "claim" and slot is not None and tombstone.get("slot") == slot and tombstone.get("value_hash") == value_hash:
            return True
        if item_id is not None and tombstone.get("item_id") == item_id:
            return True
    return False


def verify_pressure(source_chain: Sequence[Mapping[str, Any]], replay_latency_micros: int, policy: Mapping[str, Any]) -> dict[str, Any]:
    _require(isinstance(replay_latency_micros, int) and not isinstance(replay_latency_micros, bool) and replay_latency_micros >= 0, "replay latency must be non-negative")
    active_bytes = len(canonical_json(list(source_chain)))
    reasons = []
    if active_bytes > int(policy["trigger"]["active_receipt_bytes_budget"]):
        reasons.append("ACTIVE_RECEIPT_BUDGET_EXCEEDED")
    if replay_latency_micros > int(policy["trigger"]["replay_latency_micros_budget"]):
        reasons.append("REPLAY_LATENCY_BUDGET_EXCEEDED")
    return {"proposed": bool(reasons), "reason_codes": reasons, "active_receipt_bytes": active_bytes, "replay_latency_micros": replay_latency_micros}


def build_compaction_receipt(*, source_chain: Sequence[Mapping[str, Any]], archive_receipt: Mapping[str, Any], compact_state: Mapping[str, Any], equivalence: Mapping[str, Any], checkpoint: Mapping[str, Any], policy: Mapping[str, Any], approval: Mapping[str, Any], artifact_hashes: Mapping[str, str], input_hashes: Mapping[str, str], pressure: Mapping[str, Any], signer: ReceiptSigner) -> dict[str, Any]:
    _require(equivalence.get("passed") is True, "decision equivalence must pass")
    _require(approval.get("disposition") == APPROVE, "operator approval required")
    _require(set(input_hashes) == {"trajectory_sha256"}, "input manifest must bind trajectory")
    _require(all(HASH256.fullmatch(str(value)) for value in input_hashes.values()), "invalid input hash")
    payload = {
        "schema": COMPACTION_RECEIPT_SCHEMA,
        "run_id": checkpoint["run_id"],
        "checkpoint_turn": checkpoint["checkpoint_turn"],
        "checkpoint_hash": checkpoint["checkpoint_hash"],
        "source_chain_count": len(source_chain),
        "source_chain_tail_hash": source_chain[-1]["receipt_hash"],
        "source_chain_digest": chain_digest(source_chain),
        "archive_manifest_receipt_hash": archive_receipt["receipt_hash"],
        "compact_state_hash": compact_state["compact_state_hash"],
        "decision_equivalence_report_hash": equivalence["report_hash"],
        "policy_hash": policy["payload_hash"],
        "policy_public_key": policy["signature"]["public_key"],
        "operator_approval_hash": approval["payload_hash"],
        "operator_approval_public_key": approval["signature"]["public_key"],
        "artifact_hashes": dict(sorted(artifact_hashes.items())),
        "input_hashes": dict(sorted(input_hashes.items())),
        "pressure_reason_codes": list(pressure["reason_codes"]),
        "source_receipts_permanently_deleted": False,
        "operator_disposition": APPROVE,
    }
    return create_receipt("compaction", payload, signer, index=len(source_chain) + 1, parent_hash=archive_receipt["receipt_hash"])
