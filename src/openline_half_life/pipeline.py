from __future__ import annotations

import copy
from pathlib import Path
from time import perf_counter_ns
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .compaction import (
    APPROVE,
    build_checkpoint,
    build_compact_state,
    build_compaction_receipt,
    build_operator_approval_body,
    decision_equivalence_report,
    derive_compact_state,
    sign_operator_approval,
    verify_archive,
    verify_checkpoint,
    verify_operator_approval,
    verify_policy,
    verify_pressure,
    archive_source_chain,
)
from .receipts import ReceiptSigner, chain_digest, create_anchor, create_chain, verify_anchor, verify_chain
from .reference_replay import reference_projection
from .schema import load_trajectory
from .util import canonical_json, load_json, sha256_bytes, sha256_file, write_json

ARTIFACTS_BOUND_BY_COMPACTION_RECEIPT = frozenset({
    "compaction_policy.json",
    "checkpoint.json",
    "operator_approval.json",
    "full_history_handoff.json",
    "compact_state.json",
    "archive_manifest.json",
    "decision_equivalence_report.json",
})
EXPECTED_OUTPUT_ARTIFACTS = ARTIFACTS_BOUND_BY_COMPACTION_RECEIPT | {"compaction_receipt.json", "receipt_bundle.json"}


def _load_public_keys(path: Path) -> set[str]:
    lines = path.read_text(encoding="ascii").splitlines()
    keys = {line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")}
    if not keys:
        raise ValueError("trusted public-key file contains no keys")
    return keys


def _private_key(path: Path) -> Ed25519PrivateKey:
    text = path.read_text(encoding="ascii").strip()
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        raise ValueError("private key must contain exactly 32 lowercase-hex bytes")
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(text))


def _full_history_handoff(turns: list[dict[str, Any]], checkpoint_turn: int, policy_hash: str) -> dict[str, Any]:
    selected = copy.deepcopy(turns[:checkpoint_turn])
    body = {
        "schema": "openline.half-life.full-history-handoff.v2",
        "run_id": selected[0]["run_id"],
        "checkpoint_turn": checkpoint_turn,
        "policy_hash": policy_hash,
        "turns": selected,
    }
    return {**body, "packet_hash": sha256_bytes(canonical_json(body))}


def _source_items(turns: list[dict[str, Any]], checkpoint_turn: int, policy: Mapping[str, Any], checkpoint: Mapping[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    items: list[tuple[str, dict[str, Any]]] = []
    for turn in turns[:checkpoint_turn]:
        items.append(("trajectory_turn", {"run_id": turn["run_id"], "turn": turn["turn"], "turn_hash": sha256_bytes(canonical_json(turn)), "turn_record": turn}))
    items.append(("compaction_policy_binding", {"run_id": turns[0]["run_id"], "policy_hash": policy["payload_hash"], "policy_public_key": policy["signature"]["public_key"]}))
    items.append(("checkpoint", {"run_id": turns[0]["run_id"], "checkpoint_turn": checkpoint_turn, "checkpoint_hash": checkpoint["checkpoint_hash"]}))
    return items


def run_pipeline(
    trajectory_path: Path,
    source_signing_key_path: Path,
    output_dir: Path,
    *,
    compaction_policy_path: Path,
    compaction_policy_public_key_path: Path,
    operator_approval_signing_key_path: Path,
    replay_latency_micros: int,
    checkpoint_turn: int | None = None,
    operator_disposition: str = APPROVE,
) -> dict[str, Any]:
    turns = load_trajectory(trajectory_path)
    checkpoint_turn = len(turns) if checkpoint_turn is None else checkpoint_turn
    if not isinstance(checkpoint_turn, int) or isinstance(checkpoint_turn, bool) or checkpoint_turn < 1 or checkpoint_turn > len(turns):
        raise ValueError("checkpoint_turn must identify an existing turn")
    policy = load_json(compaction_policy_path)
    trusted_policy_keys = _load_public_keys(compaction_policy_public_key_path)
    policy_check = verify_policy(policy, trusted_policy_keys)
    if not policy_check["valid"]:
        raise ValueError("compaction policy verification failed: " + ",".join(policy_check["errors"]))

    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(output_dir / "compaction_policy.json", policy)
    checkpoint = build_checkpoint(turns, checkpoint_turn, policy["payload_hash"])
    write_json(output_dir / "checkpoint.json", checkpoint)
    full = _full_history_handoff(turns, checkpoint_turn, policy["payload_hash"])
    write_json(output_dir / "full_history_handoff.json", full)

    source_signer = ReceiptSigner.from_hex_file(source_signing_key_path)
    source_chain = create_chain(_source_items(turns, checkpoint_turn, policy, checkpoint), source_signer)
    chain_check = verify_chain(source_chain, expected_signer_public_key=source_signer.public_b64)
    if not chain_check["valid"]:
        raise ValueError("generated source chain failed verification")
    if source_signer.public_b64 not in set(policy["trusted_source_signer_keys_b64"]):
        raise ValueError("source signer is not trusted by compaction policy")
    source_anchor = create_anchor(source_chain, source_signer)
    if not verify_anchor(source_anchor, source_chain)["valid"]:
        raise ValueError("generated source anchor failed verification")
    if not verify_checkpoint(checkpoint)["valid"]:
        raise ValueError("generated checkpoint failed verification")
    pressure = verify_pressure(source_chain, replay_latency_micros, policy)
    if not pressure["proposed"]:
        raise ValueError("compaction is not proposed because neither declared budget is crossed")

    approval = sign_operator_approval(
        build_operator_approval_body(checkpoint=checkpoint, source_chain=source_chain, policy=policy, disposition=operator_disposition),
        _private_key(operator_approval_signing_key_path),
    )
    approval_check = verify_operator_approval(approval, checkpoint=checkpoint, source_chain=source_chain, policy=policy)
    if not approval_check["valid"]:
        raise ValueError("operator approval verification failed: " + ",".join(approval_check["errors"]))
    write_json(output_dir / "operator_approval.json", approval)

    started_ns = perf_counter_ns()
    archive_receipt = archive_source_chain(output_dir, source_chain, source_anchor, policy, source_signer)
    write_json(output_dir / "archive_manifest.json", archive_receipt)
    archive_check = verify_archive(output_dir, archive_receipt, source_chain, source_anchor)
    if not archive_check["valid"]:
        raise ValueError("archive verification failed: " + ",".join(archive_check["errors"]))

    state = derive_compact_state(turns, checkpoint_turn)
    compact_state = build_compact_state(
        state,
        policy=policy,
        checkpoint=checkpoint,
        source_chain=source_chain,
        source_anchor=source_anchor,
        archive_manifest_receipt_hash=archive_receipt["receipt_hash"],
        operator_approval=approval,
    )
    independent_projection = reference_projection(turns, checkpoint_turn)
    equivalence = decision_equivalence_report(independent_projection, compact_state, source_chain_active_bytes=pressure["active_receipt_bytes"])
    if equivalence["passed"] is not True:
        raise ValueError("independent decision replay found a compaction mismatch")
    verification_runtime_micros = max(1, (perf_counter_ns() - started_ns + 999) // 1000)
    equivalence["observed_verification_runtime_micros"] = verification_runtime_micros
    body = dict(equivalence)
    body.pop("report_hash", None)
    equivalence["report_hash"] = sha256_bytes(canonical_json(body))
    write_json(output_dir / "compact_state.json", compact_state)
    write_json(output_dir / "decision_equivalence_report.json", equivalence)

    artifact_hashes = {name: sha256_file(output_dir / name) for name in sorted(ARTIFACTS_BOUND_BY_COMPACTION_RECEIPT)}
    input_hashes = {"trajectory_sha256": sha256_file(trajectory_path)}
    compaction_receipt = build_compaction_receipt(
        source_chain=source_chain,
        archive_receipt=archive_receipt,
        compact_state=compact_state,
        equivalence=equivalence,
        checkpoint=checkpoint,
        policy=policy,
        approval=approval,
        artifact_hashes=artifact_hashes,
        input_hashes=input_hashes,
        pressure=pressure,
        signer=source_signer,
    )
    write_json(output_dir / "compaction_receipt.json", compaction_receipt)
    bundle_body = {
        "schema": "openline.half-life.receipt-bundle.v6",
        "source_chain": source_chain,
        "source_anchor": source_anchor,
        "archive_manifest_receipt": archive_receipt,
        "compaction_receipt": compaction_receipt,
        "artifact_hashes": {**artifact_hashes, "compaction_receipt.json": sha256_file(output_dir / "compaction_receipt.json")},
        "input_hashes": input_hashes,
        "policy_hash": policy["payload_hash"],
        "operator_approval_hash": approval["payload_hash"],
    }
    bundle = {**bundle_body, "bundle_hash": sha256_bytes(canonical_json(bundle_body))}
    write_json(output_dir / "receipt_bundle.json", bundle)

    verification = verify_output_directory(output_dir, expected_policy_public_keys=trusted_policy_keys)
    if not verification["valid"]:
        raise ValueError("generated output failed verification: " + ",".join(verification["errors"]))
    return {
        "schema": "openline.half-life.run-result.v2",
        "version": "0.4.0rc2",
        "passed": True,
        "run_id": turns[0]["run_id"],
        "checkpoint_turn": checkpoint_turn,
        "output_dir": str(output_dir),
        "decision_equivalence_passed": True,
        "decision_mismatch_count": len(equivalence["mismatches"]),
        "active_size_ratio_micros": equivalence["active_size_ratio_micros"],
        "archive_receipt_count": len(source_chain),
        "source_chain_digest": chain_digest(source_chain),
        "bundle_hash": bundle["bundle_hash"],
        "verification_runtime_micros": verification_runtime_micros,
        "verification": verification,
    }


def verify_output_directory(output_dir: Path, *, expected_policy_public_keys: set[str]) -> dict[str, Any]:
    from .receipts import verify_receipt

    errors: list[str] = []
    for name in EXPECTED_OUTPUT_ARTIFACTS:
        if not (output_dir / name).is_file():
            errors.append(f"missing_artifact:{name}")
    if errors:
        return {"valid": False, "errors": errors}
    try:
        bundle = load_json(output_dir / "receipt_bundle.json")
        policy = load_json(output_dir / "compaction_policy.json")
        checkpoint = load_json(output_dir / "checkpoint.json")
        approval = load_json(output_dir / "operator_approval.json")
        compact_state = load_json(output_dir / "compact_state.json")
        equivalence = load_json(output_dir / "decision_equivalence_report.json")
        archive_receipt = load_json(output_dir / "archive_manifest.json")
        compaction_receipt = load_json(output_dir / "compaction_receipt.json")
        full = load_json(output_dir / "full_history_handoff.json")
    except Exception as exc:
        return {"valid": False, "errors": [f"artifact_parse_failed:{exc}"]}

    bundle_body = dict(bundle)
    observed_bundle_hash = bundle_body.pop("bundle_hash", None)
    if observed_bundle_hash != sha256_bytes(canonical_json(bundle_body)):
        errors.append("bundle_hash_mismatch")
    policy_check = verify_policy(policy, expected_policy_public_keys)
    errors.extend(f"policy:{item}" for item in policy_check["errors"])
    source_chain = bundle.get("source_chain", [])
    source_anchor = bundle.get("source_anchor", {})
    chain_check = verify_chain(source_chain)
    errors.extend(f"source_chain:{item}" for item in chain_check["errors"])
    anchor_check = verify_anchor(source_anchor, source_chain) if source_chain else {"valid": False, "errors": ["empty"]}
    errors.extend(f"source_anchor:{item}" for item in anchor_check["errors"])
    if source_chain:
        signer = source_chain[0]["signer_public_key"]
        archive_receipt_check = verify_receipt(archive_receipt, expected_index=len(source_chain), expected_parent_hash=source_chain[-1]["receipt_hash"], expected_signer_public_key=signer)
        errors.extend(f"archive_receipt:{item}" for item in archive_receipt_check["errors"])
        compaction_receipt_check = verify_receipt(compaction_receipt, expected_index=len(source_chain)+1, expected_parent_hash=archive_receipt.get("receipt_hash"), expected_signer_public_key=signer)
        errors.extend(f"compaction_receipt:{item}" for item in compaction_receipt_check["errors"])
        if signer not in set(policy.get("trusted_source_signer_keys_b64", [])):
            errors.append("source_signer_not_trusted")
    errors.extend(f"checkpoint:{item}" for item in verify_checkpoint(checkpoint)["errors"])
    errors.extend(f"approval:{item}" for item in verify_operator_approval(approval, checkpoint=checkpoint, source_chain=source_chain, policy=policy)["errors"] if source_chain)
    if checkpoint.get("policy_hash") != policy.get("payload_hash"):
        errors.append("checkpoint_policy_binding_mismatch")
    if full.get("packet_hash") != sha256_bytes(canonical_json({key: value for key, value in full.items() if key != "packet_hash"})):
        errors.append("full_history_packet_hash_mismatch")
    compact_body = dict(compact_state)
    observed_compact_hash = compact_body.pop("compact_state_hash", None)
    if observed_compact_hash != sha256_bytes(canonical_json(compact_body)):
        errors.append("compact_state_hash_mismatch")
    report_body = dict(equivalence)
    observed_report_hash = report_body.pop("report_hash", None)
    if observed_report_hash != sha256_bytes(canonical_json(report_body)):
        errors.append("equivalence_report_hash_mismatch")
    if equivalence.get("passed") is not True or equivalence.get("mismatches") != []:
        errors.append("decision_equivalence_failed")
    archive_check = verify_archive(output_dir, archive_receipt, source_chain, source_anchor) if source_chain else {"valid": False, "errors": ["empty"]}
    errors.extend(f"archive:{item}" for item in archive_check["errors"])

    signed_hashes = compaction_receipt.get("payload", {}).get("artifact_hashes", {})
    if set(signed_hashes) != ARTIFACTS_BOUND_BY_COMPACTION_RECEIPT:
        errors.append("signed_artifact_manifest_coverage_mismatch")
    for name in ARTIFACTS_BOUND_BY_COMPACTION_RECEIPT:
        if signed_hashes.get(name) != sha256_file(output_dir / name):
            errors.append(f"signed_artifact_hash_mismatch:{name}")
    bundle_hashes = bundle.get("artifact_hashes", {})
    if set(bundle_hashes) != ARTIFACTS_BOUND_BY_COMPACTION_RECEIPT | {"compaction_receipt.json"}:
        errors.append("bundle_artifact_manifest_coverage_mismatch")
    for name in bundle_hashes:
        if bundle_hashes.get(name) != sha256_file(output_dir / name):
            errors.append(f"bundle_artifact_hash_mismatch:{name}")
    payload = compaction_receipt.get("payload", {})
    expected_bindings = {
        "checkpoint_hash": checkpoint.get("checkpoint_hash"),
        "archive_manifest_receipt_hash": archive_receipt.get("receipt_hash"),
        "compact_state_hash": compact_state.get("compact_state_hash"),
        "decision_equivalence_report_hash": equivalence.get("report_hash"),
        "policy_hash": policy.get("payload_hash"),
        "policy_public_key": policy.get("signature", {}).get("public_key"),
        "operator_approval_hash": approval.get("payload_hash"),
        "operator_approval_public_key": approval.get("signature", {}).get("public_key"),
        "source_chain_digest": chain_digest(source_chain) if source_chain else None,
    }
    for field, expected in expected_bindings.items():
        if payload.get(field) != expected:
            errors.append(f"compaction_receipt_binding_mismatch:{field}")
    if compact_state.get("operator_approval_hash") != approval.get("payload_hash"):
        errors.append("compact_state_approval_binding_mismatch")
    if compact_state.get("archive", {}).get("manifest_receipt_hash") != archive_receipt.get("receipt_hash"):
        errors.append("compact_state_archive_binding_mismatch")
    return {
        "valid": not errors,
        "errors": errors,
        "source_chain_count": len(source_chain),
        "archive_recovered_count": archive_check.get("recovered_receipt_count", 0),
        "decision_equivalence_passed": equivalence.get("passed") is True,
        "active_size_ratio_micros": equivalence.get("active_size_ratio_micros"),
        "bundle_hash": observed_bundle_hash,
    }
