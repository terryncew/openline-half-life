from __future__ import annotations

import copy
from pathlib import Path
from time import perf_counter_ns
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .candidate_admission import (
    ADMISSION_RECEIPT_SCHEMA,
    ADMISSION_REJECTION_SCHEMA,
    AdmissionRejected,
    candidate_state_hash,
    check_candidate,
    check_evidence_closure,
    check_manifest,
    verify_candidate_manifest,
)
from .compaction import (
    APPROVE,
    build_checkpoint,
    build_compact_state,
    build_compaction_receipt,
    build_operator_approval_body,
    compact_projection,
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
from .receipts import ReceiptSigner, chain_digest, create_anchor, create_chain, create_receipt, verify_anchor, verify_chain
from .reference_replay import reference_projection, source_evidence_index
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


# ---------------------------------------------------------------------------
# Compiler-neutral candidate admission.
#
# The internal `run_pipeline` above derives the compact state itself. The
# admission path below accepts a compact-state candidate produced by an
# arbitrary external producer and admits it only when the existing independent
# replay says the receiver-required projection survived. The candidate is
# untrusted input; the admission decision, bindings, archive custody,
# rehydration conditions, and operator approval are all receiver-owned.
# ---------------------------------------------------------------------------

ADMISSION_ARTIFACTS_BOUND_BY_RECEIPT = frozenset({
    "compaction_policy.json",
    "checkpoint.json",
    "operator_approval.json",
    "full_history_handoff.json",
    "candidate.json",
    "candidate_manifest.json",
    "compact_state.json",
    "archive_manifest.json",
    "decision_equivalence_report.json",
})
EXPECTED_ADMISSION_OUTPUT_ARTIFACTS = ADMISSION_ARTIFACTS_BOUND_BY_RECEIPT | {"admission_receipt.json", "receipt_bundle.json"}
ADMISSION_BUNDLE_SCHEMA = "openline.half-life.admission-receipt-bundle.v1"


def _rejection_report(
    *,
    reason_codes: list[str],
    errors: list[str],
    run_id: str | None,
    checkpoint_turn: int | None,
    checkpoint_hash: str | None,
    candidate: Any,
    manifest: Any,
    mismatches: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    try:
        candidate_hash = candidate_state_hash(candidate) if isinstance(candidate, Mapping) else None
    except Exception:
        candidate_hash = None
    try:
        manifest_hash = sha256_bytes(canonical_json(dict(manifest))) if isinstance(manifest, Mapping) else None
    except Exception:
        manifest_hash = None
    return {
        "schema": ADMISSION_REJECTION_SCHEMA,
        "accepted": False,
        "reason_codes": list(reason_codes),
        "errors": list(errors),
        "run_id": run_id,
        "checkpoint_turn": checkpoint_turn,
        "checkpoint_hash": checkpoint_hash,
        "candidate_hash": candidate_hash,
        "manifest_hash": manifest_hash,
        "mismatches": mismatches or [],
    }


def _reject(
    reason_codes: list[str],
    errors: list[str],
    *,
    run_id: str | None = None,
    checkpoint_turn: int | None = None,
    checkpoint_hash: str | None = None,
    candidate: Any = None,
    manifest: Any = None,
    mismatches: list[dict[str, Any]] | None = None,
) -> AdmissionRejected:
    report = _rejection_report(
        reason_codes=reason_codes,
        errors=errors,
        run_id=run_id,
        checkpoint_turn=checkpoint_turn,
        checkpoint_hash=checkpoint_hash,
        candidate=candidate,
        manifest=manifest,
        mismatches=mismatches,
    )
    return AdmissionRejected(reason_codes, {"errors": errors}, report)


def admit_pipeline(
    trajectory_path: Path,
    candidate_path: Path,
    manifest_path: Path,
    source_signing_key_path: Path,
    output_dir: Path,
    *,
    compaction_policy_path: Path,
    compaction_policy_public_key_path: Path,
    operator_approval_signing_key_path: Path,
    replay_latency_micros: int,
    operator_disposition: str = APPROVE,
) -> dict[str, Any]:
    """Admit an externally produced compact-state candidate.

    Raises AdmissionRejected (deterministic, no admitted artifacts) when the
    candidate, its manifest, or the decision-equivalence check fails. Raises
    ValueError for apparatus problems (bad policy, untrusted source signer,
    invalid approval key, ...) exactly like run_pipeline.
    """
    try:
        candidate = load_json(candidate_path)
    except Exception as exc:
        raise _reject(["candidate_unreadable"], [f"candidate_unreadable:{exc}"], candidate=None, manifest=None)
    try:
        manifest = load_json(manifest_path)
    except Exception as exc:
        raise _reject(["manifest_unreadable"], [f"manifest_unreadable:{exc}"], candidate=candidate, manifest=None)

    manifest_check = check_manifest(manifest)
    if not manifest_check["valid"]:
        raise _reject(["manifest_invalid"], manifest_check["errors"], candidate=candidate, manifest=manifest)
    checkpoint_turn = manifest["checkpoint_turn"]

    turns = load_trajectory(trajectory_path)
    if not isinstance(checkpoint_turn, int) or checkpoint_turn < 1 or checkpoint_turn > len(turns):
        raise _reject(
            ["checkpoint_turn_invalid"],
            ["manifest checkpoint_turn does not identify an existing turn"],
            checkpoint_turn=checkpoint_turn if isinstance(checkpoint_turn, int) else None,
            candidate=candidate,
            manifest=manifest,
        )

    policy = load_json(compaction_policy_path)
    trusted_policy_keys = _load_public_keys(compaction_policy_public_key_path)
    policy_check = verify_policy(policy, trusted_policy_keys)
    if not policy_check["valid"]:
        raise ValueError("compaction policy verification failed: " + ",".join(policy_check["errors"]))

    checkpoint = build_checkpoint(turns, checkpoint_turn, policy["payload_hash"])
    run_id = checkpoint["run_id"]
    manifest_binding = verify_candidate_manifest(manifest, candidate, checkpoint)
    if not manifest_binding["valid"]:
        raise _reject(
            ["manifest_binding_mismatch"],
            manifest_binding["errors"],
            run_id=run_id,
            checkpoint_turn=checkpoint_turn,
            checkpoint_hash=checkpoint["checkpoint_hash"],
            candidate=candidate,
            manifest=manifest,
        )

    candidate_check = check_candidate(candidate)
    if not candidate_check["valid"]:
        raise _reject(
            ["candidate_schema_invalid"],
            candidate_check["errors"],
            run_id=run_id,
            checkpoint_turn=checkpoint_turn,
            checkpoint_hash=checkpoint["checkpoint_hash"],
            candidate=candidate,
            manifest=manifest,
        )

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

    # The admission decision: the receiver-relevant projection derived from the
    # untrusted candidate must match the independent projection reconstructed
    # from the verified source history. Nothing is repaired here; a failing
    # candidate is rejected with its mismatches.
    reference = reference_projection(turns, checkpoint_turn)
    equivalence = decision_equivalence_report(
        reference, candidate, source_chain_active_bytes=pressure["active_receipt_bytes"]
    )
    if equivalence["passed"] is not True:
        raise _reject(
            ["decision_equivalence_failed"],
            ["independent decision replay found a candidate mismatch"],
            run_id=run_id,
            checkpoint_turn=checkpoint_turn,
            checkpoint_hash=checkpoint["checkpoint_hash"],
            candidate=candidate,
            manifest=manifest,
            mismatches=equivalence["mismatches"],
        )

    # Evidence closure: every evidence ID cited by the candidate's protected
    # state must resolve to a carried evidence object identical to the
    # source-bound evidence. This is independent of the decision-equivalence
    # match above, which only compares cited IDs, never the evidence objects.
    closure = check_evidence_closure(candidate, source_evidence_index(turns, checkpoint_turn))
    if closure["valid"] is not True:
        raise _reject(
            ["evidence_closure_failed"],
            closure["errors"],
            run_id=run_id,
            checkpoint_turn=checkpoint_turn,
            checkpoint_hash=checkpoint["checkpoint_hash"],
            candidate=candidate,
            manifest=manifest,
            mismatches=closure["mismatches"],
        )

    # Admission accepted. From here on Half-Life adds only receiver-owned
    # trusted metadata; the candidate's own bytes are preserved as proposed.
    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(output_dir / "compaction_policy.json", policy)
    write_json(output_dir / "checkpoint.json", checkpoint)
    full = _full_history_handoff(turns, checkpoint_turn, policy["payload_hash"])
    write_json(output_dir / "full_history_handoff.json", full)
    write_json(output_dir / "candidate.json", candidate)
    write_json(output_dir / "candidate_manifest.json", manifest)

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

    compact_state = build_compact_state(
        candidate,
        policy=policy,
        checkpoint=checkpoint,
        source_chain=source_chain,
        source_anchor=source_anchor,
        archive_manifest_receipt_hash=archive_receipt["receipt_hash"],
        operator_approval=approval,
    )
    verification_runtime_micros = max(1, (perf_counter_ns() - started_ns + 999) // 1000)
    equivalence["observed_verification_runtime_micros"] = verification_runtime_micros
    body = dict(equivalence)
    body.pop("report_hash", None)
    equivalence["report_hash"] = sha256_bytes(canonical_json(body))
    write_json(output_dir / "compact_state.json", compact_state)
    write_json(output_dir / "decision_equivalence_report.json", equivalence)

    artifact_hashes = {name: sha256_file(output_dir / name) for name in sorted(ADMISSION_ARTIFACTS_BOUND_BY_RECEIPT)}
    input_hashes = {
        "trajectory_sha256": sha256_file(trajectory_path),
        "candidate_sha256": sha256_file(candidate_path),
        "candidate_manifest_sha256": sha256_file(manifest_path),
    }
    admission_payload = {
        "schema": ADMISSION_RECEIPT_SCHEMA,
        "run_id": run_id,
        "checkpoint_turn": checkpoint_turn,
        "checkpoint_hash": checkpoint["checkpoint_hash"],
        "source_chain_count": len(source_chain),
        "source_chain_tail_hash": source_chain[-1]["receipt_hash"],
        "source_chain_digest": chain_digest(source_chain),
        "archive_manifest_receipt_hash": archive_receipt["receipt_hash"],
        "candidate_hash": candidate_state_hash(candidate),
        "candidate_manifest_hash": sha256_file(output_dir / "candidate_manifest.json"),
        "producer_label": manifest.get("producer_label"),
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
        "operator_disposition": operator_disposition,
    }
    admission_receipt = create_receipt(
        "candidate_admission", admission_payload, source_signer,
        index=len(source_chain) + 1, parent_hash=archive_receipt["receipt_hash"],
    )
    write_json(output_dir / "admission_receipt.json", admission_receipt)
    bundle_body = {
        "schema": ADMISSION_BUNDLE_SCHEMA,
        "source_chain": source_chain,
        "source_anchor": source_anchor,
        "archive_manifest_receipt": archive_receipt,
        "admission_receipt": admission_receipt,
        "artifact_hashes": {**artifact_hashes, "admission_receipt.json": sha256_file(output_dir / "admission_receipt.json")},
        "input_hashes": input_hashes,
        "policy_hash": policy["payload_hash"],
        "operator_approval_hash": approval["payload_hash"],
    }
    bundle = {**bundle_body, "bundle_hash": sha256_bytes(canonical_json(bundle_body))}
    write_json(output_dir / "receipt_bundle.json", bundle)

    verification = verify_admission_output_directory(output_dir, expected_policy_public_keys=trusted_policy_keys)
    if not verification["valid"]:
        raise ValueError("generated admission output failed verification: " + ",".join(verification["errors"]))
    return {
        "schema": "openline.half-life.admission-result.v1",
        "version": "0.4.0rc2",
        "passed": True,
        "accepted": True,
        "run_id": run_id,
        "checkpoint_turn": checkpoint_turn,
        "output_dir": str(output_dir),
        "candidate_hash": candidate_state_hash(candidate),
        "decision_equivalence_passed": True,
        "decision_mismatch_count": 0,
        "active_size_ratio_micros": equivalence["active_size_ratio_micros"],
        "archive_receipt_count": len(source_chain),
        "source_chain_digest": chain_digest(source_chain),
        "bundle_hash": bundle["bundle_hash"],
        "verification_runtime_micros": verification_runtime_micros,
        "verification": verification,
    }


def verify_admission_output_directory(output_dir: Path, *, expected_policy_public_keys: set[str]) -> dict[str, Any]:
    """Independently verify an admitted external-candidate package.

    Detects: candidate file tamper, candidate-manifest tamper,
    checkpoint/source binding mismatch, compact-state tamper, archive tamper,
    policy tamper, operator-approval tamper, equivalence-report tamper, and
    receipt/bundle tamper. Does not depend on the external producer.
    """
    from .receipts import verify_receipt

    errors: list[str] = []
    for name in EXPECTED_ADMISSION_OUTPUT_ARTIFACTS:
        if not (output_dir / name).is_file():
            errors.append(f"missing_artifact:{name}")
    if errors:
        return {"valid": False, "errors": errors}
    try:
        bundle = load_json(output_dir / "receipt_bundle.json")
        policy = load_json(output_dir / "compaction_policy.json")
        checkpoint = load_json(output_dir / "checkpoint.json")
        approval = load_json(output_dir / "operator_approval.json")
        candidate = load_json(output_dir / "candidate.json")
        manifest = load_json(output_dir / "candidate_manifest.json")
        compact_state = load_json(output_dir / "compact_state.json")
        equivalence = load_json(output_dir / "decision_equivalence_report.json")
        archive_receipt = load_json(output_dir / "archive_manifest.json")
        admission_receipt = load_json(output_dir / "admission_receipt.json")
        full = load_json(output_dir / "full_history_handoff.json")
    except Exception as exc:
        return {"valid": False, "errors": [f"artifact_parse_failed:{exc}"]}

    bundle_body = dict(bundle)
    observed_bundle_hash = bundle_body.pop("bundle_hash", None)
    if bundle.get("schema") != ADMISSION_BUNDLE_SCHEMA:
        errors.append("bundle_schema_mismatch")
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
        admission_receipt_check = verify_receipt(admission_receipt, expected_index=len(source_chain) + 1, expected_parent_hash=archive_receipt.get("receipt_hash"), expected_signer_public_key=signer)
        errors.extend(f"admission_receipt:{item}" for item in admission_receipt_check["errors"])
        if signer not in set(policy.get("trusted_source_signer_keys_b64", [])):
            errors.append("source_signer_not_trusted")
    errors.extend(f"checkpoint:{item}" for item in verify_checkpoint(checkpoint)["errors"])
    errors.extend(f"approval:{item}" for item in verify_operator_approval(approval, checkpoint=checkpoint, source_chain=source_chain, policy=policy)["errors"] if source_chain)
    if checkpoint.get("policy_hash") != policy.get("payload_hash"):
        errors.append("checkpoint_policy_binding_mismatch")
    if full.get("packet_hash") != sha256_bytes(canonical_json({key: value for key, value in full.items() if key != "packet_hash"})):
        errors.append("full_history_packet_hash_mismatch")

    # Candidate and manifest integrity, rebound to the stored checkpoint.
    if check_candidate(candidate)["valid"] is not True:
        errors.append("candidate_schema_invalid")
    if check_manifest(manifest)["valid"] is not True:
        errors.append("manifest_schema_invalid")
    manifest_binding = verify_candidate_manifest(manifest, candidate, checkpoint)
    errors.extend(f"manifest_binding:{item}" for item in manifest_binding["errors"])
    if sha256_file(output_dir / "candidate.json") is not None and manifest.get("candidate_hash") != candidate_state_hash(candidate):
        errors.append("candidate_file_hash_mismatch")

    # Compact state integrity: hash, bindings, and re-derived projection.
    compact_body = dict(compact_state)
    observed_compact_hash = compact_body.pop("compact_state_hash", None)
    if observed_compact_hash != sha256_bytes(canonical_json(compact_body)):
        errors.append("compact_state_hash_mismatch")
    if compact_state.get("policy_binding", {}).get("policy_hash") != policy.get("payload_hash"):
        errors.append("compact_state_policy_binding_mismatch")
    if compact_state.get("source_binding", {}).get("checkpoint_hash") != checkpoint.get("checkpoint_hash"):
        errors.append("compact_state_checkpoint_binding_mismatch")
    if compact_state.get("archive", {}).get("manifest_receipt_hash") != archive_receipt.get("receipt_hash"):
        errors.append("compact_state_archive_binding_mismatch")
    if compact_state.get("operator_approval_hash") != approval.get("payload_hash"):
        errors.append("compact_state_approval_binding_mismatch")
    if compact_state.get("rehydration_conditions") != policy.get("rehydration_conditions"):
        errors.append("rehydration_conditions_weakened")

    # Equivalence report integrity: hash, passed flag, and independent
    # re-derivation of both decision hashes from stored artifacts.
    report_body = dict(equivalence)
    observed_report_hash = report_body.pop("report_hash", None)
    if observed_report_hash != sha256_bytes(canonical_json(report_body)):
        errors.append("equivalence_report_hash_mismatch")
    if equivalence.get("passed") is not True or equivalence.get("mismatches") != []:
        errors.append("decision_equivalence_failed")
    try:
        stored_turns = full.get("turns", [])
        recomputed_reference = reference_projection(stored_turns, int(checkpoint.get("checkpoint_turn", 0)))
        if sha256_bytes(canonical_json(dict(sorted(recomputed_reference.items())))) != equivalence.get("full_history_decision_hash"):
            errors.append("equivalence_reference_hash_mismatch")
    except Exception:
        errors.append("equivalence_reference_recompute_failed")
    recomputed_compact = compact_projection(compact_state)
    if sha256_bytes(canonical_json(recomputed_compact)) != equivalence.get("compact_state_decision_hash"):
        errors.append("equivalence_compact_hash_mismatch")
    # The admitted compact state must project exactly like the candidate that
    # was proposed: the receiver adds bindings, never protected content.
    if recomputed_compact != compact_projection(candidate):
        errors.append("admitted_state_projection_differs_from_candidate")

    archive_check = verify_archive(output_dir, archive_receipt, source_chain, source_anchor) if source_chain else {"valid": False, "errors": ["empty"]}
    errors.extend(f"archive:{item}" for item in archive_check["errors"])

    admission_payload = admission_receipt.get("payload", {})
    if admission_payload.get("schema") != ADMISSION_RECEIPT_SCHEMA:
        errors.append("admission_receipt_schema_mismatch")
    signed_hashes = admission_payload.get("artifact_hashes", {})
    if set(signed_hashes) != ADMISSION_ARTIFACTS_BOUND_BY_RECEIPT:
        errors.append("signed_artifact_manifest_coverage_mismatch")
    for name in ADMISSION_ARTIFACTS_BOUND_BY_RECEIPT:
        if signed_hashes.get(name) != sha256_file(output_dir / name):
            errors.append(f"signed_artifact_hash_mismatch:{name}")
    bundle_hashes = bundle.get("artifact_hashes", {})
    # Everything except the bundle itself, which cannot contain its own hash.
    if set(bundle_hashes) != ADMISSION_ARTIFACTS_BOUND_BY_RECEIPT | {"admission_receipt.json"}:
        errors.append("bundle_artifact_manifest_coverage_mismatch")
    for name in bundle_hashes:
        if bundle_hashes.get(name) != sha256_file(output_dir / name):
            errors.append(f"bundle_artifact_hash_mismatch:{name}")
    expected_bindings = {
        "checkpoint_hash": checkpoint.get("checkpoint_hash"),
        "archive_manifest_receipt_hash": archive_receipt.get("receipt_hash"),
        "candidate_hash": candidate_state_hash(candidate),
        "candidate_manifest_hash": sha256_file(output_dir / "candidate_manifest.json"),
        "compact_state_hash": compact_state.get("compact_state_hash"),
        "decision_equivalence_report_hash": equivalence.get("report_hash"),
        "policy_hash": policy.get("payload_hash"),
        "policy_public_key": policy.get("signature", {}).get("public_key"),
        "operator_approval_hash": approval.get("payload_hash"),
        "operator_approval_public_key": approval.get("signature", {}).get("public_key"),
        "source_chain_digest": chain_digest(source_chain) if source_chain else None,
    }
    for field, expected in expected_bindings.items():
        if admission_payload.get(field) != expected:
            errors.append(f"admission_receipt_binding_mismatch:{field}")
    return {
        "valid": not errors,
        "errors": errors,
        "source_chain_count": len(source_chain),
        "archive_recovered_count": archive_check.get("recovered_receipt_count", 0),
        "decision_equivalence_passed": equivalence.get("passed") is True,
        "active_size_ratio_micros": equivalence.get("active_size_ratio_micros"),
        "bundle_hash": observed_bundle_hash,
    }
