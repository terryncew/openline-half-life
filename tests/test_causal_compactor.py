from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openline_half_life.causal_compactor import (
    CompactionInputs,
    build_causal_capsule,
    build_compaction_policy_body,
    build_receiver_approval_body,
    candidate_hits_tombstone,
    decision_equivalence_report,
    derive_causal_state,
    propose_rehydration,
    receipt_gate_projection,
    rehydrate_archived_state,
    sign_receiver_approval,
    sign_compaction_policy,
    verify_compaction_inputs,
    verify_compaction_policy,
)
from openline_half_life.handoff import build_verified_residue_handoff
from openline_half_life.policy import load_policy
from openline_half_life.receipts import (
    SIGNED_OUTPUT_ARTIFACTS,
    ReceiptSigner,
    build_receipt_bundle,
    create_extension_receipt,
)
from openline_half_life.schema import load_trajectory
from openline_half_life.util import canonical_json, load_json, sha256_bytes, sha256_file
from openline_half_life.receipts import verify_output_directory


def _copy_output(source: Path, destination: Path) -> Path:
    shutil.copytree(source, destination, dirs_exist_ok=True)
    return destination


def _source_context(root: Path, output: Path):
    final_bundle = load_json(output / "half_life_receipt.json")
    source_chain = final_bundle["receipts"][:-2]
    source_anchor = load_json(output / "cold_archive/source_anchor.json")
    source_bundle = build_receipt_bundle(
        chain=source_chain,
        anchor=source_anchor,
        artifact_hashes={},
        policy_hash=final_bundle["policy_hash"],
        policy_public_key=final_bundle["policy_public_key"],
        retirement_turn=final_bundle["retirement_turn"],
    )
    succession = load_policy(
        root / "policy/succession_policy.json",
        {load_json(root / "policy/succession_policy.json")["signature"]["public_key"]},
    )
    turns = load_trajectory(root / "fixtures/gradual_drift.jsonl")
    checkpoint = build_verified_residue_handoff(turns, 61, succession["payload_hash"])
    compaction_policy = load_json(root / "policy/compaction_policy.json")
    return source_bundle, checkpoint, compaction_policy


def test_demo_emits_compaction_outputs_and_meets_size_gate(causal_demo_output: Path):
    for name in (
        "causal_capsule.json",
        "compaction_receipt.json",
        "archive_manifest.json",
        "decision_equivalence_report.json",
        "verified_residue_handoff.json",
        "share_card.html",
    ):
        assert (causal_demo_output / name).exists()
    report = load_json(causal_demo_output / "decision_equivalence_report.json")
    assert report["passed"] is True
    assert report["mismatches"] == []
    assert report["active_size_ratio_micros"] <= 200_000
    card = (causal_demo_output / "share_card.html").read_text()
    assert "Causal capsule preserved exact receiver decisions" in card


def test_forged_self_signed_compaction_policy_fails_receiver_pin(
    root: Path, trusted_compaction_policy_keys: set[str]
):
    policy = load_json(root / "policy/compaction_policy.json")
    body = dict(policy)
    body.pop("payload_hash")
    body.pop("signature")
    body["trigger"]["active_receipt_bytes_budget"] = 1
    forged = sign_compaction_policy(body, Ed25519PrivateKey.generate())
    result = verify_compaction_policy(forged, trusted_compaction_policy_keys)
    assert result["valid"] is False
    assert "compaction_policy_signer_not_trusted" in result["reason_codes"]


@pytest.mark.parametrize("artifact", ["causal_capsule.json", "compaction_receipt.json"])
def test_receipt_or_capsule_tampering_fails_verification(
    causal_demo_output: Path,
    tmp_path: Path,
    artifact: str,
    trusted_policy_keys: set[str],
    trusted_compaction_policy_keys: set[str],
):
    output = _copy_output(causal_demo_output, tmp_path / "tampered")
    path = output / artifact
    value = load_json(path)
    if artifact == "causal_capsule.json":
        value["objective"] = "attacker objective"
    else:
        value["payload"]["receiver_disposition"] = "DENY"
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    result = verify_output_directory(
        output,
        expected_policy_public_keys=trusted_policy_keys,
        expected_compaction_policy_public_keys=trusted_compaction_policy_keys,
    )
    assert result["valid"] is False


def test_required_artifact_hash_coverage_cannot_be_removed(
    causal_demo_output: Path,
    tmp_path: Path,
    trusted_policy_keys: set[str],
    trusted_compaction_policy_keys: set[str],
):
    output = _copy_output(causal_demo_output, tmp_path / "missing-artifact-coverage")
    bundle_path = output / "half_life_receipt.json"
    bundle = load_json(bundle_path)
    bundle["artifact_hashes"] = {}
    bundle_path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n")
    (output / "turn_assessments.json").write_text('{"changed":true}\n')
    result = verify_output_directory(
        output,
        expected_policy_public_keys=trusted_policy_keys,
        expected_compaction_policy_public_keys=trusted_compaction_policy_keys,
    )
    assert result["valid"] is False
    assert "artifact_manifest_coverage_mismatch" in result["errors"]


def test_outer_artifact_hash_rewrite_cannot_override_the_signed_manifest(
    causal_demo_output: Path,
    tmp_path: Path,
    trusted_policy_keys: set[str],
    trusted_compaction_policy_keys: set[str],
):
    output = _copy_output(causal_demo_output, tmp_path / "rewritten-artifact-hash")
    assessments = output / "turn_assessments.json"
    assessments.write_text('{"changed":true}\n')
    bundle_path = output / "half_life_receipt.json"
    bundle = load_json(bundle_path)
    bundle["artifact_hashes"]["turn_assessments.json"] = sha256_file(assessments)
    bundle_path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n")
    result = verify_output_directory(
        output,
        expected_policy_public_keys=trusted_policy_keys,
        expected_compaction_policy_public_keys=trusted_compaction_policy_keys,
    )
    assert result["valid"] is False
    assert any(
        error.endswith("signed_artifact_hash_mismatch:turn_assessments.json")
        or error.endswith("artifact_manifest_binding_mismatch:turn_assessments.json")
        for error in result["errors"]
    )


@pytest.mark.parametrize(
    ("section", "field", "expected_error"),
    [
        ("input_hashes", "exam_hash", "input_manifest_binding_mismatch:exam_hash"),
        (
            "compaction",
            "decision_equivalence_passed",
            "receipt_bundle_compaction_binding_mismatch:decision_equivalence_passed",
        ),
    ],
)
def test_outer_bundle_summary_cannot_override_signed_evidence(
    causal_demo_output: Path,
    tmp_path: Path,
    trusted_policy_keys: set[str],
    trusted_compaction_policy_keys: set[str],
    section: str,
    field: str,
    expected_error: str,
):
    output = _copy_output(causal_demo_output, tmp_path / f"rewritten-{section}")
    bundle_path = output / "half_life_receipt.json"
    bundle = load_json(bundle_path)
    bundle[section][field] = (
        "0" * 64 if section == "input_hashes" else False
    )
    bundle_path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n")
    result = verify_output_directory(
        output,
        expected_policy_public_keys=trusted_policy_keys,
        expected_compaction_policy_public_keys=trusted_compaction_policy_keys,
    )
    assert result["valid"] is False
    assert any(error.endswith(expected_error) for error in result["errors"])


def test_stale_evidence_replay_remains_denied(causal_demo_output: Path):
    capsule = load_json(causal_demo_output / "causal_capsule.json")
    stale = next(item for item in capsule["tombstones"] if item["status"] == "stale")
    candidate = {
        "item_type": stale["item_type"],
        "item_id": "replayed-stale",
        "slot": stale.get("slot"),
        "value_hash": stale.get("value_hash"),
    }
    assert candidate_hits_tombstone(capsule, candidate) is True


def test_rejected_claim_cannot_return_after_compression(causal_demo_output: Path):
    capsule = load_json(causal_demo_output / "causal_capsule.json")
    rejected = next(item for item in capsule["tombstones"] if item["status"] == "rejected")
    candidate = {
        "item_type": "claim",
        "item_id": rejected.get("source_ids", ["unknown"])[0],
        "slot": rejected["slot"],
        "value_hash": rejected["value_hash"],
    }
    assert candidate_hits_tombstone(capsule, candidate) is True
    projection = receipt_gate_projection(capsule)
    assert projection[f"tombstone:{rejected['identity']}"]["disposition"] == "DENY"


def test_correlation_is_not_promoted_to_causation(
    root: Path, causal_demo_output: Path
):
    source_bundle, checkpoint, policy = _source_context(root, causal_demo_output)
    turns = load_trajectory(root / "fixtures/gradual_drift.jsonl")
    observation = {
        "schema": "openline.endurance.receipt.v1",
        "index": 999,
        "kind": "observation",
        "parent_hash": "0" * 64,
        "signer_public_key": source_bundle["receipts"][0]["signer_public_key"],
        "payload": {
            "run_id": checkpoint["run_id"],
            "observation_id": "latency-and-errors-repeat",
            "relation_kind": "correlation",
            "evidence_refs": [turns[0]["evidence"][0]["id"]],
        },
        "receipt_hash": "1" * 64,
        "signature": "",
    }
    state = derive_causal_state(turns, [*source_bundle["receipts"], observation], 61, policy)
    assert state["admitted_mechanisms"] == []
    assert state["unresolved_associations"][0]["status"] == "observation_or_association_not_admitted_as_causal"


def test_unresolved_contradiction_cannot_be_silently_removed(
    root: Path, causal_demo_output: Path
):
    source_bundle, checkpoint, policy = _source_context(root, causal_demo_output)
    turns = copy.deepcopy(load_trajectory(root / "fixtures/healthy.jsonl")[:2])
    evidence = turns[1]["evidence"][0]
    turns[1]["claims"] = [
        {
            "id": "conflict-a",
            "slot": "deployment_region",
            "value": "us-west-2",
            "material": True,
            "support_status": "supported",
            "evidence_refs": [evidence["id"]],
            "last_verified_turn": 2,
        },
        {
            "id": "conflict-b",
            "slot": "deployment_region",
            "value": "eu-west-1",
            "material": True,
            "support_status": "supported",
            "evidence_refs": [evidence["id"]],
            "last_verified_turn": 2,
        },
    ]
    state = derive_causal_state(turns, [], 2, policy)
    assert state["contradictions"]
    capsule = copy.deepcopy(state)
    capsule["contradictions"] = []
    capsule["schema"] = "openline.half-life.causal-capsule.v1"
    report = decision_equivalence_report(
        receipt_gate_projection(state),
        capsule,
        source_chain_size_bytes=max(1, len(canonical_json(state)) * 10),
    )
    assert report["passed"] is False
    assert any(item["decision_key"].startswith("contradiction:") for item in report["mismatches"])


def test_policy_or_key_change_proposes_rehydration(causal_demo_output: Path):
    capsule = load_json(causal_demo_output / "causal_capsule.json")
    result = propose_rehydration(
        capsule,
        [],
        current_compaction_policy_hash="0" * 64,
        current_trusted_key_version="receiver-compaction-key-v3",
    )
    assert result["proposed"] is True
    assert result["policy_rewrite_authorized"] is False
    assert result["self_approval_authorized"] is False
    assert set(result["reason_codes"]) == {
        "COMPACTION_POLICY_CHANGED",
        "TRUSTED_KEY_CHANGED",
    }


def test_archive_receipt_omission_breaks_manifest_verification(
    causal_demo_output: Path,
    tmp_path: Path,
    trusted_policy_keys: set[str],
    trusted_compaction_policy_keys: set[str],
):
    output = _copy_output(causal_demo_output, tmp_path / "omitted")
    manifest = load_json(output / "archive_manifest.json")
    omitted = manifest["payload"]["entries"][0]
    (output / omitted["path"]).unlink()
    result = verify_output_directory(
        output,
        expected_policy_public_keys=trusted_policy_keys,
        expected_compaction_policy_public_keys=trusted_compaction_policy_keys,
    )
    assert result["valid"] is False
    assert any("archived_receipt_missing" in error for error in result["errors"])


def test_compaction_before_budget_trigger_fails_closed(
    root: Path, causal_demo_output: Path
):
    source_bundle, checkpoint, original = _source_context(root, causal_demo_output)
    receiver = Ed25519PrivateKey.generate()
    body = build_compaction_policy_body(
        trusted_source_receipt_signer_keys_b64=[source_bundle["anchor"]["signer_public_key"]],
        trusted_receiver_approval_public_keys=[receiver.public_key().public_bytes_raw().hex()],
        active_receipt_bytes_budget=10**9,
        replay_latency_micros_budget=10**9,
        trusted_key_version="test-key-v1",
    )
    policy = sign_compaction_policy(body, receiver)
    approval = sign_receiver_approval(
        build_receiver_approval_body(
            run_id=checkpoint["run_id"],
            checkpoint_hash=checkpoint["packet_hash"],
            source_chain=source_bundle["receipts"],
            compaction_policy=policy,
            disposition="APPROVE",
        ),
        receiver,
    )
    result = verify_compaction_inputs(
        CompactionInputs(
            source_bundle=source_bundle,
            compaction_policy=policy,
            trusted_policy_keys={receiver.public_key().public_bytes_raw().hex()},
            checkpoint=checkpoint,
            replay_latency_micros=1,
            receiver_approval=approval,
            output_dir=causal_demo_output,
        )
    )
    assert result["valid"] is False
    assert "budget_trigger_not_met" in result["errors"]


def test_successor_decision_difference_blocks_compaction(causal_demo_output: Path):
    capsule = load_json(causal_demo_output / "causal_capsule.json")
    full_state = copy.deepcopy(capsule)
    candidate = copy.deepcopy(capsule)
    candidate["supported_claims"][0]["value"] = "attacker-value"
    report = decision_equivalence_report(
        receipt_gate_projection(full_state),
        candidate,
        source_chain_size_bytes=100_000,
    )
    assert report["passed"] is False
    assert report["mismatches"]


def test_automatic_retirement_can_never_be_authorized(root: Path):
    source_signer = ReceiptSigner.from_hex_file(root / "fixtures/demo_signing_key.hex")
    receiver = Ed25519PrivateKey.generate()
    body = build_compaction_policy_body(
        trusted_source_receipt_signer_keys_b64=[source_signer.public_b64],
        trusted_receiver_approval_public_keys=[receiver.public_key().public_bytes_raw().hex()],
        active_receipt_bytes_budget=1,
        replay_latency_micros_budget=1,
    )
    body["automatic_retirement_authorized"] = True
    policy = sign_compaction_policy(body, receiver)
    result = verify_compaction_policy(
        policy, {receiver.public_key().public_bytes_raw().hex()}
    )
    assert result["valid"] is False
    assert "automatic_retirement_must_remain_forbidden" in result["reason_codes"]


def test_later_mechanism_outcomes_update_evidence_state_without_rewriting_policy(
    root: Path, causal_demo_output: Path,
):
    capsule = load_json(causal_demo_output / "causal_capsule.json")
    bundle = load_json(causal_demo_output / "half_life_receipt.json")
    signer = ReceiptSigner.from_hex_file(root / "fixtures/demo_signing_key.hex")
    confirmed = create_extension_receipt(
        "mechanism_outcome",
        {
            "run_id": capsule["run_id"],
            "mechanism_id": "m-1",
            "result": "confirmed",
        },
        signer,
        index=len(bundle["receipts"]),
        parent_hash=bundle["receipts"][-1]["receipt_hash"],
    )
    result = propose_rehydration(
        capsule,
        [confirmed],
        current_compaction_policy_hash=capsule["policy_binding"]["compaction_policy_hash"],
        current_trusted_key_version=capsule["policy_binding"]["trusted_key_version"],
        expected_parent_hash=bundle["receipts"][-1]["receipt_hash"],
        expected_start_index=len(bundle["receipts"]),
    )
    assert result["proposed"] is False
    assert result["evidence_state_updates"] == [{
        "mechanism_id": "m-1",
        "result": "confirmed",
        "outcome_receipt_hash": confirmed["receipt_hash"],
        "policy_changed": False,
    }]
    assert result["policy_rewrite_authorized"] is False
    assert result["self_approval_authorized"] is False


def test_compaction_receipt_has_per_decision_allowance_log(causal_demo_output: Path):
    receipt = load_json(causal_demo_output / "compaction_receipt.json")
    assert set(receipt["payload"]["artifact_hashes"]) == SIGNED_OUTPUT_ARTIFACTS
    log = receipt["payload"]["decision_log"]
    assert any(item["action"] == "keep" and item["item_type"] == "claim" for item in log)
    assert any(item["action"] == "merge" for item in log)
    assert any(item["action"] == "archive" for item in log)
    assert all(item.get("allowed_by") for item in log)
