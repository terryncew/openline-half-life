from __future__ import annotations

import copy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import openline_half_life.causal_compactor as compactor
from openline_half_life.causal_compactor import (
    CompactionError,
    CompactionInputs,
    compact_verified_chain,
    propose_rehydration,
    receipt_gate_projection,
    rehydrate_archived_state,
    verify_archive_manifest,
    verify_receiver_approval,
)
from openline_half_life.handoff import build_verified_residue_handoff
from openline_half_life.pipeline import run_pipeline
from openline_half_life.policy import load_policy
from openline_half_life.receipts import ReceiptSigner, build_receipt_bundle
from openline_half_life.schema import load_trajectory, validate_turn
from openline_half_life.util import load_json


def _source_inputs(root: Path, output: Path, destination: Path) -> tuple[CompactionInputs, ReceiptSigner]:
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
    policy = load_json(root / "policy/compaction_policy.json")
    approval = load_json(output / "receiver_approval.json")
    return (
        CompactionInputs(
            source_bundle=source_bundle,
            compaction_policy=policy,
            trusted_policy_keys={policy["signature"]["public_key"]},
            checkpoint=checkpoint,
            replay_latency_micros=75_000,
            receiver_approval=approval,
            output_dir=destination,
        ),
        ReceiptSigner.from_hex_file(root / "fixtures/demo_signing_key.hex"),
    )


def test_verifier_rejects_an_internally_consistent_untrusted_source_signer(
    root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    attacker_key = tmp_path / "attacker.hex"
    attacker_key.write_text("77" * 32 + "\n", encoding="ascii")
    original = compactor.verify_compaction_inputs

    def generation_guard_bypass(inputs: CompactionInputs):
        result = original(inputs)
        result["errors"] = [
            item
            for item in result["errors"]
            if item != "source_receipt_signer_not_trusted_by_compaction_policy"
        ]
        result["valid"] = not result["errors"]
        return result

    monkeypatch.setattr(compactor, "verify_compaction_inputs", generation_guard_bypass)
    with pytest.raises(AssertionError, match="source_receipt_signer_not_trusted"):
        run_pipeline(
            root / "fixtures/gradual_drift.jsonl",
            root / "exams/heldout_exam.json",
            root / "policy/succession_policy.json",
            root / "policy/succession_policy_public_key.hex",
            attacker_key,
            tmp_path / "forged-output",
            compaction_policy_path=root / "policy/compaction_policy.json",
            compaction_policy_public_key_path=root / "policy/compaction_policy_public_key.hex",
            replay_latency_micros=75_000,
            receiver_approval_signing_key_path=root / "fixtures/demo_receiver_approval_key.hex",
            economics_assumptions_path=root / "economics/demo_cost_assumptions.json",
            receiver_disposition="APPROVE",
        )


def test_independent_replay_catches_a_compactor_that_drops_state(
    root: Path, causal_demo_output: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    inputs, signer = _source_inputs(root, causal_demo_output, tmp_path / "defective")
    original = compactor.derive_causal_state

    def defective_derivation(*args, **kwargs):
        state = original(*args, **kwargs)
        state["supported_claims"] = state["supported_claims"][1:]
        return state

    monkeypatch.setattr(compactor, "derive_causal_state", defective_derivation)
    with pytest.raises(CompactionError, match="decision equivalence failed"):
        compact_verified_chain(inputs, signer)


def test_compaction_rejects_a_signer_that_does_not_own_the_verified_source_chain(
    root: Path, causal_demo_output: Path, tmp_path: Path
):
    inputs, _ = _source_inputs(root, causal_demo_output, tmp_path / "wrong-signer")
    attacker = ReceiptSigner(Ed25519PrivateKey.generate())
    with pytest.raises(CompactionError, match="must match the verified source receipt signer"):
        compact_verified_chain(inputs, attacker)


def test_future_dated_verification_is_rejected(root: Path):
    turn = copy.deepcopy(load_trajectory(root / "fixtures/healthy.jsonl")[0])
    turn["claims"][0]["last_verified_turn"] = 999
    with pytest.raises(ValueError, match="no later than"):
        validate_turn(turn, expected_turn=1)


def test_unsigned_later_receipt_cannot_trigger_rehydration(causal_demo_output: Path):
    capsule = load_json(causal_demo_output / "causal_capsule.json")
    unsigned = {
        "kind": "evidence_revocation",
        "payload": {"run_id": capsule["run_id"]},
    }
    with pytest.raises(CompactionError, match="later receipt verification failed"):
        propose_rehydration(
            capsule,
            [unsigned],
            current_compaction_policy_hash=capsule["policy_binding"]["compaction_policy_hash"],
            current_trusted_key_version=capsule["policy_binding"]["trusted_key_version"],
            expected_parent_hash="0" * 64,
            expected_start_index=0,
        )


def test_archive_manifest_cannot_escape_output_directory(
    causal_demo_output: Path,
):
    manifest = copy.deepcopy(load_json(causal_demo_output / "archive_manifest.json"))
    bundle = load_json(causal_demo_output / "half_life_receipt.json")
    source_chain = bundle["receipts"][:-2]
    source_anchor = load_json(causal_demo_output / "cold_archive/source_anchor.json")
    manifest["payload"]["entries"][0]["path"] = "../../outside.json"
    errors = verify_archive_manifest(
        causal_demo_output,
        manifest,
        source_chain,
        source_anchor,
        expected_archive_destination="cold_archive/receipts",
    )
    assert any("path_mismatch" in item for item in errors)


def test_receiver_approval_tampering_fails(causal_demo_output: Path):
    bundle = load_json(causal_demo_output / "half_life_receipt.json")
    source_chain = bundle["receipts"][:-2]
    policy = load_json(causal_demo_output / "compaction_policy.json")
    approval = copy.deepcopy(load_json(causal_demo_output / "receiver_approval.json"))
    approval["disposition"] = "DENY"
    checkpoint_receipt = next(
        item for item in source_chain if item["kind"] == "verified_residue_checkpoint"
    )
    result = verify_receiver_approval(
        approval,
        source_chain=source_chain,
        checkpoint={
            "run_id": checkpoint_receipt["payload"]["run_id"],
            "packet_hash": checkpoint_receipt["payload"]["packet_hash"],
        },
        compaction_policy=policy,
    )
    assert result["valid"] is False
    assert "receiver_approval_signature_or_payload_hash_invalid" in result["reason_codes"]


def test_cold_archive_rehydrates_to_the_same_receiver_decisions(causal_demo_output: Path):
    capsule = load_json(causal_demo_output / "causal_capsule.json")
    policy = load_json(causal_demo_output / "compaction_policy.json")
    result = rehydrate_archived_state(
        causal_demo_output,
        capsule,
        load_json(causal_demo_output / "archive_manifest.json"),
        policy,
        expected_compaction_policy_public_keys={policy["signature"]["public_key"]},
    )
    assert result["source_chain_verified"] is True
    assert result["archive_manifest_verified"] is True
    assert result["compaction_policy_verified"] is True
    assert result["decision_projection"] == receipt_gate_projection(capsule)


@pytest.mark.parametrize("trusted_keys", [None, set()])
def test_archive_rehydration_requires_an_external_compaction_policy_pin(
    causal_demo_output: Path,
    trusted_keys: set[str] | None,
):
    with pytest.raises(CompactionError, match="compaction policy verification failed"):
        rehydrate_archived_state(
            causal_demo_output,
            load_json(causal_demo_output / "causal_capsule.json"),
            load_json(causal_demo_output / "archive_manifest.json"),
            load_json(causal_demo_output / "compaction_policy.json"),
            expected_compaction_policy_public_keys=trusted_keys,
        )


def test_archive_rehydration_rejects_a_tampered_policy_even_with_the_original_pin(
    causal_demo_output: Path,
):
    policy = load_json(causal_demo_output / "compaction_policy.json")
    tampered = copy.deepcopy(policy)
    tampered["causal_admission"]["allowed_relation_kinds"].append("correlation")
    with pytest.raises(CompactionError, match="compaction policy verification failed"):
        rehydrate_archived_state(
            causal_demo_output,
            load_json(causal_demo_output / "causal_capsule.json"),
            load_json(causal_demo_output / "archive_manifest.json"),
            tampered,
            expected_compaction_policy_public_keys={policy["signature"]["public_key"]},
        )
