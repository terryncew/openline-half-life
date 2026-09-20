"""Preregistered perturbation attack on the candidate-admission boundary.

This attack runs only because the base suite passes. The perturbation family,
success criterion, and the rule below were frozen before any perturbation was
applied: a failed base case remains failed, and perturbations cannot reopen
or rescue it.

Family (discrete, semantic-preserving; no decorative epsilon scalar):
  P1 field reordering        candidate re-serialized with reversed key order
                             and different indentation -> must ADMIT
  P2 canonical re-serialization candidate with compact separators and no
                             trailing newline -> must ADMIT
  P3 irrelevant item fields   "producer_note" added inside one supported claim
                             and one tombstone -> must ADMIT
  P4 summary-only later turn  history.jsonl + turn 7 (no protected changes),
                             candidate re-manifested at checkpoint_turn=7
                             -> must ADMIT
  P5 emptied evidence refs    candidate with evidence_references=[] (not part
                             of the projection) -> must ADMIT

Success: ADMIT with zero decision mismatches for all five. Any REJECT is a
failed attack, reported exactly as observed.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from openline_half_life.candidate_admission import build_candidate_manifest, candidate_state_hash
from openline_half_life.compaction import build_checkpoint
from openline_half_life.pipeline import admit_pipeline, verify_admission_output_directory
from openline_half_life.schema import load_trajectory
from openline_half_life.util import canonical_json, load_json, sha256_bytes

from test_candidate_admission import (
    FIXTURES,
    POLICY,
    POLICY_KEYS,
    ROOT,
    REPLAY_LATENCY_MICROS,
    _policy_public_keys,
    policy_hash,
)

CHECKPOINT_TURN = 6


def _admit(candidate_path: Path, manifest_path: Path, tmp_path: Path):
    return admit_pipeline(
        FIXTURES / "history.jsonl",
        candidate_path,
        manifest_path,
        ROOT / "fixtures" / "demo_source_signing_key.hex",
        tmp_path / "out",
        compaction_policy_path=POLICY,
        compaction_policy_public_key_path=POLICY_KEYS,
        operator_approval_signing_key_path=ROOT / "fixtures" / "demo_operator_approval_key.hex",
        replay_latency_micros=REPLAY_LATENCY_MICROS,
        operator_disposition="APPROVE",
    )


def _write_variant(tmp_path: Path, name: str, candidate_bytes: bytes) -> Path:
    candidate_path = tmp_path / f"candidate_{name}.json"
    candidate_path.write_bytes(candidate_bytes)
    return candidate_path


def _write_manifest(tmp_path: Path, name: str, candidate: dict, checkpoint) -> Path:
    manifest = build_candidate_manifest(candidate, checkpoint, producer_label="perturbation-attack")
    manifest_path = tmp_path / f"manifest_{name}.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest_path


def _good_candidate() -> dict:
    return load_json(FIXTURES / "candidate_good.json")


def _checkpoint(checkpoint_turn: int = CHECKPOINT_TURN):
    turns = load_trajectory(FIXTURES / "history.jsonl")
    return build_checkpoint(turns, checkpoint_turn, policy_hash())


def _assert_admitted(tmp_path: Path, result) -> None:
    assert result["passed"] is True
    assert result["accepted"] is True
    assert result["decision_mismatch_count"] == 0
    verification = verify_admission_output_directory(tmp_path / "out", expected_policy_public_keys=_policy_public_keys())
    assert verification["valid"] is True


def test_p1_field_reordering_still_admits(tmp_path):
    candidate = _good_candidate()
    reordered = json.loads(json.dumps(candidate))  # ensure insertion order
    reversed_candidate = {key: reordered[key] for key in reversed(list(reordered))}
    candidate_path = _write_variant(tmp_path, "p1", (json.dumps(reversed_candidate, indent=4) + "\n").encode("utf-8"))
    manifest_path = _write_manifest(tmp_path, "p1", reversed_candidate, _checkpoint())
    _assert_admitted(tmp_path, _admit(candidate_path, manifest_path, tmp_path))


def test_p2_canonical_reserialization_still_admits(tmp_path):
    candidate = _good_candidate()
    candidate_path = _write_variant(tmp_path, "p2", canonical_json(candidate))
    manifest_path = _write_manifest(tmp_path, "p2", candidate, _checkpoint())
    _assert_admitted(tmp_path, _admit(candidate_path, manifest_path, tmp_path))


def test_p3_irrelevant_item_fields_still_admit(tmp_path):
    candidate = _good_candidate()
    candidate["supported_claims"][0]["producer_note"] = "irrelevant"
    candidate["tombstones"][0]["producer_note"] = "irrelevant"
    candidate_path = _write_variant(tmp_path, "p3", (json.dumps(candidate, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    manifest_path = _write_manifest(tmp_path, "p3", candidate, _checkpoint())
    _assert_admitted(tmp_path, _admit(candidate_path, manifest_path, tmp_path))


def test_p4_summary_only_later_turn_still_admits(tmp_path):
    rows = (FIXTURES / "history.jsonl").read_text(encoding="utf-8").splitlines()
    extra = json.loads(rows[0])
    extra = dict(extra, turn=7, summary="Summary-only turn; no protected material changes.", claims=[], evidence=[], constraints=[], outcomes=[])
    extended_path = tmp_path / "history_extended.jsonl"
    extended_path.write_text("\n".join(rows + [json.dumps(extra, sort_keys=True)]) + "\n", encoding="utf-8")
    candidate = _good_candidate()
    candidate = {**candidate, "checkpoint_turn": 7}
    turns = load_trajectory(extended_path)
    checkpoint = build_checkpoint(turns, 7, policy_hash())
    assert candidate_state_hash(candidate) == sha256_bytes(canonical_json(candidate))
    manifest = build_candidate_manifest(candidate, checkpoint, producer_label="perturbation-attack")
    manifest_path = tmp_path / "manifest_p4.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    candidate_path = _write_variant(tmp_path, "p4", (json.dumps(candidate, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    result = admit_pipeline(
        extended_path,
        candidate_path,
        manifest_path,
        ROOT / "fixtures" / "demo_source_signing_key.hex",
        tmp_path / "out",
        compaction_policy_path=POLICY,
        compaction_policy_public_key_path=POLICY_KEYS,
        operator_approval_signing_key_path=ROOT / "fixtures" / "demo_operator_approval_key.hex",
        replay_latency_micros=REPLAY_LATENCY_MICROS,
        operator_disposition="APPROVE",
    )
    assert result["checkpoint_turn"] == 7
    _assert_admitted(tmp_path, result)


def test_p5_emptied_evidence_refs_still_admit(tmp_path):
    candidate = _good_candidate()
    candidate = {**candidate, "evidence_references": []}
    candidate_path = _write_variant(tmp_path, "p5", (json.dumps(candidate, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    manifest_path = _write_manifest(tmp_path, "p5", candidate, _checkpoint())
    _assert_admitted(tmp_path, _admit(candidate_path, manifest_path, tmp_path))
