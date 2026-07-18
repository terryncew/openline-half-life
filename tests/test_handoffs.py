from __future__ import annotations

import copy

import pytest

from openline_half_life.handoff import build_full_history_handoff, build_verified_residue_handoff
from openline_half_life.policy import load_policy
from openline_half_life.schema import load_trajectory


def test_verified_residue_excludes_unsupported_and_stale_material(root, trusted_policy_keys):
    turns = load_trajectory(root / "fixtures/gradual_drift.jsonl")
    policy = load_policy(root / "policy/succession_policy.json", trusted_policy_keys)
    residue = build_verified_residue_handoff(turns, 61, policy["payload_hash"])
    values = {(item["slot"], item["value"]) for item in residue["supported_claims"]}
    assert ("deployment_region", "us-west-2") in values
    assert ("deployment_region", "eu-west-1") not in values
    assert ("max_batch_size", "500") not in values
    assert ("api_version", "v1") not in values
    reasons = {item["reason"] for item in residue["excluded_claims"]}
    assert "unsupported_or_unresolved" in reasons
    assert "stale_evidence" in reasons


def test_verified_residue_recovers_important_constraint_lost_by_latest_summary(root, trusted_policy_keys):
    turns = load_trajectory(root / "fixtures/lost_constraint.jsonl")
    policy = load_policy(root / "policy/succession_policy.json", trusted_policy_keys)
    full = build_full_history_handoff(turns, 12, policy["payload_hash"])
    residue = build_verified_residue_handoff(turns, 12, policy["payload_hash"])
    assert full["turns"][-1]["constraints"] == []
    assert [item["id"] for item in residue["current_constraints"]] == ["privacy-floor"]


def test_outcome_retraction_removes_prior_confirmation(root, trusted_policy_keys):
    turns = copy.deepcopy(load_trajectory(root / "fixtures/healthy.jsonl")[:2])
    evidence_id = turns[0]["evidence"][0]["id"]
    turns[0]["outcomes"] = [
        {"id": "deployment-complete", "text": "Deployment complete.", "confirmed": True, "evidence_refs": [evidence_id]}
    ]
    turns[1]["outcomes"] = [
        {"id": "deployment-complete", "text": "Deployment was rolled back.", "confirmed": False, "evidence_refs": []}
    ]
    policy = load_policy(root / "policy/succession_policy.json", trusted_policy_keys)
    residue = build_verified_residue_handoff(turns, 2, policy["payload_hash"])
    assert residue["confirmed_outcomes"] == []
    assert residue["excluded_outcomes"] == [
        {"outcome_id": "deployment-complete", "observed_turn": 2, "reason": "retracted"}
    ]


def test_confirmed_outcome_requires_fresh_evidence(root, trusted_policy_keys):
    turns = copy.deepcopy(load_trajectory(root / "fixtures/healthy.jsonl")[:2])
    turns[0]["outcomes"] = [
        {"id": "unsupported-outcome", "text": "Done.", "confirmed": True, "evidence_refs": []}
    ]
    policy = load_policy(root / "policy/succession_policy.json", trusted_policy_keys)
    residue = build_verified_residue_handoff(turns, 2, policy["payload_hash"])
    assert residue["confirmed_outcomes"] == []
    assert residue["excluded_outcomes"][0]["reason"] == "missing_evidence_reference"


def test_handoff_rejects_evidence_id_rebinding(root, trusted_policy_keys):
    turns = copy.deepcopy(load_trajectory(root / "fixtures/healthy.jsonl")[:3])
    evidence_id = turns[0]["evidence"][0]["id"]
    turns[2]["evidence"].append(
        {"id": evidence_id, "sha256": "e" * 64, "observed_turn": 3, "expires_after_turns": 5}
    )
    policy = load_policy(root / "policy/succession_policy.json", trusted_policy_keys)
    with pytest.raises(ValueError, match="evidence_id_rebound"):
        build_verified_residue_handoff(turns, 3, policy["payload_hash"])
