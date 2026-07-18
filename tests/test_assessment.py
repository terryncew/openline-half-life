from __future__ import annotations

import copy

import pytest

from openline_half_life.assessment import assess_trajectory, first_retirement_turn
from openline_half_life.policy import load_policy
from openline_half_life.schema import load_trajectory


def test_clean_run_is_not_falsely_retired(root, trusted_policy_keys):
    turns = load_trajectory(root / "fixtures/healthy.jsonl")
    policy = load_policy(root / "policy/succession_policy.json", trusted_policy_keys)
    assessments = assess_trajectory(turns, policy, expected_policy_public_keys=trusted_policy_keys)
    assert first_retirement_turn(assessments) is None
    assert {item["mark"] for item in assessments} == {"KEEP"}


def test_first_defensible_retirement_point_is_turn_61_and_reproducible(root, trusted_policy_keys):
    turns = load_trajectory(root / "fixtures/gradual_drift.jsonl")
    policy = load_policy(root / "policy/succession_policy.json", trusted_policy_keys)
    first = assess_trajectory(turns, policy, expected_policy_public_keys=trusted_policy_keys)
    second = assess_trajectory(turns, policy, expected_policy_public_keys=trusted_policy_keys)
    assert first == second
    assert first_retirement_turn(first) == 61
    assert first[59]["mark"] == "WATCH"
    assert first[60]["mark"] == "RETIRE"
    assert first[60]["automatic_retirement_authorized"] is False


def test_sudden_failure_still_requires_canonical_persistence(root, trusted_policy_keys):
    turns = load_trajectory(root / "fixtures/sudden_failure.jsonl")
    policy = load_policy(root / "policy/succession_policy.json", trusted_policy_keys)
    assessments = assess_trajectory(turns, policy, expected_policy_public_keys=trusted_policy_keys)
    assert assessments[7]["mark"] == "WATCH"
    assert first_retirement_turn(assessments) == 9


def test_stale_replay_and_unsupported_claims_are_watch_not_retire(root, trusted_policy_keys):
    policy = load_policy(root / "policy/succession_policy.json", trusted_policy_keys)
    stale = assess_trajectory(
        load_trajectory(root / "fixtures/stale_evidence_replay.jsonl"),
        policy,
        expected_policy_public_keys=trusted_policy_keys,
    )
    unsupported = assess_trajectory(
        load_trajectory(root / "fixtures/unsupported_repetition.jsonl"),
        policy,
        expected_policy_public_keys=trusted_policy_keys,
    )
    assert all(item["mark"] != "RETIRE" for item in stale)
    assert all(item["mark"] != "RETIRE" for item in unsupported)
    assert stale[7]["reason_codes"] == ["STALE_MATERIAL_EVIDENCE"]
    assert unsupported[5]["reason_codes"] == ["UNSUPPORTED_MATERIAL_PRESENT"]


def test_evidence_id_cannot_be_rebound_to_new_content(root, trusted_policy_keys):
    turns = load_trajectory(root / "fixtures/healthy.jsonl")
    tampered = copy.deepcopy(turns)
    first_evidence = tampered[0]["evidence"][0]
    tampered[29]["evidence"].append(
        {
            "id": first_evidence["id"],
            "sha256": "f" * 64,
            "observed_turn": 30,
            "expires_after_turns": 100,
        }
    )
    policy = load_policy(root / "policy/succession_policy.json", trusted_policy_keys)
    with pytest.raises(ValueError, match="evidence_id_rebound"):
        assess_trajectory(tampered, policy, expected_policy_public_keys=trusted_policy_keys)
