from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openline_half_life.policy import (
    CANONICAL_SOURCE_SHA256,
    DEMO_POLICY_PUBLIC_KEY_HEX,
    build_demo_policy,
    verify_policy,
    verify_vendored_source,
)
from openline_half_life.vendor.openline_endurance_gate import succession as canonical


def test_policy_is_generated_by_pinned_v0100_fitter(root, trusted_policy_keys):
    policy = build_demo_policy()
    assert verify_policy(policy, trusted_policy_keys)["valid"] is True
    assert policy["canonical_source"]["version"] == "0.10.0"
    assert policy["canonical_source"]["vendored_source_sha256"] == CANONICAL_SOURCE_SHA256
    assert policy["signature"]["public_key"] == DEMO_POLICY_PUBLIC_KEY_HEX
    assert verify_vendored_source(root / "src/openline_half_life/vendor/openline_endurance_gate/succession.py")


def test_policy_verification_requires_receiver_owned_key_pin():
    policy = build_demo_policy()
    result = verify_policy(policy, None)
    assert result["valid"] is False
    assert "trusted_policy_key_required" in result["reason_codes"]


def test_self_signed_forged_policy_is_rejected_by_receiver_pin(trusted_policy_keys):
    policy = build_demo_policy()
    body = dict(policy)
    body.pop("payload_hash")
    body.pop("signature")
    body["persistence"] = {
        "minimum_metric_breaches": 0,
        "persistence_window": 1,
        "persistence_required": 1,
    }
    attacker = Ed25519PrivateKey.generate()
    forged = canonical._sign_envelope(body, attacker)
    result = verify_policy(forged, trusted_policy_keys)
    assert result["valid"] is False
    assert "policy_signer_not_trusted" in result["reason_codes"]



def test_trusted_signature_cannot_replace_canonical_fitter_output():
    policy = build_demo_policy()
    body = dict(policy)
    body.pop("payload_hash")
    body.pop("signature")
    body["persistence"] = {
        "minimum_metric_breaches": 0,
        "persistence_window": 1,
        "persistence_required": 1,
    }
    signer = Ed25519PrivateKey.generate()
    forged = canonical._sign_envelope(body, signer)
    trusted_attacker_key = {signer.public_key().public_bytes_raw().hex()}
    result = verify_policy(forged, trusted_attacker_key)
    assert result["valid"] is False
    assert "canonical_fitter_output_mismatch" in result["reason_codes"]

def test_metrics_and_ucr_remain_separate(trusted_policy_keys):
    policy = build_demo_policy()
    assert verify_policy(policy, trusted_policy_keys)["valid"] is True
    assert set(policy["thresholds"]) == {
        "kappa_micros",
        "epsilon_micros",
        "delta_hol_micros",
        "phi_star_micros",
    }
    assert "ucr_micros" not in policy["thresholds"]
    assert policy["evidence_sufficiency"] == {
        "metric": "ucr_micros",
        "required_value_micros": 0,
        "role": "separate_evidence_gate_not_health_score",
    }


def test_canonical_demo_policy_is_reproducible():
    first = build_demo_policy()
    second = build_demo_policy()
    assert first == second
    assert first["persistence"]["minimum_metric_breaches"] == 4
    assert first["persistence"]["persistence_window"] == 2
    assert first["persistence"]["persistence_required"] == 2
    assert first["holdout_validation"]["balanced_accuracy_micros"] == 1_000_000
