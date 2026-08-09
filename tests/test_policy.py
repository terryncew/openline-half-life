from __future__ import annotations

import copy
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openline_half_life.compaction import build_policy_body, sign_policy, verify_policy
from openline_half_life.receipts import ReceiptSigner
from openline_half_life.util import load_json


def _keys(path: Path) -> set[str]:
    return {line.strip() for line in path.read_text().splitlines() if line.strip()}


def test_demo_policy_is_pinned_and_valid(root: Path):
    policy = load_json(root / "policy/compaction_policy.json")
    result = verify_policy(policy, _keys(root / "policy/compaction_policy_public_key.hex"))
    assert result["valid"] is True


def test_policy_tamper_fails(root: Path):
    policy = load_json(root / "policy/compaction_policy.json")
    policy["trigger"]["active_receipt_bytes_budget"] += 1
    assert verify_policy(policy, _keys(root / "policy/compaction_policy_public_key.hex"))["valid"] is False


def test_unpinned_policy_fails(root: Path):
    policy = load_json(root / "policy/compaction_policy.json")
    assert "trusted_policy_key_required" in verify_policy(policy, None)["errors"]


def test_policy_signer_cannot_be_approval_signer(root: Path):
    source = ReceiptSigner.from_hex_file(root / "fixtures/demo_source_signing_key.hex")
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("44" * 32))
    pub = key.public_key().public_bytes_raw().hex()
    policy = sign_policy(build_policy_body(trusted_source_signer_keys_b64=[source.public_b64], trusted_operator_approval_public_keys=[pub], active_receipt_bytes_budget=1, replay_latency_micros_budget=1), key)
    result = verify_policy(policy, {pub})
    assert "policy_signer_cannot_approve_its_own_compaction" in result["errors"]
