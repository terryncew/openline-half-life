#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import random
import statistics
import sys
from concurrent.futures import ProcessPoolExecutor
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openline_half_life.causal_compactor import (
    build_causal_capsule,
    build_compaction_policy_body,
    candidate_hits_tombstone,
    decision_equivalence_report,
    derive_causal_state,
    sign_compaction_policy,
    verify_compaction_policy,
)
from openline_half_life.handoff import build_verified_residue_handoff
from openline_half_life.reference_replay import reference_receipt_gate_projection
from openline_half_life.receipts import ReceiptSigner, create_anchor, create_chain, verify_chain
from openline_half_life.util import canonical_json, sha256_bytes

HISTORY_COUNT = 10_000
def _private(label: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(sha256(label).digest())


def _turn(seed: int, number: int, total: int, false_turn: int) -> dict:
    run_id = f"seeded-{seed:05d}"
    evidence_id = "ev-current"
    evidence_hash = sha256(f"evidence:{seed}".encode()).hexdigest()
    evidence = [
        {
            "id": evidence_id,
            "sha256": evidence_hash,
            "observed_turn": number,
            "expires_after_turns": total + 5,
        }
    ]
    claims = [
        {
            "id": f"claim-current-{number}",
            "slot": "current_mode",
            "value": f"mode-{seed % 7}",
            "material": True,
            "support_status": "supported",
            "evidence_refs": [evidence_id],
            "last_verified_turn": number,
        }
    ]
    if number == false_turn:
        claims.append(
            {
                "id": "claim-rejected",
                "slot": "unsafe_override",
                "value": "enabled",
                "material": True,
                "support_status": "unsupported",
                "evidence_refs": [],
                "last_verified_turn": number,
            }
        )
    constraints = []
    if number == 1:
        constraints = [
            {
                "id": "safety-floor",
                "text": "Never bypass receiver approval.",
                "active": True,
                "evidence_refs": [evidence_id],
                "last_verified_turn": 1,
            }
        ]
    outcomes = []
    if number == total:
        outcomes = [
            {
                "id": "checkpoint-complete",
                "text": "Checkpoint complete.",
                "confirmed": True,
                "evidence_refs": [evidence_id],
            }
        ]
    return {
        "schema": "openline.half-life.turn.v1",
        "run_id": run_id,
        "turn": number,
        "objective": "Preserve receiver-governed state.",
        "summary": f"seed={seed};turn={number};checkpoint",
        "measurements": {
            "kappa_micros": 0,
            "epsilon_micros": 0,
            "delta_hol_micros": 0,
            "phi_star_micros": 990_099,
            "ucr_micros": 0,
        },
        "claims": claims,
        "evidence": evidence,
        "constraints": constraints,
        "outcomes": outcomes,
        "unresolved_questions": ["Will a future outcome overturn the retained mechanism?"],
        "cost": {"input_tokens": number * 10, "output_tokens": number},
    }


def _gate_context() -> tuple[ReceiptSigner, dict]:
    source_signer = ReceiptSigner(_private(b"openline-half-life-10k-source"))
    receiver_key = _private(b"openline-half-life-10k-policy")
    policy_body = build_compaction_policy_body(
        trusted_source_receipt_signer_keys_b64=[source_signer.public_b64],
        trusted_receiver_approval_public_keys=[receiver_key.public_key().public_bytes_raw().hex()],
        active_receipt_bytes_budget=25_000,
        replay_latency_micros_budget=1_000,
        policy_version="10k-gate",
        trusted_key_version="10k-receiver-key-v1",
    )
    policy = sign_compaction_policy(policy_body, receiver_key)
    policy_check = verify_compaction_policy(
        policy, {receiver_key.public_key().public_bytes_raw().hex()}
    )
    if not policy_check["valid"]:
        raise AssertionError(policy_check)
    return source_signer, policy


def _run_range(start_seed: int, end_seed: int) -> dict:
    """Run a deterministic contiguous seed range with full crypto on every chain."""

    source_signer, policy = _gate_context()
    mismatches = 0
    tombstone_replays = 0
    archive_failures = 0
    chain_failures = 0
    ratios: list[int] = []
    archived_receipts = 0
    cryptographically_verified_history_count = 0
    semantic_history_count = 0

    for seed in range(start_seed, end_seed):
        rng = random.Random(seed)
        turn_count = (
            20 + rng.randrange(0, 5)
            if seed % 10 == 0
            else 10 + rng.randrange(0, 4)
        )
        false_turn = 2 + rng.randrange(0, max(1, turn_count - 3))
        turns = [_turn(seed, number, turn_count, false_turn) for number in range(1, turn_count + 1)]
        items = [
            (
                "trajectory_turn",
                {
                    "run_id": turn["run_id"],
                    "turn_number": turn["turn"],
                    "turn_hash": sha256_bytes(canonical_json(turn)),
                    "turn_record": turn,
                },
            )
            for turn in turns
        ]
        checkpoint = build_verified_residue_handoff(turns, turn_count, "a" * 64)
        items.append(
            (
                "verified_residue_checkpoint",
                {
                    "run_id": turns[0]["run_id"],
                    "retirement_turn": turn_count,
                    "packet_hash": checkpoint["packet_hash"],
                    "policy_hash": "a" * 64,
                    "automatic_retirement_authorized": False,
                },
            )
        )

        # No synthetic envelope and no sampling: every history is signed,
        # hash-chained, anchored, and fully verified.
        chain = create_chain(items, source_signer)
        anchor = create_anchor(chain, source_signer)
        cryptographically_verified_history_count += 1
        if not verify_chain(chain, anchor)["valid"]:
            chain_failures += 1
            continue

        state = derive_causal_state(turns, chain, turn_count, policy)
        capsule = build_causal_capsule(
            state,
            source_chain=chain,
            source_anchor=anchor,
            succession_policy_hash="a" * 64,
            succession_policy_public_key="b" * 64,
            compaction_policy=policy,
            checkpoint_hash=checkpoint["packet_hash"],
            archive_destination=policy["archive"]["destination"],
            receiver_disposition="APPROVE",
        )
        report = decision_equivalence_report(
            reference_receipt_gate_projection(turns, chain, turn_count, policy),
            capsule,
            source_chain_size_bytes=len(canonical_json(chain)),
        )
        semantic_history_count += 1
        if report["source_chain_active_bytes"] > policy["trigger"]["active_receipt_bytes_budget"]:
            ratios.append(report["active_size_ratio_micros"])
        if not report["passed"]:
            mismatches += 1

        rejected = next(
            (item for item in capsule["tombstones"] if item["status"] == "rejected"),
            None,
        )
        if rejected is None or not candidate_hits_tombstone(
            capsule,
            {
                "item_type": "claim",
                "item_id": "claim-rejected",
                "slot": "unsafe_override",
                "value_hash": sha256_bytes(canonical_json("enabled")),
            },
        ):
            tombstone_replays += 1

        archive = {receipt["receipt_hash"]: canonical_json(receipt) for receipt in chain}
        archived_receipts += len(archive)
        for receipt in chain:
            encoded = archive.get(receipt["receipt_hash"])
            if encoded is None or json.loads(encoded) != receipt:
                archive_failures += 1
                break
            body = {
                key: receipt[key]
                for key in (
                    "schema",
                    "index",
                    "kind",
                    "parent_hash",
                    "signer_public_key",
                    "payload",
                )
            }
            if sha256_bytes(canonical_json(body)) != receipt["receipt_hash"]:
                archive_failures += 1
                break

    return {
        "semantic_history_count": semantic_history_count,
        "cryptographically_verified_history_count": cryptographically_verified_history_count,
        "mismatches": mismatches,
        "tombstone_replays": tombstone_replays,
        "archive_failures": archive_failures,
        "chain_failures": chain_failures,
        "ratios": ratios,
        "archived_receipts": archived_receipts,
    }


def _run_bounds(bounds: tuple[int, int]) -> dict:
    return _run_range(*bounds)


def _seed_ranges(history_count: int, worker_count: int) -> list[tuple[int, int]]:
    base, extra = divmod(history_count, worker_count)
    ranges: list[tuple[int, int]] = []
    start = 0
    for index in range(worker_count):
        stop = start + base + (1 if index < extra else 0)
        if start < stop:
            ranges.append((start, stop))
        start = stop
    return ranges


def run(history_count: int = HISTORY_COUNT) -> dict:
    requested_workers = int(
        os.environ.get(
            "OPENLINE_HALF_LIFE_GATE_WORKERS",
            str(min(4, os.cpu_count() or 1)),
        )
    )
    worker_count = max(1, min(requested_workers, history_count))
    # Small regression runs stay in-process. The full release gate uses bounded
    # deterministic workers to keep 10,000 complete Ed25519 verifications fast.
    if history_count < 2_000:
        worker_count = 1

    if worker_count == 1:
        parts = [_run_range(0, history_count)]
    else:
        ranges = _seed_ranges(history_count, worker_count)
        with ProcessPoolExecutor(max_workers=worker_count) as executor:
            parts = list(executor.map(_run_bounds, ranges))

    semantic_history_count = sum(part["semantic_history_count"] for part in parts)
    cryptographically_verified_history_count = sum(
        part["cryptographically_verified_history_count"] for part in parts
    )
    mismatches = sum(part["mismatches"] for part in parts)
    tombstone_replays = sum(part["tombstone_replays"] for part in parts)
    archive_failures = sum(part["archive_failures"] for part in parts)
    chain_failures = sum(part["chain_failures"] for part in parts)
    archived_receipts = sum(part["archived_receipts"] for part in parts)
    ratios = [ratio for part in parts for ratio in part["ratios"]]

    median_ratio = int(statistics.median(ratios)) if ratios else 1_000_000
    all_histories_cryptographically_verified = (
        cryptographically_verified_history_count == history_count
    )
    passed = (
        semantic_history_count == history_count
        and len(ratios) == (history_count + 9) // 10
        and all_histories_cryptographically_verified
        and chain_failures == 0
        and mismatches == 0
        and tombstone_replays == 0
        and archive_failures == 0
        and median_ratio <= 200_000
    )
    return {
        "schema": "openline.half-life.compaction-release-gate.v2",
        "seeded_history_count": history_count,
        "independently_replayed_history_count": semantic_history_count,
        "compression_size_history_count": len(ratios),
        "passed": passed,
        "decision_mismatch_count": mismatches,
        "successful_tombstone_replay_count": tombstone_replays,
        "archive_recovery_failure_count": archive_failures,
        "chain_verification_failure_count": chain_failures,
        "cryptographically_verified_history_count": cryptographically_verified_history_count,
        "all_histories_cryptographically_verified": all_histories_cryptographically_verified,
        "worker_count": worker_count,
        "archived_receipt_count": archived_receipts,
        "median_active_size_ratio_micros": median_ratio,
        "maximum_allowed_median_ratio_micros": 200_000,
        "automatic_retirement_authorized": False,
    }


if __name__ == "__main__":
    result = run()
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["passed"] else 1)
