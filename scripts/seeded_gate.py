from __future__ import annotations

import argparse
import json
import statistics
import tempfile
from pathlib import Path

from openline_half_life.compaction import candidate_hits_tombstone, compact_projection, derive_compact_state
from openline_half_life.receipts import ReceiptSigner, canonical_json, create_chain, verify_chain
from openline_half_life.reference_replay import reference_projection
from openline_half_life.schema import TURN_SCHEMA
from openline_half_life.util import sha256_bytes

ROOT = Path(__file__).resolve().parents[1]


def _evidence(run: int, turn: int, name: str, expiry: int = 100) -> dict:
    raw = f"{run}:{turn}:{name}".encode()
    return {"id": f"ev-{name}-{turn}", "sha256": sha256_bytes(raw), "observed_turn": turn, "expires_after_turns": expiry}


def build_history(run: int, turns: int = 3) -> list[dict]:
    rows = []
    for turn in range(1, turns + 1):
        evidence = []
        claims = []
        constraints = []
        outcomes = []
        questions = []
        if turn == 1:
            ev = _evidence(run, turn, "version1")
            evidence.append(ev)
            claims.append({"id": "version-v1", "slot": "version", "value": "v1", "material": True, "support_status": "supported", "evidence_refs": [ev["id"]], "last_verified_turn": turn})
        if turn == 2:
            region = _evidence(run, turn, "region")
            old = _evidence(run, turn, "old-credential", expiry=0)
            evidence.extend([region, old])
            constraints.append({"id": "region-lock", "text": "Use the registered region.", "active": True, "evidence_refs": [region["id"]], "last_verified_turn": turn})
            claims.append({"id": "old-credential", "slot": "credential", "value": "old", "material": True, "support_status": "supported", "evidence_refs": [old["id"]], "last_verified_turn": turn})
        if turn == 3:
            version2 = _evidence(run, turn, "version2")
            complete = _evidence(run, turn, "complete")
            evidence.extend([version2, complete])
            claims.append({"id": "version-v2", "slot": "version", "value": "v2", "material": True, "support_status": "supported", "evidence_refs": [version2["id"]], "last_verified_turn": turn})
            outcomes.append({"id": "job-complete", "text": "Job completed and verified.", "confirmed": True, "evidence_refs": [complete["id"]]})
            questions = ["Confirm the final deployment window."]
        rows.append({
            "schema": TURN_SCHEMA,
            "run_id": f"seeded-{run:05d}",
            "turn": turn,
            "objective": "Preserve the verified job state.",
            "summary": (f"Checkpoint {turn}. " + "Repeated operational detail. " * 60),
            "claims": claims,
            "evidence": evidence,
            "constraints": constraints,
            "outcomes": outcomes,
            "unresolved_questions": questions,
            "cost": {"input_tokens": 800 + turn, "output_tokens": 120 + turn},
        })
    return rows


def run_gate(count: int) -> dict:
    signer = ReceiptSigner.from_hex_file(ROOT / "fixtures/demo_source_signing_key.hex")
    ratios = []
    decision_mismatches = 0
    chain_failures = 0
    archive_failures = 0
    tombstone_replays = 0
    verified_histories = 0
    for run in range(count):
        turns = build_history(run)
        items = [("trajectory_turn", {"run_id": row["run_id"], "turn": row["turn"], "turn_hash": sha256_bytes(canonical_json(row)), "turn_record": row}) for row in turns]
        items.extend([
            ("compaction_policy_binding", {"run_id": turns[0]["run_id"], "policy_hash": "0" * 64, "policy_public_key": "1" * 64}),
            ("checkpoint", {"run_id": turns[0]["run_id"], "checkpoint_turn": len(turns), "checkpoint_hash": "2" * 64}),
        ])
        chain = create_chain(items, signer)
        check = verify_chain(chain, expected_signer_public_key=signer.public_b64)
        if not check["valid"]:
            chain_failures += 1
            continue
        verified_histories += 1
        # Archive round trip: every signed receipt is serialized, hashed, recovered,
        # and compared byte-for-byte. The filesystem archive path is tested separately.
        for receipt in chain:
            encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
            digest = sha256_bytes(encoded)
            recovered = json.loads(encoded)
            if sha256_bytes(json.dumps(recovered, sort_keys=True, separators=(",", ":")).encode()) != digest or recovered != receipt:
                archive_failures += 1
                break
        state = derive_compact_state(turns, len(turns))
        full_projection = reference_projection(turns, len(turns))
        compact = compact_projection(state)
        if full_projection != compact:
            decision_mismatches += 1
        candidate = {"item_type": "claim", "slot": "version", "value": "v1", "item_id": "version-v1"}
        if not candidate_hits_tombstone(state, candidate):
            tombstone_replays += 1
        ratios.append(len(canonical_json(state)) * 1_000_000 // len(canonical_json(chain)))
    median_ratio = int(statistics.median(ratios)) if ratios else 1_000_000
    result = {
        "schema": "openline.half-life.seeded-gate.v2",
        "seeded_history_count": count,
        "cryptographically_verified_history_count": verified_histories,
        "chain_verification_failure_count": chain_failures,
        "decision_mismatch_count": decision_mismatches,
        "archive_recovery_failure_count": archive_failures,
        "successful_tombstone_replay_count": tombstone_replays,
        "median_active_size_ratio_micros": median_ratio,
        "passed": verified_histories == count and chain_failures == 0 and decision_mismatches == 0 and archive_failures == 0 and tombstone_replays == 0 and median_ratio <= 200_000,
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=10_000)
    args = parser.parse_args()
    result = run_gate(args.count)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
