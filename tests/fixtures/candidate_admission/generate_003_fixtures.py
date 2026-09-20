#!/usr/bin/env python3
"""Generate the frozen fixtures for context-admit discrimination (003).

Deterministic. No randomness, no network, no model calls.

Produces, under tests/fixtures/candidate_admission/:
  context3_history.jsonl                  7-turn trajectory; evidence ev-c-short
                                          (observed turn 5, expires_after_turns=1)
                                          is fresh at checkpoint 6 and stale at 7
  context3_candidate_good.json            candidate derived at checkpoint 6
  context3_candidate_manifest_good.json
  context3_candidate_rehydrated.json      candidate derived at checkpoint 7
                                          (c-live tombstoned stale, not live)
  context3_candidate_manifest_rehydrated.json

Candidates are derived once from Half-Life's own derivation by this script
and CHECKED IN, exactly like generate_admission_fixtures.py. Tests read the
static files; nothing is generated dynamically by the code under test.

Regenerate only intentionally: the checked-in files are the frozen test input.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from openline_half_life.candidate_admission import (
    CANDIDATE_STATE_SCHEMA,
    build_candidate_manifest,
)
from openline_half_life.compaction import build_checkpoint, derive_compact_state
from openline_half_life.schema import load_trajectory
from openline_half_life.util import load_json

OUT = Path(__file__).resolve().parent
RUN_ID = "context-admit-003"
OBJECTIVE = "Discriminate continued-use conditioning on evidence standing."
Q1 = "What is the post-cutover latency under peak load?"


def h(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def ev(evidence_id: str, observed_turn: int, expires: int = 100) -> dict:
    return {
        "id": evidence_id,
        "sha256": h(f"evidence:{evidence_id}"),
        "observed_turn": observed_turn,
        "expires_after_turns": expires,
    }


def claim(claim_id: str, slot: str, value, status: str, refs: list, turn: int) -> dict:
    return {
        "id": claim_id,
        "slot": slot,
        "value": value,
        "material": True,
        "support_status": status,
        "evidence_refs": refs,
        "last_verified_turn": turn,
    }


def constraint(constraint_id: str, text: str, refs: list, turn: int, active: bool = True) -> dict:
    return {
        "id": constraint_id,
        "text": text,
        "active": active,
        "evidence_refs": refs,
        "last_verified_turn": turn,
    }


def outcome(outcome_id: str, text: str, refs: list, confirmed: bool = True) -> dict:
    return {"id": outcome_id, "text": text, "confirmed": confirmed, "evidence_refs": refs}


def turn(number: int, *, claims=(), constraints=(), outcomes=(), questions=(), evidence=()) -> dict:
    return {
        "schema": "openline.half-life.turn.v2",
        "run_id": RUN_ID,
        "turn": number,
        "objective": OBJECTIVE,
        "summary": f"Context-admit case-3 fixture turn {number}.",
        "claims": list(claims),
        "evidence": list(evidence),
        "constraints": list(constraints),
        "outcomes": list(outcomes),
        "unresolved_questions": list(questions),
        "cost": {"input_tokens": 100 + number, "output_tokens": 20 + number},
    }


def build_history() -> list[dict]:
    return [
        turn(
            1,
            claims=[
                claim("claim-region-1", "deployment_region", "us-west-2", "supported", ["ev-region-1"], 1),
                claim("claim-batch-1", "max_batch_size", "300", "supported", ["ev-batch-1"], 1),
            ],
            outcomes=[outcome("o-cutover", "Cutover completed.", ["ev-outcome-1"])],
            questions=[Q1],
            evidence=[ev("ev-region-1", 1), ev("ev-batch-1", 1), ev("ev-outcome-1", 1)],
        ),
        turn(
            2,
            claims=[claim("claim-region-2", "deployment_region", "us-east-1", "supported", ["ev-region-2"], 2)],
            questions=[Q1],
            evidence=[ev("ev-region-2", 2)],
        ),
        turn(
            3,
            claims=[
                claim("claim-flag-3a", "cache_ttl", "60", "supported", ["ev-flag-3"], 3),
                claim("claim-flag-3b", "cache_ttl", "120", "supported", ["ev-flag-3"], 3),
            ],
            questions=[Q1],
            evidence=[ev("ev-flag-3", 3)],
        ),
        turn(4, questions=[Q1]),
        turn(
            5,
            constraints=[constraint("c-live", "Batch cost must stay under the budget cap.", ["ev-c-short"], 5)],
            questions=[Q1],
            # ev-c-short: fresh at checkpoint 6 (6 <= 5+1), stale at 7 (7 > 5+1).
            evidence=[ev("ev-c-short", 5, expires=1)],
        ),
        turn(6, questions=[Q1]),
        turn(7, questions=[Q1]),
    ]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def candidate_from_state(state: dict) -> dict:
    """Strip the internal derivation to the external candidate contract."""
    return {
        "schema": CANDIDATE_STATE_SCHEMA,
        "run_id": state["run_id"],
        "checkpoint_turn": state["checkpoint_turn"],
        "objective": state["objective"],
        "supported_claims": state["supported_claims"],
        "current_constraints": state["current_constraints"],
        "confirmed_outcomes": state["confirmed_outcomes"],
        "unresolved_questions": state["unresolved_questions"],
        "contradictions": state["contradictions"],
        "tombstones": state["tombstones"],
        "evidence_references": state["evidence_references"],
    }


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    policy = load_json(ROOT / "policy" / "compaction_policy.json")
    policy_hash = policy["payload_hash"]

    history = build_history()
    write_jsonl(OUT / "context3_history.jsonl", history)
    turns = load_trajectory(OUT / "context3_history.jsonl")

    for checkpoint_turn, tag in ((6, "good"), (7, "rehydrated")):
        checkpoint = build_checkpoint(turns, checkpoint_turn, policy_hash)
        state = derive_compact_state(turns, checkpoint_turn)
        candidate = candidate_from_state(state)
        write_json(OUT / f"context3_candidate_{tag}.json", candidate)
        write_json(
            OUT / f"context3_candidate_manifest_{tag}.json",
            build_candidate_manifest(candidate, checkpoint, producer_label="fixture-producer-003"),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
