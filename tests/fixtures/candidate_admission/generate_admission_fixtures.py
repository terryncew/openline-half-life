#!/usr/bin/env python3
"""Generate the frozen fixtures for candidate-admission tests.

Deterministic. No randomness, no network, no model calls.

Produces, under tests/fixtures/candidate_admission/:
  history.jsonl            small rich trajectory (6 turns)
  history_extended.jsonl   history.jsonl + a summary-only 7th turn (perturbation)
  history_other.jsonl      unrelated trajectory (wrong-source fixture)
  candidate_good.json      candidate preserving the full protected projection
  candidate_manifest_good.json
  candidate_<variant>.json + candidate_manifest_<variant>.json for B-H, L
  candidate_mutated.json   (J: bytes changed after manifest creation)
  candidate_manifest_mutated.json  (K: binding altered)

The GOOD candidate is derived once from Half-Life's own derivation by this
script and CHECKED IN. Tests read the static files; nothing is generated
dynamically by the admission function under test.

Regenerate only intentionally: the checked-in files are the frozen test input.
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from openline_half_life.candidate_admission import (
    CANDIDATE_STATE_SCHEMA,
    build_candidate_manifest,
    candidate_state_hash,
)
from openline_half_life.compaction import build_checkpoint, derive_compact_state
from openline_half_life.schema import load_trajectory
from openline_half_life.util import load_json

OUT = Path(__file__).resolve().parent
RUN_ID = "candidate-admission-demo"
OBJECTIVE = "Exercise the compiler-neutral candidate-admission doorway."
Q1 = "What is the post-cutover latency under peak load?"
Q2 = "Who owns the legacy endpoint decommission decision?"


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
        "summary": f"Admission fixture turn {number}.",
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
            constraints=[constraint("c-budget", "Batch cost must stay under the budget cap.", ["ev-constraint-1"], 1)],
            outcomes=[outcome("o-cutover", "Cutover completed.", ["ev-outcome-1"])],
            questions=[Q1],
            evidence=[ev("ev-region-1", 1), ev("ev-batch-1", 1), ev("ev-constraint-1", 1), ev("ev-outcome-1", 1)],
        ),
        turn(
            2,
            claims=[claim("claim-region-2", "deployment_region", "us-east-1", "supported", ["ev-region-2"], 2)],
            questions=[Q1],
            evidence=[ev("ev-region-2", 2)],
        ),
        turn(
            3,
            claims=[claim("claim-flag-3", "experimental_flag", True, "unsupported", ["ev-flag-3"], 3)],
            outcomes=[outcome("o-rollback", "Rollback executed.", ["ev-outcome-3"], confirmed=False)],
            questions=[Q1],
            evidence=[ev("ev-flag-3", 3), ev("ev-outcome-3", 3)],
        ),
        turn(
            4,
            claims=[
                claim("claim-ttl-4a", "cache_ttl", "60", "supported", ["ev-ttl-4"], 4),
                claim("claim-ttl-4b", "cache_ttl", "120", "supported", ["ev-ttl-4"], 4),
            ],
            questions=[Q1],
            evidence=[ev("ev-ttl-4", 4)],
        ),
        turn(
            5,
            constraints=[constraint("c-legacy", "Legacy endpoint must remain reachable.", ["ev-constraint-5"], 5, active=False)],
            questions=[Q1, Q2],
            evidence=[ev("ev-constraint-5", 5)],
        ),
        turn(6, questions=[Q1, Q2]),
    ]


def build_other_history() -> list[dict]:
    other = "candidate-admission-other"

    def other_turn(number: int, *, claims=(), questions=(), evidence=()) -> dict:
        return {
            "schema": "openline.half-life.turn.v2",
            "run_id": other,
            "turn": number,
            "objective": OBJECTIVE,
            "summary": f"Unrelated history turn {number}.",
            "claims": list(claims),
            "evidence": list(evidence),
            "constraints": [],
            "outcomes": [],
            "unresolved_questions": list(questions),
            "cost": {"input_tokens": 10 + number, "output_tokens": 1 + number},
        }

    return [
        other_turn(1, claims=[claim("claim-x-1", "unrelated_slot", "x", "supported", ["ev-x-1"], 1)], questions=["An unrelated question?"], evidence=[ev("ev-x-1", 1)]),
        other_turn(2, claims=[claim("claim-x-2", "unrelated_slot", "y", "supported", ["ev-x-2"], 2)], questions=["An unrelated question?"], evidence=[ev("ev-x-2", 2)]),
        other_turn(3, questions=["An unrelated question?"]),
        other_turn(4, questions=["An unrelated question?"]),
        other_turn(5, questions=["An unrelated question?", "A second unrelated question?"]),
        other_turn(6, questions=["An unrelated question?", "A second unrelated question?"]),
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
    policy = load_json(ROOT / "src/openline_half_life/data/policy/compaction_policy.json")
    policy_hash = policy["payload_hash"]

    history = build_history()
    write_jsonl(OUT / "history.jsonl", history)
    extended = history + [turn(7, questions=[Q1, Q2])]
    write_jsonl(OUT / "history_extended.jsonl", extended)
    write_jsonl(OUT / "history_other.jsonl", build_other_history())

    turns = load_trajectory(OUT / "history.jsonl")
    checkpoint_turn = 6
    checkpoint = build_checkpoint(turns, checkpoint_turn, policy_hash)
    state = derive_compact_state(turns, checkpoint_turn)
    good = candidate_from_state(state)
    write_json(OUT / "candidate_good.json", good)
    write_json(OUT / "candidate_manifest_good.json", build_candidate_manifest(good, checkpoint, producer_label="fixture-producer"))

    def variant(name: str, mutate) -> None:
        cand = copy.deepcopy(good)
        mutate(cand)
        write_json(OUT / f"candidate_{name}.json", cand)
        write_json(OUT / f"candidate_manifest_{name}.json", build_candidate_manifest(cand, checkpoint, producer_label="fixture-producer"))

    def drop_constraint(c):
        c["current_constraints"] = []

    def drop_question(c):
        c["unresolved_questions"] = [q for q in c["unresolved_questions"] if q != Q2]

    def drop_tombstone(c):
        c["tombstones"] = [t for t in c["tombstones"] if t.get("status") != "superseded"]

    def resurrect(c):
        for item in c["supported_claims"]:
            if item["slot"] == "deployment_region":
                item["value"] = "us-west-2"

    def alter_claim(c):
        for item in c["supported_claims"]:
            if item["slot"] == "deployment_region":
                item["value"] = "eu-west-1"

    def drop_contradiction(c):
        c["contradictions"] = []

    def empty(c):
        for key in ("supported_claims", "current_constraints", "confirmed_outcomes", "unresolved_questions", "contradictions", "tombstones", "evidence_references"):
            c[key] = []

    def extra_material(c):
        c["producer_note"] = "harmless extra material"

    variant("drop_constraint", drop_constraint)
    variant("drop_question", drop_question)
    variant("drop_tombstone", drop_tombstone)
    variant("resurrect", resurrect)
    variant("alter_claim", alter_claim)
    variant("drop_contradiction", drop_contradiction)
    variant("empty", empty)
    variant("extra_material", extra_material)

    # J: mutate candidate bytes after the manifest was created (keep GOOD manifest).
    mutated = copy.deepcopy(good)
    mutated["objective"] = OBJECTIVE + " (mutated after manifest)"
    write_json(OUT / "candidate_mutated.json", mutated)

    # K: alter the manifest binding itself (keep GOOD candidate).
    bad_manifest = build_candidate_manifest(good, checkpoint, producer_label="fixture-producer")
    digest = bad_manifest["checkpoint_hash"]
    bad_manifest["checkpoint_hash"] = ("0" if digest[0] != "0" else "1") + digest[1:]
    write_json(OUT / "candidate_manifest_mutated.json", bad_manifest)

    # Sanity: the good candidate must project identically to the derivation.
    from openline_half_life.compaction import compact_projection
    from openline_half_life.reference_replay import reference_projection

    assert compact_projection(good) == reference_projection(turns, checkpoint_turn), "good fixture must preserve the projection"
    assert candidate_state_hash(good) == load_json(OUT / "candidate_manifest_good.json")["candidate_hash"]
    print(f"wrote {len(list(OUT.glob('*.json*')))} fixture files to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
