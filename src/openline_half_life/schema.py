from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Mapping

from .util import load_jsonl

TURN_SCHEMA = "openline.half-life.turn.v2"
HASH256 = re.compile(r"^[0-9a-f]{64}$")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_turn(turn: Mapping[str, Any], expected_turn: int | None = None) -> dict[str, Any]:
    required = {
        "schema", "run_id", "turn", "objective", "summary", "claims", "evidence",
        "constraints", "outcomes", "unresolved_questions", "cost",
    }
    _require(set(turn) == required, f"turn field mismatch: {sorted(set(turn) ^ required)}")
    _require(turn["schema"] == TURN_SCHEMA, "unsupported turn schema")
    _require(isinstance(turn["run_id"], str) and turn["run_id"], "run_id must be non-empty")
    _require(isinstance(turn["turn"], int) and not isinstance(turn["turn"], bool), "turn must be an integer")
    if expected_turn is not None:
        _require(turn["turn"] == expected_turn, f"turn sequence must be contiguous; expected {expected_turn}")
    _require(isinstance(turn["objective"], str) and turn["objective"], "objective must be non-empty")
    _require(isinstance(turn["summary"], str), "summary must be a string")

    evidence = turn["evidence"]
    _require(isinstance(evidence, list), "evidence must be an array")
    seen: set[str] = set()
    for item in evidence:
        _require(isinstance(item, Mapping), "evidence item must be an object")
        _require(set(item) == {"id", "sha256", "observed_turn", "expires_after_turns"}, "evidence field mismatch")
        _require(isinstance(item["id"], str) and item["id"], "evidence id must be non-empty")
        _require(item["id"] not in seen, "duplicate evidence id within turn")
        seen.add(item["id"])
        _require(isinstance(item["sha256"], str) and HASH256.fullmatch(item["sha256"]) is not None, "invalid evidence hash")
        _require(item["observed_turn"] == turn["turn"], "evidence observed_turn must equal containing turn")
        _require(isinstance(item["expires_after_turns"], int) and not isinstance(item["expires_after_turns"], bool) and item["expires_after_turns"] >= 0, "invalid evidence expiry")

    claims = turn["claims"]
    _require(isinstance(claims, list), "claims must be an array")
    for claim in claims:
        _require(isinstance(claim, Mapping), "claim must be an object")
        _require(set(claim) == {"id", "slot", "value", "material", "support_status", "evidence_refs", "last_verified_turn"}, "claim field mismatch")
        _require(isinstance(claim["id"], str) and claim["id"], "claim id must be non-empty")
        _require(isinstance(claim["slot"], str) and claim["slot"], "claim slot must be non-empty")
        _require(isinstance(claim["material"], bool), "claim material must be boolean")
        _require(claim["support_status"] in {"supported", "unsupported", "unresolved"}, "invalid claim support_status")
        _require(isinstance(claim["evidence_refs"], list) and all(isinstance(ref, str) and ref for ref in claim["evidence_refs"]), "claim evidence_refs invalid")
        _require(isinstance(claim["last_verified_turn"], int) and not isinstance(claim["last_verified_turn"], bool) and 1 <= claim["last_verified_turn"] <= turn["turn"], "claim last_verified_turn invalid")

    constraints = turn["constraints"]
    _require(isinstance(constraints, list), "constraints must be an array")
    for item in constraints:
        _require(isinstance(item, Mapping), "constraint must be an object")
        _require(set(item) == {"id", "text", "active", "evidence_refs", "last_verified_turn"}, "constraint field mismatch")
        _require(isinstance(item["id"], str) and item["id"], "constraint id must be non-empty")
        _require(isinstance(item["text"], str), "constraint text must be a string")
        _require(isinstance(item["active"], bool), "constraint active must be boolean")
        _require(isinstance(item["evidence_refs"], list) and all(isinstance(ref, str) and ref for ref in item["evidence_refs"]), "constraint evidence_refs invalid")
        _require(isinstance(item["last_verified_turn"], int) and not isinstance(item["last_verified_turn"], bool) and 1 <= item["last_verified_turn"] <= turn["turn"], "constraint last_verified_turn invalid")

    outcomes = turn["outcomes"]
    _require(isinstance(outcomes, list), "outcomes must be an array")
    for item in outcomes:
        _require(isinstance(item, Mapping), "outcome must be an object")
        _require(set(item) == {"id", "text", "confirmed", "evidence_refs"}, "outcome field mismatch")
        _require(isinstance(item["id"], str) and item["id"], "outcome id must be non-empty")
        _require(isinstance(item["text"], str), "outcome text must be a string")
        _require(isinstance(item["confirmed"], bool), "outcome confirmed must be boolean")
        _require(isinstance(item["evidence_refs"], list) and all(isinstance(ref, str) and ref for ref in item["evidence_refs"]), "outcome evidence_refs invalid")

    _require(isinstance(turn["unresolved_questions"], list) and all(isinstance(item, str) for item in turn["unresolved_questions"]), "unresolved_questions invalid")
    cost = turn["cost"]
    _require(isinstance(cost, Mapping) and set(cost) == {"input_tokens", "output_tokens"}, "cost field mismatch")
    _require(all(isinstance(cost[name], int) and not isinstance(cost[name], bool) and cost[name] >= 0 for name in cost), "cost values invalid")
    return dict(turn)


def load_trajectory(path: Path) -> list[dict[str, Any]]:
    rows = load_jsonl(path)
    _require(bool(rows), "trajectory must contain at least one turn")
    run_id = rows[0].get("run_id")
    normalized = [validate_turn(row, expected_turn=index) for index, row in enumerate(rows, 1)]
    _require(all(row["run_id"] == run_id for row in normalized), "trajectory cannot cross run_id boundaries")
    evidence_hashes: dict[str, str] = {}
    for row in normalized:
        for item in row["evidence"]:
            prior = evidence_hashes.setdefault(item["id"], item["sha256"])
            _require(prior == item["sha256"], f"evidence id rebound to different bytes: {item['id']}")
    return normalized
