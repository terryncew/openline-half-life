from __future__ import annotations

import json

import pytest

from openline_half_life.schema import load_trajectory


def test_schema_rejects_cross_turn_evidence_hash_rebinding(root, tmp_path):
    rows = [json.loads(line) for line in (root / "fixtures/healthy.jsonl").read_text().splitlines()]
    evidence_id = rows[0]["evidence"][0]["id"]
    rows[1]["evidence"].append(
        {
            "id": evidence_id,
            "sha256": "d" * 64,
            "observed_turn": 2,
            "expires_after_turns": 10,
        }
    )
    path = tmp_path / "rebound.jsonl"
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    with pytest.raises(ValueError, match="evidence_id_rebound"):
        load_trajectory(path)


def test_evidence_observation_cannot_claim_a_different_turn(root, tmp_path):
    rows = [json.loads(line) for line in (root / "fixtures/healthy.jsonl").read_text().splitlines()]
    rows[1]["evidence"].append(
        {
            "id": "replayed-old-observation",
            "sha256": "c" * 64,
            "observed_turn": 1,
            "expires_after_turns": 100,
        }
    )
    path = tmp_path / "replay.jsonl"
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    with pytest.raises(ValueError, match="observed_turn must equal"):
        load_trajectory(path)
