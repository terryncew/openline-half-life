from __future__ import annotations

import copy
from pathlib import Path

from openline_half_life.compaction import candidate_hits_tombstone, compact_projection, derive_compact_state
from openline_half_life.reference_replay import reference_projection
from openline_half_life.schema import load_trajectory


def test_independent_projection_matches_compact_state(root: Path):
    turns = load_trajectory(root / "fixtures/demo_trajectory.jsonl")
    state = derive_compact_state(turns, len(turns))
    assert compact_projection(state) == reference_projection(turns, len(turns))


def test_stale_material_becomes_tombstone(root: Path):
    turns = load_trajectory(root / "fixtures/demo_trajectory.jsonl")
    state = derive_compact_state(turns, len(turns))
    assert any(item["status"] == "stale" for item in state["tombstones"])


def test_superseded_claim_cannot_replay():
    from scripts.seeded_gate import build_history
    turns = build_history(1)
    state = derive_compact_state(turns, len(turns))
    assert candidate_hits_tombstone(state, {"item_type": "claim", "slot": "version", "value": "v1", "item_id": "version-v1"})


def test_conflicting_latest_claims_quarantine(root: Path):
    turns = load_trajectory(root / "fixtures/demo_trajectory.jsonl")[:3]
    base = copy.deepcopy(turns[-1])
    ev = {"id": "ev-conflict", "sha256": "e" * 64, "observed_turn": 3, "expires_after_turns": 100}
    base["evidence"].append(ev)
    base["claims"].extend([
        {"id": "a", "slot": "conflict-slot", "value": "x", "material": True, "support_status": "supported", "evidence_refs": ["ev-conflict"], "last_verified_turn": 3},
        {"id": "b", "slot": "conflict-slot", "value": "y", "material": True, "support_status": "supported", "evidence_refs": ["ev-conflict"], "last_verified_turn": 3},
    ])
    turns[-1] = base
    state = derive_compact_state(turns, 3)
    assert any(item["slot"] == "conflict-slot" for item in state["contradictions"])
    assert not any(item["slot"] == "conflict-slot" for item in state["supported_claims"])
