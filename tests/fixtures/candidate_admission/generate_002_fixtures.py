#!/usr/bin/env python3
"""Generate the frozen 002 evidence-closure fixtures.

Deterministic. No randomness, no network, no model calls.

Produces, under tests/fixtures/candidate_admission/:
  candidate_evidence_altered.json       good candidate with ev-batch-1's
                                       contents changed (same ID)
  candidate_manifest_evidence_altered.json
  candidate_compiler_different.json     hand-arranged candidate: same protected
                                       contents as the good candidate, different
                                       shape (reordered collections)
  candidate_manifest_compiler_different.json

Inputs (good candidate, history, policy, checkpoint) are the frozen 001
fixtures; they are read, never altered.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from openline_half_life.candidate_admission import build_candidate_manifest
from openline_half_life.compaction import build_checkpoint
from openline_half_life.schema import load_trajectory
from openline_half_life.util import load_json

OUT = Path(__file__).resolve().parent
POLICY_HASH = load_json(ROOT / "policy" / "compaction_policy.json")["payload_hash"]
CHECKPOINT_TURN = 6


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def manifest_for(candidate: dict) -> dict:
    turns = load_trajectory(OUT / "history.jsonl")
    checkpoint = build_checkpoint(turns, CHECKPOINT_TURN, POLICY_HASH)
    return build_candidate_manifest(
        candidate, checkpoint, producer_label="evidence-closure-fixture-producer"
    )


def main() -> int:
    good = load_json(OUT / "candidate_good.json")

    # D2: same evidence ID, altered contents.
    altered = copy.deepcopy(good)
    for item in altered["evidence_references"]:
        if item["id"] == "ev-batch-1":
            item["sha256"] = "0" * 64  # valid hex shape, wrong content binding
    write_json(OUT / "candidate_evidence_altered.json", altered)
    write_json(OUT / "candidate_manifest_evidence_altered.json", manifest_for(altered))

    # D3: same protected contents, different compiler shape. Reorder
    # collections and shuffle key insertion order; array order changes the
    # canonical candidate hash, so this is a genuinely different candidate.
    different = copy.deepcopy(good)
    different["supported_claims"] = list(reversed(different["supported_claims"]))
    different["current_constraints"] = list(reversed(different["current_constraints"]))
    different["confirmed_outcomes"] = list(reversed(different["confirmed_outcomes"]))
    different["tombstones"] = list(reversed(different["tombstones"]))
    different["evidence_references"] = list(reversed(different["evidence_references"]))
    for item in different["evidence_references"]:
        reordered = {k: item[k] for k in reversed(list(item))}
        item.clear()
        item.update(reordered)
    for collection in (
        different["supported_claims"],
        different["current_constraints"],
        different["confirmed_outcomes"],
    ):
        for item in collection:
            if isinstance(item.get("evidence_refs"), list):
                item["evidence_refs"] = list(reversed(item["evidence_refs"]))
    write_json(OUT / "candidate_compiler_different.json", different)
    write_json(OUT / "candidate_manifest_compiler_different.json", manifest_for(different))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
