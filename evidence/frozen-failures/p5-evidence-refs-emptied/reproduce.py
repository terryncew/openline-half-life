"""Frozen counterexample reproducer: P5 emptied evidence_references admitted.

This is NOT a development test and is NOT wired into pytest. It documents the
frozen FAIL — CANDIDATE ADMISSION ALLOWED LOSS OF REQUIRED EVIDENCE-REFERENCE
STATE (2026-09-20, branch feat/compiler-neutral-admission-001).

Run:  cd <repo root> && PYTHONPATH=src python3 \\
        evidence/frozen-failures/p5-evidence-refs-emptied/reproduce.py

Exit 0 means the frozen behavior reproduces (admission accepted, 0 mismatches).
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
FIX = REPO / "tests" / "fixtures" / "candidate_admission"

sys.path.insert(0, str(REPO / "src"))

from openline_half_life.candidate_admission import build_candidate_manifest  # noqa: E402
from openline_half_life.compaction import build_checkpoint  # noqa: E402
from openline_half_life.pipeline import admit_pipeline  # noqa: E402
from openline_half_life.schema import load_trajectory  # noqa: E402
from openline_half_life.util import load_json  # noqa: E402


def main() -> None:
    turns = load_trajectory(FIX / "history.jsonl")
    policy = load_json(REPO / "policy" / "compaction_policy.json")
    checkpoint = build_checkpoint(turns, 6, policy["payload_hash"])

    good = load_json(FIX / "candidate_good.json")
    assert len(good["evidence_references"]) == 4, "good fixture changed; frozen record invalid"

    p5 = dict(good, evidence_references=[])

    tmp = Path(tempfile.mkdtemp(prefix="p5-frozen-repro-"))
    candidate_path = tmp / "candidate_p5.json"
    manifest_path = tmp / "manifest_p5.json"
    candidate_path.write_text(json.dumps(p5, indent=2, sort_keys=True) + "\n")
    manifest = build_candidate_manifest(p5, checkpoint, producer_label="perturbation-attack-p5")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    result = admit_pipeline(
        FIX / "history.jsonl",
        candidate_path,
        manifest_path,
        REPO / "fixtures" / "demo_source_signing_key.hex",
        tmp / "out",
        compaction_policy_path=REPO / "policy" / "compaction_policy.json",
        compaction_policy_public_key_path=REPO / "policy" / "compaction_policy_public_key.hex",
        operator_approval_signing_key_path=REPO / "fixtures" / "demo_operator_approval_key.hex",
        replay_latency_micros=75000,
        operator_disposition="APPROVE",
    )
    admitted = load_json(tmp / "out" / "compact_state.json")
    shutil.rmtree(tmp, ignore_errors=True)

    print("accepted:", result["accepted"])
    print("decision_mismatch_count:", result["decision_mismatch_count"])
    print("admitted compact_state evidence_references:", len(admitted["evidence_references"]))
    assert result["accepted"] is True
    assert result["decision_mismatch_count"] == 0
    assert len(admitted["evidence_references"]) == 0
    print("FROZEN FAIL REPRODUCED: evidence loss admitted with zero mismatches")


if __name__ == "__main__":
    main()
