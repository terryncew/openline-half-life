"""Evidence-closure tests for candidate admission (HALF-LIFE-CANDIDATE-ADMISSION-002).

The evidence-closure invariant (frozen in EVIDENCE_CLOSURE_CONTRACT_002.md):
every evidence reference relied on by protected candidate state must resolve
to an evidence object carried in the candidate that is content-identical to
the source-bound evidence from the verified source history.

Discrimination set (preregistered in EVIDENCE_CLOSURE_PREREGISTRATION_002.md):
  D1 001 evidence-deletion counterexample (frozen, unmodified) -> REFUSE
  D2 same evidence ID, altered contents -> REFUSE
  D3 compiler-different candidate preserving required evidence -> ADMIT
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from openline_half_life.candidate_admission import (
    AdmissionRejected,
    check_evidence_closure,
)
from openline_half_life.pipeline import admit_pipeline, verify_admission_output_directory
from openline_half_life.reference_replay import source_evidence_index
from openline_half_life.schema import load_trajectory
from openline_half_life.util import load_json

from test_candidate_admission import (
    FIXTURES,
    POLICY,
    POLICY_KEYS,
    ROOT,
    REPLAY_LATENCY_MICROS,
    _policy_public_keys,
    admission_kwargs,
)

CHECKPOINT_TURN = 6
FROZEN_P5 = ROOT / "evidence" / "frozen-failures" / "p5-evidence-refs-emptied"


def _source_evidence():
    turns = load_trajectory(FIXTURES / "history.jsonl")
    return source_evidence_index(turns, CHECKPOINT_TURN)


def test_check_evidence_closure_good_candidate_passes():
    candidate = load_json(FIXTURES / "candidate_good.json")
    result = check_evidence_closure(candidate, _source_evidence())
    assert result["valid"] is True
    assert result["mismatches"] == []


def test_check_evidence_closure_emptied_refs_fails():
    candidate = dict(load_json(FIXTURES / "candidate_good.json"))
    candidate["evidence_references"] = []
    result = check_evidence_closure(candidate, _source_evidence())
    assert result["valid"] is False
    ids = {entry["evidence_id"] for entry in result["mismatches"]}
    assert ids == {"ev-batch-1", "ev-constraint-1", "ev-outcome-1", "ev-region-2"}
    assert {entry["reason"] for entry in result["mismatches"]} == {"evidence_not_carried"}


def test_check_evidence_closure_altered_contents_fails():
    candidate = load_json(FIXTURES / "candidate_evidence_altered.json")
    result = check_evidence_closure(candidate, _source_evidence())
    assert result["valid"] is False
    assert result["mismatches"] == [
        {"evidence_id": "ev-batch-1", "reason": "evidence_altered"}
    ]


def test_check_evidence_closure_ambiguous_duplicates_fail():
    candidate = load_json(FIXTURES / "candidate_good.json")
    candidate = dict(candidate)
    dup = dict(candidate["evidence_references"][0])
    dup["sha256"] = "1" * 64
    candidate["evidence_references"] = [*candidate["evidence_references"], dup]
    result = check_evidence_closure(candidate, _source_evidence())
    assert result["valid"] is False
    assert {"evidence_id": dup["id"], "reason": "evidence_ambiguous"} in result["mismatches"]


def test_d1_frozen_p5_counterexample_refused_unmodified(tmp_path):
    # The 001 frozen counterexample, read-only, run exactly as frozen.
    assert (FROZEN_P5 / "candidate_p5.json").is_file()
    assert (FROZEN_P5 / "manifest_p5.json").is_file()
    kwargs = admission_kwargs("good", "good", out=tmp_path / "out")
    kwargs["candidate_path"] = FROZEN_P5 / "candidate_p5.json"
    kwargs["manifest_path"] = FROZEN_P5 / "manifest_p5.json"
    with pytest.raises(AdmissionRejected) as exc_info:
        admit_pipeline(**kwargs)
    assert "evidence_closure_failed" in exc_info.value.reason_codes
    mismatches = exc_info.value.report["mismatches"]
    ids = {entry["evidence_id"] for entry in mismatches}
    assert ids == {"ev-batch-1", "ev-constraint-1", "ev-outcome-1", "ev-region-2"}
    assert all(entry["reason"] == "evidence_not_carried" for entry in mismatches)
    assert exc_info.value.report["accepted"] is False


def test_d2_altered_evidence_contents_refused(tmp_path):
    with pytest.raises(AdmissionRejected) as exc_info:
        admit_pipeline(**admission_kwargs("evidence_altered", "evidence_altered", out=tmp_path / "out"))
    assert "evidence_closure_failed" in exc_info.value.reason_codes
    assert exc_info.value.report["mismatches"] == [
        {"evidence_id": "ev-batch-1", "reason": "evidence_altered"}
    ]


def test_d3_compiler_different_candidate_admitted(tmp_path):
    result = admit_pipeline(
        **admission_kwargs("compiler_different", "compiler_different", out=tmp_path / "out")
    )
    assert result["passed"] is True
    assert result["accepted"] is True
    assert result["decision_mismatch_count"] == 0
    # Evidence closure held on the admitted package: carried evidence matches
    # the source-bound evidence.
    admitted = json.loads((tmp_path / "out" / "compact_state.json").read_text())
    closure = check_evidence_closure(admitted, _source_evidence())
    assert closure["valid"] is True
    verification = verify_admission_output_directory(
        tmp_path / "out", expected_policy_public_keys=_policy_public_keys()
    )
    assert verification["valid"] is True
    # This candidate is genuinely different from the good fixture: the repair
    # is not byte identity with any single byte layout.
    good_hash = json.loads((tmp_path / "out" / "admission_receipt.json").read_text())["payload"]
    other = load_json(FIXTURES / "candidate_compiler_different.json")
    proposed = load_json(FIXTURES / "candidate_good.json")
    from openline_half_life.candidate_admission import candidate_state_hash

    assert candidate_state_hash(other) != candidate_state_hash(proposed)
    assert good_hash["candidate_hash"] == candidate_state_hash(other)
