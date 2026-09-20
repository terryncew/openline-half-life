"""Context-admit discrimination (003): is continued use of an admitted compact
context conditioned on the standing of its evidence dependencies?

Preregistered in CONTEXT_ADMIT_PREREGISTRATION_003.md before any fixture was
generated. Discrimination only: no source-code changes, no repairs.

Case 1: candidate preserving a live constraint + unresolved contradiction +
evidence closure -> admit (positive control, frozen 001 fixtures).
Case 2: same candidate drops the constraint or the contradiction -> refuse
(two runs, frozen 001 fixtures).
Case 3: admitted context at checkpoint 6; at checkpoint 7 the required
evidence ev-c-short goes stale under existing _fresh semantics ->
tombstone:constraint:c-live appears; the admitted context is detectably
invalid against the turn-7 source truth; re-admission at checkpoint 7
(rehydration) succeeds.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from openline_half_life.candidate_admission import AdmissionRejected
from openline_half_life.compaction import compact_projection, decision_equivalence_report
from openline_half_life.pipeline import admit_pipeline, verify_admission_output_directory
from openline_half_life.reference_replay import reference_projection
from openline_half_life.schema import load_trajectory
from openline_half_life.util import canonical_json, load_json, sha256_bytes

FIXTURES = Path(__file__).parent / "fixtures" / "candidate_admission"
ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "policy" / "compaction_policy.json"
POLICY_KEYS = ROOT / "policy" / "compaction_policy_public_key.hex"
REPLAY_LATENCY_MICROS = 2_000_000
C3_HISTORY = FIXTURES / "context3_history.jsonl"


def _policy_public_keys() -> set[str]:
    return {line.strip() for line in POLICY_KEYS.read_text(encoding="ascii").splitlines() if line.strip() and not line.lstrip().startswith("#")}


def _admit(candidate: Path, manifest: Path, trajectory: Path, *, out: Path):
    return admit_pipeline(
        trajectory_path=trajectory,
        candidate_path=candidate,
        manifest_path=manifest,
        source_signing_key_path=ROOT / "fixtures" / "demo_source_signing_key.hex",
        output_dir=out,
        compaction_policy_path=POLICY,
        compaction_policy_public_key_path=POLICY_KEYS,
        operator_approval_signing_key_path=ROOT / "fixtures" / "demo_operator_approval_key.hex",
        replay_latency_micros=REPLAY_LATENCY_MICROS,
        operator_disposition="APPROVE",
    )


# Case 1: positive control on the frozen 001 fixtures.
def test_case1_admit_positive_control(tmp_path):
    result = _admit(
        FIXTURES / "candidate_good.json",
        FIXTURES / "candidate_manifest_good.json",
        FIXTURES / "history.jsonl",
        out=tmp_path / "out",
    )
    assert result["accepted"] is True
    assert result["decision_mismatch_count"] == 0
    proposed = load_json(FIXTURES / "candidate_good.json")
    assert [c["id"] for c in proposed["current_constraints"]] == ["c-budget"]
    assert [c["id"] for c in proposed["contradictions"]] == ["claim-slot:cache_ttl:4"]
    verification = verify_admission_output_directory(tmp_path / "out", expected_policy_public_keys=_policy_public_keys())
    assert verification["valid"] is True


# Case 2a: drop the live constraint -> refuse.
def test_case2a_drop_constraint_refused(tmp_path):
    with pytest.raises(AdmissionRejected) as exc_info:
        _admit(
            FIXTURES / "candidate_drop_constraint.json",
            FIXTURES / "candidate_manifest_drop_constraint.json",
            FIXTURES / "history.jsonl",
            out=tmp_path / "out",
        )
    assert "decision_equivalence_failed" in exc_info.value.reason_codes


# Case 2b: drop the unresolved contradiction -> refuse.
def test_case2b_drop_contradiction_refused(tmp_path):
    with pytest.raises(AdmissionRejected) as exc_info:
        _admit(
            FIXTURES / "candidate_drop_contradiction.json",
            FIXTURES / "candidate_manifest_drop_contradiction.json",
            FIXTURES / "history.jsonl",
            out=tmp_path / "out",
        )
    assert "decision_equivalence_failed" in exc_info.value.reason_codes


# Case 3a: admit the case-3 candidate at checkpoint 6 (positive control for
# the new fixture: live constraint + contradiction + evidence closure).
def test_case3a_admit_at_checkpoint6(tmp_path):
    result = _admit(
        FIXTURES / "context3_candidate_good.json",
        FIXTURES / "context3_candidate_manifest_good.json",
        C3_HISTORY,
        out=tmp_path / "out",
    )
    assert result["accepted"] is True
    assert result["decision_mismatch_count"] == 0
    assert result["checkpoint_turn"] == 6
    verification = verify_admission_output_directory(tmp_path / "out", expected_policy_public_keys=_policy_public_keys())
    assert verification["valid"] is True


# Case 3b: at checkpoint 7 the required evidence ev-c-short is stale under
# existing _fresh semantics. The admitted checkpoint-6 context is detectably
# invalid against the turn-7 source truth, using only existing functions.
def test_case3b_continued_use_invalidated_at_checkpoint7(tmp_path):
    _admit(
        FIXTURES / "context3_candidate_good.json",
        FIXTURES / "context3_candidate_manifest_good.json",
        C3_HISTORY,
        out=tmp_path / "out",
    )
    admitted = load_json(tmp_path / "out" / "compact_state.json")
    bundle = load_json(tmp_path / "out" / "receipt_bundle.json")
    active_bytes = len(canonical_json(bundle["source_chain"]))

    turns = load_trajectory(C3_HISTORY)
    reference7 = reference_projection(turns, 7)

    # The invalidation signal comes from existing standing machinery:
    # ev-c-short (observed 5, expires_after_turns=1) is stale at turn 7.
    assert reference7["tombstone:constraint:c-live"] == {"disposition": "DENY", "status": "stale"}
    assert "constraint:c-live" not in reference7

    report = decision_equivalence_report(reference7, admitted, source_chain_active_bytes=active_bytes)
    assert report["passed"] is False
    keys = {m["decision_key"] for m in report["mismatches"]}
    assert "constraint:c-live" in keys
    assert "tombstone:constraint:c-live" in keys
    # Nothing else moved: exactly the evidence-expiry case, nothing broader.
    assert keys == {"constraint:c-live", "tombstone:constraint:c-live"}

    # The compact context still projects exactly like the admitted candidate;
    # the mismatch is against the NEW source truth, not tampering.
    assert compact_projection(admitted) == compact_projection(load_json(FIXTURES / "context3_candidate_good.json"))
    # The carried rehydration conditions name exactly this situation.
    assert "evidence_revoked" in admitted["rehydration_conditions"]
    assert "decision_mismatch" in admitted["rehydration_conditions"]


# Case 3c: rehydration — re-run admission at checkpoint 7 with the corrected
# candidate (c-live tombstoned stale, not live). Existing machinery only.
def test_case3c_rehydration_at_checkpoint7(tmp_path):
    result = _admit(
        FIXTURES / "context3_candidate_rehydrated.json",
        FIXTURES / "context3_candidate_manifest_rehydrated.json",
        C3_HISTORY,
        out=tmp_path / "out",
    )
    assert result["accepted"] is True
    assert result["decision_mismatch_count"] == 0
    assert result["checkpoint_turn"] == 7
    verification = verify_admission_output_directory(tmp_path / "out", expected_policy_public_keys=_policy_public_keys())
    assert verification["valid"] is True
    admitted = load_json(tmp_path / "out" / "compact_state.json")
    assert [c["id"] for c in admitted["current_constraints"]] == []
    assert any(t["identity"] == "constraint:c-live" and t["status"] == "stale" for t in admitted["tombstones"])
    # The refreshed context agrees with the turn-7 source truth.
    turns = load_trajectory(C3_HISTORY)
    reference7 = reference_projection(turns, 7)
    bundle = load_json(tmp_path / "out" / "receipt_bundle.json")
    report = decision_equivalence_report(reference7, admitted, source_chain_active_bytes=len(canonical_json(bundle["source_chain"])))
    assert report["passed"] is True
    assert sha256_bytes(canonical_json(dict(sorted(reference7.items())))) == report["full_history_decision_hash"]
