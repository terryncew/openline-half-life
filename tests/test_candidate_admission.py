"""Tests for the compiler-neutral candidate-admission doorway.

The candidate is an externally produced compact state: untrusted input. The
admission boundary admits it only when Half-Life's existing independent
decision replay says the receiver-required projection survived.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from openline_half_life import __version__
from openline_half_life.candidate_admission import (
    ADMISSION_RECEIPT_SCHEMA,
    AdmissionRejected,
    build_candidate_manifest,
    candidate_state_hash,
)
from openline_half_life.compaction import build_checkpoint, compact_projection
from openline_half_life.pipeline import (
    ADMISSION_BUNDLE_SCHEMA,
    admit_pipeline,
    verify_admission_output_directory,
)
from openline_half_life.schema import load_trajectory
from openline_half_life.util import load_json, sha256_file

FIXTURES = Path(__file__).parent / "fixtures" / "candidate_admission"
ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "policy" / "compaction_policy.json"
POLICY_KEYS = ROOT / "policy" / "compaction_policy_public_key.hex"
REPLAY_LATENCY_MICROS = 2_000_000


def _policy_public_keys() -> set[str]:
    return {line.strip() for line in POLICY_KEYS.read_text(encoding="ascii").splitlines() if line.strip() and not line.lstrip().startswith("#")}


def policy_hash() -> str:
    return load_json(POLICY)["payload_hash"]


def admission_kwargs(candidate: str, manifest: str, *, out: Path):
    return {
        "trajectory_path": FIXTURES / "history.jsonl",
        "candidate_path": FIXTURES / f"candidate_{candidate}.json",
        "manifest_path": FIXTURES / f"candidate_manifest_{manifest}.json",
        "source_signing_key_path": ROOT / "fixtures" / "demo_source_signing_key.hex",
        "output_dir": out,
        "compaction_policy_path": POLICY,
        "compaction_policy_public_key_path": POLICY_KEYS,
        "operator_approval_signing_key_path": ROOT / "fixtures" / "demo_operator_approval_key.hex",
        "replay_latency_micros": REPLAY_LATENCY_MICROS,
        "operator_disposition": "APPROVE",
    }


def test_admit_good_candidate(tmp_path):
    result = admit_pipeline(**admission_kwargs("good", "good", out=tmp_path / "out"))
    assert result["passed"] is True
    assert result["accepted"] is True
    assert result["decision_equivalence_passed"] is True
    assert result["decision_mismatch_count"] == 0

    # The admitted state projects exactly like the untrusted candidate did.
    admitted = json.loads((tmp_path / "out" / "compact_state.json").read_text())
    proposed = json.loads((FIXTURES / "candidate_good.json").read_text())
    assert compact_projection(admitted) == compact_projection(proposed)

    # The verification receipt binds the candidate, not just the admitted state.
    receipt = json.loads((tmp_path / "out" / "admission_receipt.json").read_text())
    assert receipt["payload"]["schema"] == ADMISSION_RECEIPT_SCHEMA
    assert receipt["payload"]["candidate_hash"] == candidate_state_hash(proposed)
    bundle = json.loads((tmp_path / "out" / "receipt_bundle.json").read_text())
    assert bundle["schema"] == ADMISSION_BUNDLE_SCHEMA
    assert bundle["bundle_hash"] == result["bundle_hash"]

    # Archive custody intact, operator approval recorded.
    assert result["archive_receipt_count"] == len(bundle["source_chain"]) > 0
    approval = json.loads((tmp_path / "out" / "operator_approval.json").read_text())
    assert approval["disposition"] == "APPROVE"

    verification = verify_admission_output_directory(
        tmp_path / "out",
        expected_policy_public_keys=_policy_public_keys(),
    )
    assert verification["valid"] is True
    assert verification["decision_equivalence_passed"] is True
    assert verification["bundle_hash"] == result["bundle_hash"]


@pytest.mark.parametrize(
    "variant,expected_code",
    [
        ("drop_constraint", "decision_equivalence_failed"),
        ("drop_question", "decision_equivalence_failed"),
        ("drop_tombstone", "decision_equivalence_failed"),
        ("resurrect", "decision_equivalence_failed"),
        ("alter_claim", "decision_equivalence_failed"),
        ("drop_contradiction", "decision_equivalence_failed"),
        ("empty", "decision_equivalence_failed"),
        ("extra_material", "candidate_schema_invalid"),
    ],
)
def test_admit_protected_corruption_rejected(tmp_path, variant, expected_code):
    with pytest.raises(AdmissionRejected) as exc_info:
        admit_pipeline(**admission_kwargs(variant, variant, out=tmp_path / "out"))
    assert expected_code in exc_info.value.reason_codes
    report = exc_info.value.report
    assert report["accepted"] is False
    assert report["schema"].endswith("admission-rejection.v1")


def test_admit_mutated_candidate_bytes_rejected(tmp_path):
    with pytest.raises(AdmissionRejected) as exc_info:
        admit_pipeline(**admission_kwargs("mutated", "good", out=tmp_path / "out"))
    assert "manifest_binding_mismatch" in exc_info.value.reason_codes


def test_admit_mutated_manifest_rejected(tmp_path):
    with pytest.raises(AdmissionRejected) as exc_info:
        admit_pipeline(**admission_kwargs("good", "mutated", out=tmp_path / "out"))
    assert "manifest_binding_mismatch" in exc_info.value.reason_codes


def test_admit_wrong_source_binding_rejected(tmp_path):
    other_kwargs = dict(admission_kwargs("good", "good", out=tmp_path / "out"))
    other_kwargs["trajectory_path"] = FIXTURES / "history_other.jsonl"
    with pytest.raises(AdmissionRejected) as exc_info:
        admit_pipeline(**other_kwargs)
    assert "manifest_binding_mismatch" in exc_info.value.reason_codes


def test_admit_rejection_report_matches_candidate_projection(tmp_path):
    with pytest.raises(AdmissionRejected) as exc_info:
        admit_pipeline(**admission_kwargs("drop_constraint", "drop_constraint", out=tmp_path / "out"))
    mismatches = exc_info.value.report["mismatches"]
    keys = {entry["decision_key"] for entry in mismatches}
    assert any(key.startswith("constraint:") for key in keys)
    entries = [entry for entry in mismatches if entry["decision_key"] in keys and entry["decision_key"].startswith("constraint:")]
    assert all("c-budget" in entry["full_history"].get("id", "") or "c-budget" in str(entry) for entry in entries)


def test_admit_invalid_manifest_rejected(tmp_path):
    manifest_path = tmp_path / "manifest_invalid.json"
    manifest = json.loads((FIXTURES / "candidate_manifest_good.json").read_text())
    manifest["producer_label"] = 42
    manifest_path.write_text(json.dumps(manifest))
    kwargs = admission_kwargs("good", "good", out=tmp_path / "out")
    kwargs["manifest_path"] = manifest_path
    with pytest.raises(AdmissionRejected) as exc_info:
        admit_pipeline(**kwargs)
    assert "manifest_invalid" in exc_info.value.reason_codes


def test_admit_invalid_candidate_schema_rejected(tmp_path):
    candidate_path = tmp_path / "candidate_invalid.json"
    candidate = json.loads((FIXTURES / "candidate_good.json").read_text())
    del candidate["schema"]
    candidate_path.write_text(json.dumps(candidate))
    manifest = build_candidate_manifest(candidate, build_checkpoint(load_trajectory(FIXTURES / "history.jsonl"), 6, policy_hash()), producer_label="fixture-producer")
    manifest_path = tmp_path / "manifest_invalid.json"
    manifest_path.write_text(json.dumps(manifest))
    kwargs = admission_kwargs("good", "good", out=tmp_path / "out")
    kwargs["candidate_path"] = candidate_path
    kwargs["manifest_path"] = manifest_path
    with pytest.raises(AdmissionRejected) as exc_info:
        admit_pipeline(**kwargs)
    assert "candidate_schema_invalid" in exc_info.value.reason_codes


def test_admit_denied_operator_disposition_preserved(tmp_path):
    kwargs = admission_kwargs("good", "good", out=tmp_path / "out")
    kwargs["operator_disposition"] = "DENY"
    with pytest.raises(ValueError, match="operator approval verification failed"):
        admit_pipeline(**kwargs)


def test_admit_version_is_package_version(tmp_path):
    result = admit_pipeline(**admission_kwargs("good", "good", out=tmp_path / "out"))
    assert result["version"] == __version__


def test_verify_admission_detects_candidate_tamper(tmp_path):
    result = admit_pipeline(**admission_kwargs("good", "good", out=tmp_path / "out"))
    assert result["passed"] is True
    candidate_path = tmp_path / "out" / "candidate.json"
    candidate = json.loads(candidate_path.read_text())
    candidate["supported_claims"][0]["value"] = "tampered-region"
    candidate_path.write_text(json.dumps(candidate, indent=2, sort_keys=True))
    verification = verify_admission_output_directory(
        tmp_path / "out",
        expected_policy_public_keys=_policy_public_keys(),
    )
    assert verification["valid"] is False
    assert any("candidate" in item or "equivalence" in item for item in verification["errors"])


def test_verify_admission_detects_manifest_tamper(tmp_path):
    admit_pipeline(**admission_kwargs("good", "good", out=tmp_path / "out"))
    manifest_path = tmp_path / "out" / "candidate_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["producer_label"] = "renamed"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    verification = verify_admission_output_directory(
        tmp_path / "out",
        expected_policy_public_keys=_policy_public_keys(),
    )
    assert verification["valid"] is False


def test_verify_admission_detects_compact_state_tamper(tmp_path):
    admit_pipeline(**admission_kwargs("good", "good", out=tmp_path / "out"))
    state_path = tmp_path / "out" / "compact_state.json"
    state = json.loads(state_path.read_text())
    state["supported_claims"][0]["value"] = "tampered-region"
    state_path.write_text(json.dumps(state, indent=2, sort_keys=True))
    verification = verify_admission_output_directory(
        tmp_path / "out",
        expected_policy_public_keys=_policy_public_keys(),
    )
    assert verification["valid"] is False


def test_verify_admission_detects_archive_tamper(tmp_path):
    admit_pipeline(**admission_kwargs("good", "good", out=tmp_path / "out"))
    archive_dir = tmp_path / "out" / "cold_archive" / "receipts"
    archived = sorted(archive_dir.glob("*.json"))
    assert archived, "admission must archive the source receipts"
    archived[0].write_text(archived[0].read_text().replace("cutover", "mutated"))
    verification = verify_admission_output_directory(
        tmp_path / "out",
        expected_policy_public_keys=_policy_public_keys(),
    )
    assert verification["valid"] is False
