from __future__ import annotations

import json
from pathlib import Path

import pytest

from openline_half_life.cli import _command_succeeded
from openline_half_life.comparison import compare_results
import openline_half_life.pipeline as pipeline_module
from openline_half_life.pipeline import run_pipeline
from openline_half_life.receipts import verify_output_directory
from openline_half_life.share_card import render_share_card


def _run(root: Path, out: Path):
    return run_pipeline(
        root / "fixtures/gradual_drift.jsonl",
        root / "exams/heldout_exam.json",
        root / "policy/succession_policy.json",
        root / "policy/succession_policy_public_key.hex",
        root / "fixtures/demo_signing_key.hex",
        out,
        compaction_policy_path=root / "policy/compaction_policy.json",
        compaction_policy_public_key_path=root / "policy/compaction_policy_public_key.hex",
        replay_latency_micros=75_000,
        receiver_approval_signing_key_path=root / "fixtures/demo_receiver_approval_key.hex",
        economics_assumptions_path=root / "economics/demo_cost_assumptions.json",
        receiver_disposition="APPROVE",
    )


def test_pipeline_emits_required_artifacts_and_exact_demo_claim(root, tmp_path):
    result = _run(root, tmp_path)
    for name in (
        "half_life_receipt.json",
        "calibrator_policy.json",
        "full_history_handoff.json",
        "verified_residue_handoff.json",
        "comparison.json",
        "share_card.html",
        "cost_assumptions.json",
        "break_even_report.json",
        "break_even_curve.csv",
        "break_even_card.html",
    ):
        assert (tmp_path / name).exists()
    assert result["passed"] is True
    assert result["retirement_turn"] == 61
    comparison = json.loads((tmp_path / "comparison.json").read_text())
    assert comparison["full_history"]["metrics"]["error_count"] == 7
    assert comparison["verified_residue"]["metrics"]["error_count"] == 4
    assert comparison["delta"]["error_reduction_micros"] == 428_571
    card = (tmp_path / "share_card.html").read_text()
    assert "COMPARISON PASSED" in card
    assert "Agent retired after turn 61." in card
    assert "Verified handoff reduced errors by 43% on the same exam." in card
    economics = json.loads((tmp_path / "break_even_report.json").read_text())
    assert economics["status"] == "DURABLE_BREAK_EVEN_REACHED"
    assert economics["dollar_claim_earned"] is True
    assert economics["dollar_durable_break_even_turn"] is not None
    expected_turn = economics["dollar_durable_break_even_turn"]
    assert f"Economic break-even after {expected_turn} future turns under declared assumptions." in card


def test_both_successors_receive_exactly_the_same_exam(root, tmp_path):
    _run(root, tmp_path)
    comparison = json.loads((tmp_path / "comparison.json").read_text())
    assert comparison["same_exam_verified"] is True
    assert comparison["full_history"]["exam_hash"] == comparison["verified_residue"]["exam_hash"]


def test_comparison_cannot_pass_without_legitimate_task_completion():
    base = {
        "exam_hash": "a" * 64,
        "metrics": {
            "error_count": 5,
            "accuracy_micros": 500_000,
            "unsupported_claim_count": 2,
            "constraint_violation_count": 1,
            "estimated_input_tokens": 100,
            "legitimate_completion_required": 2,
            "legitimate_completion_correct": 2,
        },
    }
    residue = json.loads(json.dumps(base))
    residue["metrics"].update(
        {
            "error_count": 1,
            "accuracy_micros": 900_000,
            "unsupported_claim_count": 0,
            "constraint_violation_count": 0,
            "estimated_input_tokens": 20,
            "legitimate_completion_correct": 1,
        }
    )
    assert compare_results(base, residue)["passed"] is False


def _failed_comparison(*, reduction_micros: int, legitimate: bool = True) -> dict:
    full_errors = 8
    residue_errors = 6 if reduction_micros > 0 else 10
    return {
        "passed": False,
        "legitimate_task_completion_preserved": legitimate,
        "delta": {"error_reduction_micros": reduction_micros},
        "full_history": {
            "metrics": {
                "error_count": full_errors,
                "unsupported_claim_count": 1,
            }
        },
        "verified_residue": {
            "metrics": {
                "error_count": residue_errors,
                "unsupported_claim_count": 0,
            }
        },
    }


def test_failed_comparison_share_card_cannot_claim_verified_reduction(tmp_path):
    path = tmp_path / "card.html"
    render_share_card(path, 61, _failed_comparison(reduction_micros=250_000))
    card = path.read_text()
    assert "COMPARISON FAILED" in card
    assert "No verified handoff advantage established." in card
    assert "Errors fell by 25%, but the comparison gate failed." in card
    assert "Verified handoff reduced errors" not in card


def test_negative_delta_is_described_as_increase_not_negative_reduction(tmp_path):
    path = tmp_path / "card.html"
    render_share_card(path, 61, _failed_comparison(reduction_micros=-180_000))
    card = path.read_text()
    assert "increased errors by 18%" in card
    assert "reduced errors by -18%" not in card


def test_cli_run_exit_requires_hypothesis_and_integrity_to_pass():
    assert _command_succeeded(
        "run",
        {"comparison": {"passed": False}, "compaction": {"decision_equivalence_passed": True}, "verification": {"valid": True}},
    ) is False
    assert _command_succeeded(
        "run",
        {"comparison": {"passed": True}, "compaction": {"decision_equivalence_passed": True}, "verification": {"valid": False}},
    ) is False
    assert _command_succeeded(
        "run",
        {"comparison": {"passed": True}, "compaction": {"decision_equivalence_passed": True}, "verification": {"valid": True}},
    ) is True


def test_pipeline_seals_failed_hypothesis_honestly_and_returns_failure(
    root, tmp_path, monkeypatch, trusted_policy_keys, trusted_compaction_policy_keys
):
    full_result = {
        "exam_hash": "b" * 64,
        "metrics": {
            "error_count": 4,
            "accuracy_micros": 600_000,
            "unsupported_claim_count": 0,
            "constraint_violation_count": 0,
            "estimated_input_tokens": 100,
            "legitimate_completion_required": 3,
            "legitimate_completion_correct": 3,
        },
    }
    residue_result = json.loads(json.dumps(full_result))
    residue_result["metrics"].update(
        {
            "error_count": 5,
            "accuracy_micros": 500_000,
            "estimated_input_tokens": 40,
        }
    )
    def fake_run_same_exam(full, residue, exam):
        left = json.loads(json.dumps(full_result))
        right = json.loads(json.dumps(residue_result))
        exam_hash = pipeline_module.sha256_bytes(pipeline_module.canonical_json(exam))
        left["exam_hash"] = exam_hash
        right["exam_hash"] = exam_hash
        left["packet_hash"] = full["packet_hash"]
        right["packet_hash"] = residue["packet_hash"]
        return left, right

    monkeypatch.setattr(
        pipeline_module,
        "run_same_exam",
        fake_run_same_exam,
    )
    result = _run(root, tmp_path)
    assert result["passed"] is False
    assert result["comparison"]["passed"] is False
    assert result["verification"]["valid"] is True
    card = (tmp_path / "share_card.html").read_text()
    assert "COMPARISON FAILED" in card
    assert "increased errors by 25%" in card
    assert "Verified handoff reduced errors" not in card
    assert verify_output_directory(
        tmp_path,
        expected_policy_public_keys=trusted_policy_keys,
        expected_compaction_policy_public_keys=trusted_compaction_policy_keys,
    )["valid"] is True


def test_verification_requires_external_policy_pin(root, tmp_path, trusted_policy_keys, trusted_compaction_policy_keys):
    _run(root, tmp_path)
    missing_pin = verify_output_directory(
        tmp_path,
        expected_policy_public_keys=None,
        expected_compaction_policy_public_keys=trusted_compaction_policy_keys,
    )
    assert missing_pin["valid"] is False
    assert "trusted_policy_key_required" in missing_pin["errors"]
    assert verify_output_directory(
        tmp_path,
        expected_policy_public_keys=trusted_policy_keys,
        expected_compaction_policy_public_keys=trusted_compaction_policy_keys,
    )["valid"] is True


@pytest.mark.parametrize(
    "name",
    [
        "cost_assumptions.json",
        "break_even_report.json",
        "break_even_curve.csv",
        "break_even_card.html",
    ],
)
def test_tampering_with_economics_artifacts_breaks_verification(
    root, tmp_path, name, trusted_policy_keys, trusted_compaction_policy_keys
):
    _run(root, tmp_path)
    path = tmp_path / name
    if path.suffix == ".json":
        value = json.loads(path.read_text())
        value["tampered"] = True
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    else:
        path.write_text(path.read_text() + "\nTAMPERED\n")
    result = verify_output_directory(
        tmp_path,
        expected_policy_public_keys=trusted_policy_keys,
        expected_compaction_policy_public_keys=trusted_compaction_policy_keys,
    )
    assert result["valid"] is False
    assert f"artifact_hash_mismatch:{name}" in result["errors"]


@pytest.mark.parametrize("name", ["full_history_handoff.json", "verified_residue_handoff.json"])
def test_tampering_with_either_handoff_breaks_verification(root, tmp_path, name, trusted_policy_keys, trusted_compaction_policy_keys):
    _run(root, tmp_path)
    assert verify_output_directory(
        tmp_path,
        expected_policy_public_keys=trusted_policy_keys,
        expected_compaction_policy_public_keys=trusted_compaction_policy_keys,
    )["valid"] is True
    path = tmp_path / name
    value = json.loads(path.read_text())
    value["run_id"] = "attacker-run"
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    result = verify_output_directory(
        tmp_path,
        expected_policy_public_keys=trusted_policy_keys,
        expected_compaction_policy_public_keys=trusted_compaction_policy_keys,
    )
    assert result["valid"] is False
    assert f"artifact_hash_mismatch:{name}" in result["errors"]


def test_tampering_with_policy_breaks_receiver_verification(root, tmp_path, trusted_policy_keys, trusted_compaction_policy_keys):
    _run(root, tmp_path)
    path = tmp_path / "calibrator_policy.json"
    value = json.loads(path.read_text())
    value["persistence"]["minimum_metric_breaches"] = 0
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    result = verify_output_directory(
        tmp_path,
        expected_policy_public_keys=trusted_policy_keys,
        expected_compaction_policy_public_keys=trusted_compaction_policy_keys,
    )
    assert result["valid"] is False
    assert "artifact_hash_mismatch:calibrator_policy.json" in result["errors"]
    assert any(error.startswith("calibrator_policy:") for error in result["errors"])


def test_tampering_with_any_receipt_breaks_chain(root, tmp_path, trusted_policy_keys, trusted_compaction_policy_keys):
    _run(root, tmp_path)
    path = tmp_path / "half_life_receipt.json"
    value = json.loads(path.read_text())
    value["receipts"][2]["payload"]["turn_hash"] = "0" * 64
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    result = verify_output_directory(
        tmp_path,
        expected_policy_public_keys=trusted_policy_keys,
        expected_compaction_policy_public_keys=trusted_compaction_policy_keys,
    )
    assert result["valid"] is False
    assert any(error.startswith(("hash_mismatch:2", "signature_or_shape_invalid:2", "parent_mismatch:3")) for error in result["errors"])
