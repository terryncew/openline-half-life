from __future__ import annotations

import copy
from pathlib import Path
import pytest

from openline_half_life.pipeline import run_pipeline, verify_output_directory
from openline_half_life.util import load_json, write_json


def _keys(path: Path) -> set[str]:
    return {line.strip() for line in path.read_text().splitlines() if line.strip()}


def test_demo_output_is_valid(root: Path, demo_output: Path):
    result = verify_output_directory(demo_output, expected_policy_public_keys=_keys(root / "policy/compaction_policy_public_key.hex"))
    assert result["valid"] is True
    assert result["decision_equivalence_passed"] is True
    assert result["active_size_ratio_micros"] < 200_000


def test_archive_file_tamper_is_detected(root: Path, demo_output: Path, tmp_path: Path):
    import shutil
    out = tmp_path / "tampered"
    shutil.copytree(demo_output, out)
    receipt = next((out / "cold_archive/receipts").glob("*.json"))
    receipt.write_text("{}\n")
    result = verify_output_directory(out, expected_policy_public_keys=_keys(root / "policy/compaction_policy_public_key.hex"))
    assert result["valid"] is False
    assert any(item.startswith("archive:") for item in result["errors"])


def test_compact_state_tamper_is_detected(root: Path, demo_output: Path, tmp_path: Path):
    import shutil
    out = tmp_path / "tampered"
    shutil.copytree(demo_output, out)
    value = load_json(out / "compact_state.json")
    value["objective"] = "attacker"
    write_json(out / "compact_state.json", value)
    result = verify_output_directory(out, expected_policy_public_keys=_keys(root / "policy/compaction_policy_public_key.hex"))
    assert result["valid"] is False


def test_bundle_tamper_is_detected(root: Path, demo_output: Path, tmp_path: Path):
    import shutil
    out = tmp_path / "tampered"
    shutil.copytree(demo_output, out)
    value = load_json(out / "receipt_bundle.json")
    value["policy_hash"] = "0" * 64
    write_json(out / "receipt_bundle.json", value)
    result = verify_output_directory(out, expected_policy_public_keys=_keys(root / "policy/compaction_policy_public_key.hex"))
    assert "bundle_hash_mismatch" in result["errors"]


def test_denied_operator_cannot_compact(root: Path, tmp_path: Path):
    with pytest.raises(ValueError, match="operator approval verification failed"):
        run_pipeline(root / "fixtures/demo_trajectory.jsonl", root / "fixtures/demo_source_signing_key.hex", tmp_path / "out", compaction_policy_path=root / "policy/compaction_policy.json", compaction_policy_public_key_path=root / "policy/compaction_policy_public_key.hex", operator_approval_signing_key_path=root / "fixtures/demo_operator_approval_key.hex", replay_latency_micros=75_000, operator_disposition="DENY")


def test_below_budgets_does_not_compact(root: Path, tmp_path: Path):
    with pytest.raises(ValueError, match="neither declared budget"):
        run_pipeline(root / "fixtures/demo_trajectory.jsonl", root / "fixtures/demo_source_signing_key.hex", tmp_path / "out", compaction_policy_path=root / "policy/compaction_policy.json", compaction_policy_public_key_path=root / "policy/compaction_policy_public_key.hex", operator_approval_signing_key_path=root / "fixtures/demo_operator_approval_key.hex", replay_latency_micros=0, checkpoint_turn=1)


def test_wrong_operator_key_fails(root: Path, tmp_path: Path):
    wrong = tmp_path / "wrong.hex"
    wrong.write_text("55" * 32 + "\n")
    with pytest.raises(ValueError, match="operator approval verification failed"):
        run_pipeline(root / "fixtures/demo_trajectory.jsonl", root / "fixtures/demo_source_signing_key.hex", tmp_path / "out", compaction_policy_path=root / "policy/compaction_policy.json", compaction_policy_public_key_path=root / "policy/compaction_policy_public_key.hex", operator_approval_signing_key_path=wrong, replay_latency_micros=75_000)
