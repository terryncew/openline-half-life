from __future__ import annotations

from pathlib import Path

import pytest

from openline_half_life.causal_compactor import load_trusted_compaction_policy_keys
from openline_half_life.pipeline import run_pipeline
from openline_half_life.policy import load_trusted_policy_keys


@pytest.fixture(scope="session")
def root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def trusted_policy_keys(root: Path) -> set[str]:
    return load_trusted_policy_keys(root / "policy/succession_policy_public_key.hex")


@pytest.fixture(scope="session")
def trusted_compaction_policy_keys(root: Path) -> set[str]:
    return load_trusted_compaction_policy_keys(
        root / "policy/compaction_policy_public_key.hex"
    )


@pytest.fixture(scope="session")
def causal_demo_output(root: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    output = tmp_path_factory.mktemp("causal-demo")
    result = run_pipeline(
        root / "fixtures/gradual_drift.jsonl",
        root / "exams/heldout_exam.json",
        root / "policy/succession_policy.json",
        root / "policy/succession_policy_public_key.hex",
        root / "fixtures/demo_signing_key.hex",
        output,
        compaction_policy_path=root / "policy/compaction_policy.json",
        compaction_policy_public_key_path=root / "policy/compaction_policy_public_key.hex",
        replay_latency_micros=75_000,
        receiver_approval_signing_key_path=root / "fixtures/demo_receiver_approval_key.hex",
        economics_assumptions_path=root / "economics/demo_cost_assumptions.json",
        receiver_disposition="APPROVE",
    )
    assert result["passed"] is True
    return output
