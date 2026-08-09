from __future__ import annotations

from pathlib import Path
import pytest

from openline_half_life.pipeline import run_pipeline


@pytest.fixture(scope="session")
def root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def demo_output(root: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("demo-output")
    result = run_pipeline(
        root / "fixtures/demo_trajectory.jsonl",
        root / "fixtures/demo_source_signing_key.hex",
        out,
        compaction_policy_path=root / "policy/compaction_policy.json",
        compaction_policy_public_key_path=root / "policy/compaction_policy_public_key.hex",
        operator_approval_signing_key_path=root / "fixtures/demo_operator_approval_key.hex",
        replay_latency_micros=75_000,
    )
    assert result["passed"] is True
    return out
