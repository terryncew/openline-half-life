from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_gate(root: Path):
    path = root / "scripts/compaction_release_gate.py"
    spec = importlib.util.spec_from_file_location("compaction_release_gate", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_seeded_history_gets_full_cryptographic_verification(root):
    gate = _load_gate(root)
    result = gate.run(history_count=25)
    assert result["passed"] is True
    assert result["seeded_history_count"] == 25
    assert result["cryptographically_verified_history_count"] == 25
    assert result["all_histories_cryptographically_verified"] is True
    assert "cryptographic_sample_interval" not in result
    assert result["chain_verification_failure_count"] == 0
