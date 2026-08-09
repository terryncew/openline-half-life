from scripts.seeded_gate import run_gate


def test_small_seeded_gate():
    result = run_gate(100)
    assert result["passed"] is True
    assert result["decision_mismatch_count"] == 0
    assert result["successful_tombstone_replay_count"] == 0
