from __future__ import annotations

import copy
import json
from pathlib import Path
import pytest

from openline_half_life.schema import load_trajectory, validate_turn


def test_demo_trajectory_loads(root: Path):
    rows = load_trajectory(root / "fixtures/demo_trajectory.jsonl")
    assert len(rows) == 70
    assert all("measurements" not in row for row in rows)


def test_old_extra_fields_fail_closed(root: Path):
    row = load_trajectory(root / "fixtures/demo_trajectory.jsonl")[0]
    changed = copy.deepcopy(row)
    changed["measurements"] = {"score": 1}
    with pytest.raises(ValueError, match="turn field mismatch"):
        validate_turn(changed, expected_turn=1)


def test_evidence_id_cannot_rebind(root: Path, tmp_path: Path):
    rows = load_trajectory(root / "fixtures/demo_trajectory.jsonl")[:2]
    ev = copy.deepcopy(rows[0]["evidence"][0])
    ev["observed_turn"] = 2
    ev["sha256"] = "f" * 64
    rows[1]["evidence"].append(ev)
    path = tmp_path / "bad.jsonl"
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    with pytest.raises(ValueError, match="rebound"):
        load_trajectory(path)
