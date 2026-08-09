from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_cli_demo(root: Path, tmp_path: Path):
    result = subprocess.run([sys.executable, "-m", "openline_half_life", "demo", "--out", str(tmp_path / "demo")], cwd=root, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "Independent replay mismatches: 0." in result.stdout
