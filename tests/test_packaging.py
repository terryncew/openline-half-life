from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def test_wheel_installed_demo_runs_outside_checkout(root: Path, tmp_path: Path):
    wheel_dir = tmp_path / "wheel"
    target = tmp_path / "site"
    empty = tmp_path / "empty"
    output = tmp_path / "demo"
    wheel_dir.mkdir()
    empty.mkdir()
    pip_env = dict(os.environ)
    pip_env["PIP_CACHE_DIR"] = str(tmp_path / "pip-cache")
    pip_env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"

    built = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            ".",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(wheel_dir),
        ],
        cwd=root,
        env=pip_env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert built.returncode == 0, built.stdout + built.stderr
    wheel = next(wheel_dir.glob("openline_half_life-*.whl"))

    installed = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--no-deps", "--target", str(target), str(wheel)],
        cwd=empty,
        env=pip_env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert installed.returncode == 0, installed.stdout + installed.stderr

    env = dict(os.environ)
    env["PYTHONPATH"] = str(target)
    demo = subprocess.run(
        [sys.executable, "-m", "openline_half_life", "demo", "--out", str(output)],
        cwd=empty,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert demo.returncode == 0, demo.stdout + demo.stderr
    result = json.loads(demo.stdout)
    assert result["comparison"]["passed"] is True
    assert result["retirement_turn"] == 61
    assert (output / "share_card.html").exists()
