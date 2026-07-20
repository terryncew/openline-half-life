from __future__ import annotations

import json
from pathlib import Path

from scripts.build_landing_page import build


def test_landing_page_is_derived_from_reference_artifacts(root: Path, tmp_path: Path):
    out = tmp_path / "docs"
    metrics = build(root / "examples" / "demo_output", out)
    comparison = json.loads((root / "examples/demo_output/comparison.json").read_text())
    equivalence = json.loads((root / "examples/demo_output/decision_equivalence_report.json").read_text())
    economics = json.loads((root / "examples/demo_output/break_even_report.json").read_text())
    page = (out / "index.html").read_text()

    assert metrics["full_history_errors"] == comparison["full_history"]["metrics"]["error_count"]
    assert metrics["compact_errors"] == comparison["verified_residue"]["metrics"]["error_count"]
    assert metrics["decision_mismatches"] == len(equivalence["mismatches"])
    assert metrics["break_even_turn"] == economics["dollar_durable_break_even_turn"]
    assert "Your agent should survive changing models." in page
    assert "You own the job. The model is the console." in page
    assert f">{metrics['full_history_errors']} → {metrics['compact_errors']}<" in page
    assert f">{metrics['active_state_percent']}%<" in page
    assert (out / "reference/share_card.html").exists()
    assert (out / "reference/break_even_card.html").exists()
    assert (out / "proof.html").exists()


def test_pypi_release_workflow_tests_published_package(root: Path):
    text = (root / ".github/workflows/publish.yml").read_text()
    assert "pypa/gh-action-pypi-publish@release/v1" in text
    assert "uvx --from" in text
    assert "pipx run --spec" in text
    assert "published-demo" in text
    assert "verify_output_directory" in text
