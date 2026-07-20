from __future__ import annotations

import json
from pathlib import Path

from openline_half_life.cli import format_run_summary
from openline_half_life.economics import render_break_even_card
from openline_half_life.share_card import render_share_card


def _comparison():
    return {
        "passed": True,
        "legitimate_task_completion_preserved": True,
        "delta": {"error_reduction_micros": 428571},
        "full_history": {"metrics": {"error_count": 7, "unsupported_claim_count": 2}},
        "verified_residue": {"metrics": {"error_count": 4, "unsupported_claim_count": 0}},
    }


def test_cli_summary_is_human_readable_and_derived(tmp_path: Path):
    result = {
        "retirement_turn": 61,
        "comparison": _comparison(),
        "compaction": {"active_size_ratio_micros": 93451, "decision_mismatch_count": 0},
        "economics": {"dollar_durable_break_even_turn": 23, "status": "DURABLE_BREAK_EVEN_REACHED"},
        "output_dir": str(tmp_path),
    }
    text = format_run_summary(result)
    assert "Agent retired after turn 61." in text
    assert "Verified save file preserved" in text
    assert "reduced errors by 43%" in text
    assert "Active state: 9%" in text
    assert "Reference break-even: 23 future turns." in text
    assert "Decision mismatches: 0." in text
    assert str((tmp_path / "share_card.html").resolve()) in text


def test_share_card_carries_continuity_hook_and_byline(tmp_path: Path):
    html = render_share_card(
        tmp_path / "share.html",
        61,
        _comparison(),
        {"passed": True, "active_size_ratio_micros": 93451},
        {"dollar_claim_earned": True, "dollar_durable_break_even_turn": 23},
    )
    assert "Your agent should survive changing models." in html
    assert "Terrynce White · OpenLine Protocol" in html
    assert "not model weights or hidden thoughts" in html


def test_break_even_card_carries_byline_and_secondary_boundary(tmp_path: Path):
    report = {
        "status": "DURABLE_BREAK_EVEN_REACHED",
        "dollar_durable_break_even_turn": 2,
        "future_turn_horizon": 2,
        "pricing_complete": True,
        "canonical_initial_verification_runtime_micros": 100000,
        "observed_initial_verification_runtime_micros": 50000,
        "final": {
            "full_history_model_input_tokens": 200,
            "compact_model_input_tokens": 100,
        },
    }
    curve = [
        {"future_turn": 1, "full_history_total_usd_micros": 10, "compact_total_usd_micros": 20},
        {"future_turn": 2, "full_history_total_usd_micros": 30, "compact_total_usd_micros": 25},
    ]
    html = render_break_even_card(tmp_path / "economic.html", report, curve)
    assert "Terrynce White · OpenLine Protocol" in html
    assert "Cost is a secondary benefit of portable continuity." in html


def test_public_launch_surfaces_use_reference_active_state_not_gate_median(root: Path):
    public_paths = [
        root / "README.md",
        root / "POSITIONING.md",
        root / "LAUNCH_COPY.md",
        root / "docs/index.html",
        root / "docs/proof.html",
    ]
    combined = "\n".join(path.read_text(encoding="utf-8") for path in public_paths)
    assert "Active state: 9%" in combined
    assert "12%" not in combined
