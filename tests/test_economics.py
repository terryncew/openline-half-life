from __future__ import annotations

import copy
import re
from pathlib import Path

import pytest

from openline_half_life.economics import (
    EconomicsError,
    INPUT_SCHEMA,
    render_break_even_card,
    run_break_even_benchmark,
    write_economics_outputs,
    verify_economics_outputs,
)
from openline_half_life.util import write_json


def _declared(*, horizon: int = 100, fixed: int = 100_000, compute_rate: int = 4_000_000, model_rate: int = 2_500_000, canonical_runtime: int = 100_000, rehydrate=None, recompaction=None):
    return {
        "schema": INPUT_SCHEMA,
        "assumptions_id": "test-assumptions",
        "future_turns": horizon,
        "canonical_initial_verification_runtime_micros": canonical_runtime,
        "recompaction_turns": [] if recompaction is None else recompaction,
        "rehydration_turns": [] if rehydrate is None else rehydrate,
        "rehydration_full_history_loads": 1,
        "recompaction_verification_multiplier_micros": 1_000_000,
        "rehydration_verification_multiplier_micros": 1_000_000,
        "model_input_price_usd_micros_per_million_tokens": model_rate,
        "deterministic_compute_price_usd_micros_per_second": compute_rate,
        "fixed_verification_overhead_usd_micros": fixed,
        "pricing_effective_date": "2026-07-20",
        "pricing_source": "DECLARED_TEST_ASSUMPTION",
    }


def _comparison(passed: bool = True):
    return {
        "passed": passed,
        "same_exam_verified": passed,
        "legitimate_task_completion_preserved": passed,
    }


def _equivalence(passed: bool = True):
    return {"passed": passed}


def _sources():
    return {
        "full_history_packet_hash": "a" * 64,
        "compact_state_packet_hash": "b" * 64,
        "comparison_hash": "c" * 64,
        "equivalence_report_hash": "d" * 64,
    }


def _run(declared, *, runtime=50_000, comparison=None, equivalence=None):
    return run_break_even_benchmark(
        declared_assumptions=declared,
        full_history_tokens_per_turn=10_000,
        compact_state_tokens_per_turn=2_000,
        observed_initial_verification_runtime_micros=runtime,
        comparison=_comparison() if comparison is None else comparison,
        equivalence_report=_equivalence() if equivalence is None else equivalence,
        source_hashes=_sources(),
    )


def test_short_task_can_honestly_show_no_break_even():
    _, report, _ = _run(_declared(horizon=2, fixed=1_000_000), runtime=500_000)
    assert report["status"] == "NO_DURABLE_BREAK_EVEN_WITHIN_HORIZON"
    assert report["dollar_claim_earned"] is False


def test_long_task_crosses_and_stays_below():
    _, report, curve = _run(_declared(horizon=100, fixed=100_000), runtime=50_000)
    assert report["status"] == "DURABLE_BREAK_EVEN_REACHED"
    assert report["dollar_durable_break_even_turn"] is not None
    turn = report["dollar_durable_break_even_turn"]
    assert all(row["compact_total_usd_micros"] <= row["full_history_total_usd_micros"] for row in curve[turn - 1 :])


def test_more_declared_verification_cost_moves_break_even_later():
    _, low, _ = _run(_declared(horizon=200, fixed=0, canonical_runtime=10_000), runtime=500_000)
    _, high, _ = _run(_declared(horizon=200, fixed=500_000, canonical_runtime=500_000), runtime=10_000)
    assert low["dollar_durable_break_even_turn"] < high["dollar_durable_break_even_turn"]


def test_observed_runtime_is_evidence_not_headline_input():
    first_assumptions, first_report, first_curve = _run(_declared(horizon=200, canonical_runtime=100_000), runtime=10_000)
    second_assumptions, second_report, second_curve = _run(_declared(horizon=200, canonical_runtime=100_000), runtime=900_000)
    assert first_report["dollar_durable_break_even_turn"] == second_report["dollar_durable_break_even_turn"]
    assert first_curve == second_curve
    assert first_assumptions["measured"]["observed_initial_verification_runtime_micros"] == 10_000
    assert second_assumptions["measured"]["observed_initial_verification_runtime_micros"] == 900_000
    assert first_report["headline_basis"] == "DECLARED_CANONICAL_SCENARIO"


def test_rehydration_frequency_moves_durable_break_even_later():
    _, base, _ = _run(_declared(horizon=200, fixed=200_000), runtime=100_000)
    _, rehydrated, _ = _run(
        _declared(horizon=200, fixed=200_000, rehydrate=[20, 40, 60, 80, 100]),
        runtime=100_000,
    )
    assert rehydrated["dollar_durable_break_even_turn"] >= base["dollar_durable_break_even_turn"]


def test_missing_pricing_blocks_dollar_claim(tmp_path: Path):
    declared = _declared()
    declared.update(
        {
            "model_input_price_usd_micros_per_million_tokens": None,
            "deterministic_compute_price_usd_micros_per_second": None,
            "fixed_verification_overhead_usd_micros": None,
            "pricing_effective_date": None,
            "pricing_source": None,
        }
    )
    _, report, curve = _run(declared)
    assert report["status"] == "UNDECIDABLE_MISSING_PRICING"
    assert report["dollar_claim_earned"] is False
    assert all(row["compact_total_usd_micros"] is None for row in curve)
    card = render_break_even_card(tmp_path / "card.html", report, curve)
    assert "No dollar break-even calculated." in card
    assert "stays cheaper" not in card


def test_safety_or_equivalence_failure_blocks_economic_claim():
    _, report, _ = _run(_declared(), equivalence=_equivalence(False))
    assert report["status"] == "BLOCKED_SAFETY_OR_EQUIVALENCE_FAILED"
    assert report["dollar_claim_earned"] is False


def test_calculation_is_reproducible_for_fixed_measurements():
    first = _run(_declared(rehydrate=[90], recompaction=[60]), runtime=75_000)
    second = _run(_declared(rehydrate=[90], recompaction=[60]), runtime=75_000)
    assert first == second


def test_semantic_verifier_rejects_modified_curve(tmp_path: Path):
    assumptions, report, curve = _run(_declared(), runtime=75_000)
    write_economics_outputs(tmp_path, assumptions, report, curve)
    write_json(tmp_path / "comparison.json", {**_comparison(), "comparison_hash": "c" * 64})
    write_json(tmp_path / "decision_equivalence_report.json", {**_equivalence(), "report_hash": "d" * 64})
    (tmp_path / "share_card.html").write_text(
        f"Economic break-even after {report['dollar_durable_break_even_turn']} future turns under declared assumptions.",
        encoding="utf-8",
    )
    assert verify_economics_outputs(tmp_path) == []
    text = (tmp_path / "break_even_curve.csv").read_text(encoding="utf-8")
    (tmp_path / "break_even_curve.csv").write_text(text.replace("ordinary", "rehydration", 1), encoding="utf-8")
    assert "break_even_curve_semantic_mismatch" in verify_economics_outputs(tmp_path)


def test_complete_pricing_requires_positive_model_rate_and_iso_date():
    zero = _declared(model_rate=0)
    with pytest.raises(EconomicsError, match="model input price must be positive"):
        _run(zero)
    bad_date = _declared()
    bad_date["pricing_effective_date"] = "July 20, 2026"
    with pytest.raises(EconomicsError, match="ISO YYYY-MM-DD"):
        _run(bad_date)


def test_source_hashes_must_be_lowercase_hex():
    sources = _sources()
    sources["comparison_hash"] = "z" * 64
    with pytest.raises(EconomicsError, match="source hash invalid"):
        run_break_even_benchmark(
            declared_assumptions=_declared(),
            full_history_tokens_per_turn=10_000,
            compact_state_tokens_per_turn=2_000,
            observed_initial_verification_runtime_micros=50_000,
            comparison=_comparison(),
            equivalence_report=_equivalence(),
            source_hashes=sources,
        )


def test_break_even_graph_uses_one_shared_vertical_scale(tmp_path: Path):
    _, report, curve = _run(_declared(horizon=100), runtime=50_000)
    html = render_break_even_card(tmp_path / "card.html", report, curve)
    lines = re.findall(r'<polyline points="([^"]+)"', html)
    assert len(lines) == 2
    full_last_y = int(lines[0].split()[-1].split(",")[1])
    compact_last_y = int(lines[1].split()[-1].split(",")[1])
    assert full_last_y < compact_last_y
    assert "one shared vertical scale" in html
    assert f"break-even: turn {report['dollar_durable_break_even_turn']}" in html
