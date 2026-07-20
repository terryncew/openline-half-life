from __future__ import annotations

import csv
from datetime import date
from html import escape
from pathlib import Path
from typing import Any, Mapping, Sequence

from .util import canonical_json, load_json, sha256_bytes, write_json

INPUT_SCHEMA = "openline.half-life.cost-assumptions-input.v2"
ASSUMPTIONS_SCHEMA = "openline.half-life.cost-assumptions.v2"
REPORT_SCHEMA = "openline.half-life.break-even-report.v2"
MAX_HORIZON_TURNS = 100_000
SCALE = 1_000_000

INPUT_FIELDS = {
    "schema",
    "assumptions_id",
    "future_turns",
    "canonical_initial_verification_runtime_micros",
    "recompaction_turns",
    "rehydration_turns",
    "rehydration_full_history_loads",
    "recompaction_verification_multiplier_micros",
    "rehydration_verification_multiplier_micros",
    "model_input_price_usd_micros_per_million_tokens",
    "deterministic_compute_price_usd_micros_per_second",
    "fixed_verification_overhead_usd_micros",
    "pricing_effective_date",
    "pricing_source",
}


class EconomicsError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EconomicsError(message)


def _integer(value: Any, name: str, *, minimum: int = 0, maximum: int | None = None) -> int:
    _require(isinstance(value, int) and not isinstance(value, bool), f"{name} must be an integer")
    _require(value >= minimum, f"{name} must be at least {minimum}")
    if maximum is not None:
        _require(value <= maximum, f"{name} exceeds {maximum}")
    return value


def _optional_integer(value: Any, name: str) -> int | None:
    if value is None:
        return None
    return _integer(value, name)


def _turn_list(value: Any, name: str, horizon: int) -> list[int]:
    _require(isinstance(value, list), f"{name} must be an array")
    turns = [_integer(item, name, minimum=1, maximum=horizon) for item in value]
    _require(turns == sorted(set(turns)), f"{name} must be sorted and unique")
    return turns


def validate_cost_assumptions_input(value: Mapping[str, Any]) -> dict[str, Any]:
    _require(isinstance(value, Mapping), "cost assumptions must be an object")
    _require(set(value) == INPUT_FIELDS, "cost assumptions field mismatch")
    _require(value["schema"] == INPUT_SCHEMA, "unsupported cost assumptions schema")
    assumptions_id = value["assumptions_id"]
    _require(isinstance(assumptions_id, str) and assumptions_id and assumptions_id.isascii(), "assumptions_id must be non-empty ASCII")
    horizon = _integer(value["future_turns"], "future_turns", minimum=1, maximum=MAX_HORIZON_TURNS)
    _integer(value["canonical_initial_verification_runtime_micros"], "canonical_initial_verification_runtime_micros", minimum=1)
    recompaction_turns = _turn_list(value["recompaction_turns"], "recompaction_turns", horizon)
    rehydration_turns = _turn_list(value["rehydration_turns"], "rehydration_turns", horizon)
    _require(not (set(recompaction_turns) & set(rehydration_turns)), "recompaction and rehydration turns must not overlap")
    _integer(value["rehydration_full_history_loads"], "rehydration_full_history_loads", maximum=1000)
    _integer(value["recompaction_verification_multiplier_micros"], "recompaction_verification_multiplier_micros", maximum=100 * SCALE)
    _integer(value["rehydration_verification_multiplier_micros"], "rehydration_verification_multiplier_micros", maximum=100 * SCALE)
    model_price = _optional_integer(value["model_input_price_usd_micros_per_million_tokens"], "model_input_price_usd_micros_per_million_tokens")
    compute_price = _optional_integer(value["deterministic_compute_price_usd_micros_per_second"], "deterministic_compute_price_usd_micros_per_second")
    fixed = _optional_integer(value["fixed_verification_overhead_usd_micros"], "fixed_verification_overhead_usd_micros")
    pricing_complete = None not in {model_price, compute_price, fixed}
    effective = value["pricing_effective_date"]
    source = value["pricing_source"]
    if pricing_complete:
        _require(int(model_price) > 0, "model input price must be positive with complete pricing")
        _require(int(compute_price) > 0, "deterministic compute price must be positive with complete pricing")
        _require(int(fixed) > 0, "fixed verification overhead must be positive with complete pricing")
        _require(isinstance(effective, str) and effective, "pricing_effective_date is required with complete pricing")
        try:
            date.fromisoformat(effective)
        except (TypeError, ValueError) as exc:
            raise EconomicsError("pricing_effective_date must be ISO YYYY-MM-DD") from exc
        _require(isinstance(source, str) and source and source.isascii(), "pricing_source must be non-empty ASCII")
    else:
        _require(effective is None and source is None, "partial pricing cannot carry a date or source")
    return dict(value)


def load_cost_assumptions_input(path: Path) -> dict[str, Any]:
    return validate_cost_assumptions_input(load_json(path))


def _ceil_div(numerator: int, denominator: int) -> int:
    return 0 if numerator == 0 else (numerator + denominator - 1) // denominator


def _model_cost(tokens: int, rate: int) -> int:
    return _ceil_div(tokens * rate, SCALE)


def _compute_cost(runtime_micros: int, rate_per_second: int) -> int:
    return _ceil_div(runtime_micros * rate_per_second, SCALE)


def _durable_break_even(curve: Sequence[Mapping[str, Any]], field: str) -> int | None:
    """Return the first turn after which compact stays at or below full history.

    A single backward pass records the last row that violates durability. This
    preserves the previous semantics while avoiding a quadratic suffix scan.
    """
    full_field = field.replace("compact_", "full_history_")
    last_failure_index = -1
    for index in range(len(curve) - 1, -1, -1):
        row = curve[index]
        compact = row.get(field)
        full = row.get(full_field)
        if compact is None or full is None or compact > full:
            last_failure_index = index
            break
    candidate_index = last_failure_index + 1
    if candidate_index >= len(curve):
        return None
    return int(curve[candidate_index]["future_turn"])


def _first_crossing(curve: Sequence[Mapping[str, Any]], compact_field: str) -> int | None:
    full_field = compact_field.replace("compact_", "full_history_")
    for row in curve:
        compact = row.get(compact_field)
        full = row.get(full_field)
        if compact is not None and full is not None and compact <= full:
            return int(row["future_turn"])
    return None


def run_break_even_benchmark(
    *,
    declared_assumptions: Mapping[str, Any],
    full_history_tokens_per_turn: int,
    compact_state_tokens_per_turn: int,
    observed_initial_verification_runtime_micros: int,
    comparison: Mapping[str, Any],
    equivalence_report: Mapping[str, Any],
    source_hashes: Mapping[str, str],
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    declared = validate_cost_assumptions_input(declared_assumptions)
    full_tokens = _integer(full_history_tokens_per_turn, "full_history_tokens_per_turn", minimum=1)
    compact_tokens = _integer(compact_state_tokens_per_turn, "compact_state_tokens_per_turn", minimum=1)
    observed_runtime = _integer(observed_initial_verification_runtime_micros, "observed_initial_verification_runtime_micros", minimum=1)
    canonical_runtime = _integer(declared["canonical_initial_verification_runtime_micros"], "canonical_initial_verification_runtime_micros", minimum=1)
    _require(set(source_hashes) == {"full_history_packet_hash", "compact_state_packet_hash", "comparison_hash", "equivalence_report_hash"}, "economics source hash field mismatch")
    _require(all(isinstance(item, str) and len(item) == 64 and all(ch in "0123456789abcdef" for ch in item) for item in source_hashes.values()), "economics source hash invalid")

    assumptions_body = {
        "schema": ASSUMPTIONS_SCHEMA,
        "declared": declared,
        "measured": {
            "full_history_tokens_per_turn": full_tokens,
            "compact_state_tokens_per_turn": compact_tokens,
            "observed_initial_verification_runtime_micros": observed_runtime,
            "model_token_reduction_micros": (full_tokens - compact_tokens) * SCALE // full_tokens,
        },
        "source_hashes": dict(sorted(source_hashes.items())),
        "measurement_boundary": (
            "Token sizes are measured from the disclosed handoff packets. Observed verification runtime is retained as wall-clock evidence and may vary by machine. "
            "The economic curve uses the receiver-declared canonical verification runtime, so its headline is reproducible across machines. Dollar results require complete dated pricing assumptions."
        ),
    }
    assumptions = {**assumptions_body, "assumptions_hash": sha256_bytes(canonical_json(assumptions_body))}

    horizon = declared["future_turns"]
    recompaction_turns = set(declared["recompaction_turns"])
    rehydration_turns = set(declared["rehydration_turns"])
    pricing_complete = all(
        declared[name] is not None
        for name in (
            "model_input_price_usd_micros_per_million_tokens",
            "deterministic_compute_price_usd_micros_per_second",
            "fixed_verification_overhead_usd_micros",
        )
    )
    model_rate = declared["model_input_price_usd_micros_per_million_tokens"]
    compute_rate = declared["deterministic_compute_price_usd_micros_per_second"]
    fixed_overhead = declared["fixed_verification_overhead_usd_micros"]

    curve: list[dict[str, Any]] = []
    cumulative_full_tokens = 0
    cumulative_compact_tokens = 0
    cumulative_verification_runtime = canonical_runtime
    recompactions = 0
    rehydrations = 0
    for future_turn in range(1, horizon + 1):
        cumulative_full_tokens += full_tokens
        cumulative_compact_tokens += compact_tokens
        event = "ordinary"
        if future_turn in recompaction_turns:
            recompactions += 1
            event = "recompaction"
            cumulative_verification_runtime += (
                canonical_runtime * declared["recompaction_verification_multiplier_micros"] // SCALE
            )
        elif future_turn in rehydration_turns:
            rehydrations += 1
            event = "rehydration"
            cumulative_compact_tokens += full_tokens * declared["rehydration_full_history_loads"]
            cumulative_verification_runtime += (
                canonical_runtime * declared["rehydration_verification_multiplier_micros"] // SCALE
            )

        if pricing_complete:
            full_cost = _model_cost(cumulative_full_tokens, int(model_rate))
            compact_cost = (
                _model_cost(cumulative_compact_tokens, int(model_rate))
                + _compute_cost(cumulative_verification_runtime, int(compute_rate))
                + int(fixed_overhead)
            )
            savings = full_cost - compact_cost
        else:
            full_cost = None
            compact_cost = None
            savings = None
        curve.append(
            {
                "future_turn": future_turn,
                "event": event,
                "full_history_model_input_tokens": cumulative_full_tokens,
                "compact_model_input_tokens": cumulative_compact_tokens,
                "compact_verification_runtime_micros": cumulative_verification_runtime,
                "recompaction_count": recompactions,
                "rehydration_count": rehydrations,
                "full_history_total_usd_micros": full_cost,
                "compact_total_usd_micros": compact_cost,
                "compact_savings_usd_micros": savings,
            }
        )

    token_first = _first_crossing(curve, "compact_model_input_tokens")
    token_durable = _durable_break_even(curve, "compact_model_input_tokens")
    dollar_first = _first_crossing(curve, "compact_total_usd_micros") if pricing_complete else None
    dollar_durable = _durable_break_even(curve, "compact_total_usd_micros") if pricing_complete else None
    safety_preserved = bool(
        comparison.get("passed") is True
        and equivalence_report.get("passed") is True
        and comparison.get("legitimate_task_completion_preserved") is True
        and comparison.get("same_exam_verified") is True
    )
    if not safety_preserved:
        status = "BLOCKED_SAFETY_OR_EQUIVALENCE_FAILED"
    elif not pricing_complete:
        status = "UNDECIDABLE_MISSING_PRICING"
    elif dollar_durable is None:
        status = "NO_DURABLE_BREAK_EVEN_WITHIN_HORIZON"
    else:
        status = "DURABLE_BREAK_EVEN_REACHED"
    final_row = curve[-1]
    dollar_claim_earned = bool(status == "DURABLE_BREAK_EVEN_REACHED" and final_row["compact_savings_usd_micros"] is not None and final_row["compact_savings_usd_micros"] > 0)
    if status == "DURABLE_BREAK_EVEN_REACHED" and not dollar_claim_earned:
        status = "NO_DURABLE_BREAK_EVEN_WITHIN_HORIZON"
        dollar_durable = None
    report_body = {
        "schema": REPORT_SCHEMA,
        "benchmark_valid": safety_preserved,
        "status": status,
        "pricing_complete": pricing_complete,
        "dollar_claim_earned": dollar_claim_earned,
        "future_turn_horizon": horizon,
        "headline_basis": "DECLARED_CANONICAL_SCENARIO",
        "canonical_initial_verification_runtime_micros": canonical_runtime,
        "observed_initial_verification_runtime_micros": observed_runtime,
        "token_first_crossing_turn": token_first,
        "token_durable_break_even_turn": token_durable,
        "dollar_first_crossing_turn": dollar_first,
        "dollar_durable_break_even_turn": dollar_durable,
        "final": {
            "full_history_model_input_tokens": final_row["full_history_model_input_tokens"],
            "compact_model_input_tokens": final_row["compact_model_input_tokens"],
            "compact_verification_runtime_micros": final_row["compact_verification_runtime_micros"],
            "full_history_total_usd_micros": final_row["full_history_total_usd_micros"],
            "compact_total_usd_micros": final_row["compact_total_usd_micros"],
            "compact_savings_usd_micros": final_row["compact_savings_usd_micros"],
        },
        "assumptions_hash": assumptions["assumptions_hash"],
        "comparison_hash": source_hashes["comparison_hash"],
        "equivalence_report_hash": source_hashes["equivalence_report_hash"],
        "claim_boundary": (
            "This benchmark reports break-even only under the declared horizon, event schedule, measured packet sizes, receiver-declared canonical verification runtime, and dated pricing assumptions. "
            "Observed wall-clock runtime is retained as evidence but does not set the headline crossing. It does not establish universal net savings. A short task or frequent rehydration may never break even."
        ),
    }
    report = {**report_body, "report_hash": sha256_bytes(canonical_json(report_body))}
    return assumptions, report, curve


def write_break_even_curve(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    fieldnames = [
        "future_turn",
        "event",
        "full_history_model_input_tokens",
        "compact_model_input_tokens",
        "compact_verification_runtime_micros",
        "recompaction_count",
        "rehydration_count",
        "full_history_total_usd_micros",
        "compact_total_usd_micros",
        "compact_savings_usd_micros",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({name: "" if row[name] is None else row[name] for name in fieldnames})


def _points(rows: Sequence[Mapping[str, Any]], field: str, width: int, height: int, high: int) -> str:
    if high <= 0:
        return ""
    count = max(1, len(rows) - 1)
    points: list[str] = []
    for index, row in enumerate(rows):
        value = row[field]
        if value is None:
            continue
        x = 20 + index * (width - 40) // count
        y = height - 20 - int(value) * (height - 40) // high
        points.append(f"{x},{y}")
    return " ".join(points)


def describe_break_even(report: Mapping[str, Any]) -> dict[str, str]:
    status = report["status"]
    if status == "DURABLE_BREAK_EVEN_REACHED":
        turn = int(report["dollar_durable_break_even_turn"])
        return {
            "status": "BREAK-EVEN MEASURED",
            "headline": f"Break-even after {turn} future turns.",
            "subhead": "Under the declared canonical scenario, the compact path catches full history at that turn and remains no more expensive afterward.",
        }
    if status == "NO_DURABLE_BREAK_EVEN_WITHIN_HORIZON":
        return {
            "status": "NO BREAK-EVEN",
            "headline": f"No break-even within {report['future_turn_horizon']} turns.",
            "subhead": "For this horizon and event schedule, full-history loading remains cheaper.",
        }
    if status == "UNDECIDABLE_MISSING_PRICING":
        return {
            "status": "DOLLAR CLAIM UNDECIDABLE",
            "headline": "No dollar break-even calculated.",
            "subhead": "Packet sizes and verification runtime were measured, but complete dated pricing assumptions were not supplied.",
        }
    return {
        "status": "BENCHMARK BLOCKED",
        "headline": "No economic claim permitted.",
        "subhead": "The same-exam or decision-equivalence safety gate did not pass.",
    }


def render_break_even_card(path: Path, report: Mapping[str, Any], curve: Sequence[Mapping[str, Any]]) -> str:
    description = describe_break_even(report)
    pricing = report.get("pricing_complete") is True
    if pricing:
        width, height = 900, 360
        plotted = [
            int(row[field])
            for row in curve
            for field in ("full_history_total_usd_micros", "compact_total_usd_micros")
            if row[field] is not None
        ]
        shared_high = max(plotted) if plotted else 1
        full_points = _points(curve, "full_history_total_usd_micros", width, height, shared_high)
        compact_points = _points(curve, "compact_total_usd_micros", width, height, shared_high)
        break_even_turn = report.get("dollar_durable_break_even_turn")
        if break_even_turn is not None:
            marker_x = 20 + (int(break_even_turn) - 1) * (width - 40) // max(1, len(curve) - 1)
            marker = f'<line x1="{marker_x}" y1="20" x2="{marker_x}" y2="340" stroke="#667892" stroke-dasharray="8 8"/><text x="{min(marker_x + 8, 790)}" y="42" fill="#aebbd0" font-size="18">break-even: turn {int(break_even_turn)}</text>'
        else:
            marker = ""
        graph = f'''<svg viewBox="0 0 900 360" role="img" aria-label="Cumulative cost curve using one shared vertical scale">
<line x1="20" y1="340" x2="880" y2="340" stroke="#354052"/>
<line x1="20" y1="20" x2="20" y2="340" stroke="#354052"/>
<polyline points="{escape(full_points)}" fill="none" stroke="#d5dceb" stroke-width="5"/>
<polyline points="{escape(compact_points)}" fill="none" stroke="#8aa4c8" stroke-width="5"/>
{marker}
</svg>'''
    else:
        graph = '<div class="unpriced">Dollar curve withheld: pricing assumptions incomplete.</div>'
    final = report["final"]
    html = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenLine Half-Life Break-Even</title>
<style>
:root {{ color-scheme: dark; }} * {{ box-sizing:border-box; }} body {{ margin:0; min-height:100vh; display:grid; place-items:center; background:#090c12; color:#f4f7fb; font-family:ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }}
.card {{ width:min(1040px,94vw); padding:clamp(28px,6vw,68px); border:1px solid #2b3442; border-radius:28px; background:linear-gradient(145deg,#121722,#0c1017); }}
.eyebrow {{ color:#98a7bc; letter-spacing:.14em; text-transform:uppercase; font-size:13px; }} .status {{ display:inline-block; margin-top:18px; border:1px solid #3a4659; border-radius:999px; padding:8px 12px; font-size:13px; font-weight:700; }}
h1 {{ margin:24px 0 12px; font-size:clamp(40px,7vw,78px); line-height:1; letter-spacing:-.045em; }} .sub {{ color:#c6d0df; font-size:clamp(20px,3vw,30px); line-height:1.25; max-width:880px; }}
.graph {{ margin-top:34px; padding:18px; border:1px solid #293342; border-radius:18px; background:#0d121a; }} svg {{ width:100%; height:auto; }} .legend {{ display:flex; gap:22px; color:#9dacbf; font-size:14px; }}
.metrics {{ display:grid; grid-template-columns:repeat(3,1fr); gap:14px; margin-top:24px; }} .metric {{ padding:16px; background:#171d29; border:1px solid #2a3342; border-radius:14px; }} .label {{ color:#8f9db2; font-size:12px; text-transform:uppercase; letter-spacing:.08em; }} .value {{ margin-top:7px; font-size:24px; font-weight:700; }}
.unpriced {{ padding:70px 20px; text-align:center; color:#a9b6c8; }} .byline {{ margin-top:26px; color:#c8d3e2; font-size:15px; font-weight:700; }} .footer {{ margin-top:8px; color:#75849a; font-size:14px; }} @media(max-width:700px){{.metrics{{grid-template-columns:1fr;}}}}
</style></head><body><main class="card">
<div class="eyebrow">OpenLine Half-Life · Save-File Economics · Declared Assumptions</div>
<div class="status">{escape(description['status'])}</div><h1>{escape(description['headline'])}</h1><p class="sub">{escape(description['subhead'])}</p>
<div class="graph">{graph}<div class="legend"><span>Full-history loading</span><span>Periodic verification + compact-state loading</span></div></div>
<section class="metrics"><div class="metric"><div class="label">Full-history tokens</div><div class="value">{final['full_history_model_input_tokens']:,}</div></div><div class="metric"><div class="label">Compact-path tokens</div><div class="value">{final['compact_model_input_tokens']:,}</div></div><div class="metric"><div class="label">Canonical initial verification</div><div class="value">{report['canonical_initial_verification_runtime_micros']:,} µs</div></div><div class="metric"><div class="label">Observed this run</div><div class="value">{report['observed_initial_verification_runtime_micros']:,} µs</div></div></section>
<div class="byline">Terrynce White · OpenLine Protocol</div>
<div class="footer">Cost is a secondary benefit of portable continuity. Headline uses the declared canonical scenario; observed runtime is shown separately. Not a universal savings claim.</div>
</main></body></html>'''
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return html


def write_economics_outputs(
    output_dir: Path,
    assumptions: Mapping[str, Any],
    report: Mapping[str, Any],
    curve: Sequence[Mapping[str, Any]],
) -> None:
    write_json(output_dir / "cost_assumptions.json", assumptions)
    write_json(output_dir / "break_even_report.json", report)
    write_break_even_curve(output_dir / "break_even_curve.csv", curve)
    render_break_even_card(output_dir / "break_even_card.html", report, curve)


def read_break_even_curve(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    result: list[dict[str, Any]] = []
    integer_fields = {
        "future_turn",
        "full_history_model_input_tokens",
        "compact_model_input_tokens",
        "compact_verification_runtime_micros",
        "recompaction_count",
        "rehydration_count",
    }
    optional_integer_fields = {
        "full_history_total_usd_micros",
        "compact_total_usd_micros",
        "compact_savings_usd_micros",
    }
    for row in rows:
        parsed: dict[str, Any] = {"event": row["event"]}
        for name in integer_fields:
            parsed[name] = int(row[name])
        for name in optional_integer_fields:
            parsed[name] = None if row[name] == "" else int(row[name])
        result.append(parsed)
    return result


def verify_economics_outputs(output_dir: Path) -> list[str]:
    errors: list[str] = []
    try:
        assumptions = load_json(output_dir / "cost_assumptions.json")
        report = load_json(output_dir / "break_even_report.json")
        curve = read_break_even_curve(output_dir / "break_even_curve.csv")
        comparison = load_json(output_dir / "comparison.json")
        equivalence = load_json(output_dir / "decision_equivalence_report.json")
        declared = assumptions["declared"]
        measured = assumptions["measured"]
        expected_assumptions, expected_report, expected_curve = run_break_even_benchmark(
            declared_assumptions=declared,
            full_history_tokens_per_turn=measured["full_history_tokens_per_turn"],
            compact_state_tokens_per_turn=measured["compact_state_tokens_per_turn"],
            observed_initial_verification_runtime_micros=measured["observed_initial_verification_runtime_micros"],
            comparison=comparison,
            equivalence_report=equivalence,
            source_hashes=assumptions["source_hashes"],
        )
        if assumptions != expected_assumptions:
            errors.append("cost_assumptions_semantic_mismatch")
        if report != expected_report:
            errors.append("break_even_report_semantic_mismatch")
        if curve != expected_curve:
            errors.append("break_even_curve_semantic_mismatch")
        card = (output_dir / "break_even_card.html").read_text(encoding="utf-8")
        description = describe_break_even(report)
        for value in description.values():
            if value not in card:
                errors.append("break_even_card_semantic_mismatch")
                break
        share_card = (output_dir / "share_card.html").read_text(encoding="utf-8")
        if report["dollar_claim_earned"]:
            expected_line = f"Economic break-even after {report['dollar_durable_break_even_turn']} future turns under declared assumptions."
        elif report["status"] == "NO_DURABLE_BREAK_EVEN_WITHIN_HORIZON":
            expected_line = f"No economic break-even within {report['future_turn_horizon']} future turns under declared assumptions."
        else:
            expected_line = "No dollar savings claim earned by this run."
        if expected_line not in share_card:
            errors.append("share_card_economics_statement_mismatch")
    except Exception as exc:
        errors.append(f"economics_verification_failed:{exc}")
    return errors
