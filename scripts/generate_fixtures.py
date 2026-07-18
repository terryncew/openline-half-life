#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def h(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def evidence(evidence_id: str, value: str, observed_turn: int, expires_after_turns: int = 100) -> dict[str, Any]:
    return {
        "id": evidence_id,
        "sha256": h(value),
        "observed_turn": observed_turn,
        "expires_after_turns": expires_after_turns,
    }


def claim(
    claim_id: str,
    slot: str,
    value: str,
    status: str,
    refs: list[str],
    turn: int,
    *,
    material: bool = True,
) -> dict[str, Any]:
    return {
        "id": claim_id,
        "slot": slot,
        "value": value,
        "material": material,
        "support_status": status,
        "evidence_refs": refs,
        "last_verified_turn": turn,
    }


def constraint(constraint_id: str, text: str, refs: list[str], turn: int, active: bool = True) -> dict[str, Any]:
    return {
        "id": constraint_id,
        "text": text,
        "active": active,
        "evidence_refs": refs,
        "last_verified_turn": turn,
    }


def outcome(outcome_id: str, text: str, refs: list[str], confirmed: bool = True) -> dict[str, Any]:
    return {"id": outcome_id, "text": text, "confirmed": confirmed, "evidence_refs": refs}


def measurements(kind: str, ucr: int = 0) -> dict[str, int]:
    if kind == "high":
        return {
            "kappa_micros": 800_000,
            "epsilon_micros": 700_000,
            "delta_hol_micros": 650_000,
            "phi_star_micros": 600_000,
            "ucr_micros": ucr,
        }
    return {
        "kappa_micros": 0,
        "epsilon_micros": 0,
        "delta_hol_micros": 0,
        "phi_star_micros": 995_000,
        "ucr_micros": ucr,
    }


def turn(
    run_id: str,
    number: int,
    *,
    metric_kind: str = "low",
    ucr: int = 0,
    claims: list[dict[str, Any]] | None = None,
    evidence_items: list[dict[str, Any]] | None = None,
    constraints: list[dict[str, Any]] | None = None,
    outcomes: list[dict[str, Any]] | None = None,
    unresolved: list[str] | None = None,
    summary: str | None = None,
) -> dict[str, Any]:
    return {
        "schema": "openline.half-life.turn.v1",
        "run_id": run_id,
        "turn": number,
        "objective": "Deploy Atlas safely while preserving region, budget, privacy, and confirmed completion state.",
        "summary": summary if summary is not None else f"Atlas execution checkpoint {number}.",
        "measurements": measurements(metric_kind, ucr),
        "claims": claims or [],
        "evidence": evidence_items or [],
        "constraints": constraints or [],
        "outcomes": outcomes or [],
        "unresolved_questions": unresolved or [],
        "cost": {"input_tokens": 900 + number * 3, "output_tokens": 240 + number},
    }


def write(name: str, rows: list[dict[str, Any]]) -> None:
    path = ROOT / "fixtures" / name
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")


def base_events(number: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    ev: list[dict[str, Any]] = []
    cl: list[dict[str, Any]] = []
    co: list[dict[str, Any]] = []
    out: list[dict[str, Any]] = []
    if number == 1:
        ev.append(evidence("ev-region-current", "region=us-west-2", 1, 100))
        cl.append(claim("claim-region-1", "deployment_region", "us-west-2", "supported", ["ev-region-current"], 1))
    if number == 2:
        ev.append(evidence("ev-budget-current", "max_batch_size=300", 2, 100))
        cl.append(claim("claim-budget-2", "max_batch_size", "300", "supported", ["ev-budget-current"], 2))
    if number == 3:
        ev.append(evidence("ev-privacy", "never-delete-customer-data", 3, 100))
        co.append(constraint("privacy-floor", "Never delete customer data.", ["ev-privacy"], 3))
    if number == 4:
        ev.append(evidence("ev-api-v2", "api_version=v2", 4, 100))
        cl.append(claim("claim-api-4", "api_version", "v2", "supported", ["ev-api-v2"], 4))
    if number == 5:
        ev.append(evidence("ev-api-v1-old", "api_version=v1", 5, 12))
    if number == 10:
        ev.append(evidence("ev-migration", "migration-complete", 10, 100))
        out.append(outcome("migration-complete", "Migration completed and verified.", ["ev-migration"]))
    if number == 20:
        ev.append(evidence("ev-tests", "tests-complete", 20, 100))
        out.append(outcome("tests-complete", "Held-out deployment tests completed.", ["ev-tests"]))
    if number == 30:
        ev.append(evidence("ev-owner", "owner-approved", 30, 100))
        out.append(outcome("owner-approved", "Receiver approved the deployment plan.", ["ev-owner"]))
    return ev, cl, co, out


def gradual_drift() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number in range(1, 71):
        ev, cl, co, out = base_events(number)
        ucr = 0
        kind = "high" if number in {60, 61} else "low"
        if 45 <= number <= 55:
            cl.extend(
                [
                    claim(f"claim-region-false-{number}", "deployment_region", "eu-west-1", "unsupported", [], number),
                    claim(f"claim-budget-false-{number}", "max_batch_size", "500", "unsupported", [], number),
                    claim(f"claim-api-stale-{number}", "api_version", "v1", "supported", ["ev-api-v1-old"], 5),
                ]
            )
            ucr = 666_667
        if number in {40, 59, 60, 61}:
            cl.extend(
                [
                    claim(f"claim-region-refresh-{number}", "deployment_region", "us-west-2", "supported", ["ev-region-current"], number),
                    claim(f"claim-budget-refresh-{number}", "max_batch_size", "300", "supported", ["ev-budget-current"], number),
                    claim(f"claim-api-refresh-{number}", "api_version", "v2", "supported", ["ev-api-v2"], number),
                ]
            )
        if number == 50:
            co.append(constraint("privacy-floor", "Never delete customer data.", ["ev-privacy"], 50))
        summary = f"Atlas checkpoint {number}."
        if number == 61:
            summary = "Replacement requested after persistent coherence signal; recent summary omits the privacy floor."
        rows.append(
            turn(
                "gradual-drift-demo",
                number,
                metric_kind=kind,
                ucr=ucr,
                claims=cl,
                evidence_items=ev,
                constraints=co,
                outcomes=out,
                unresolved=["What is the post-cutover latency under peak load?"],
                summary=summary,
            )
        )
    return rows


def healthy() -> list[dict[str, Any]]:
    rows = []
    for number in range(1, 71):
        ev, cl, co, out = base_events(number)
        if number in {20, 40, 60}:
            cl.extend(
                [
                    claim(f"healthy-region-{number}", "deployment_region", "us-west-2", "supported", ["ev-region-current"], number),
                    claim(f"healthy-budget-{number}", "max_batch_size", "300", "supported", ["ev-budget-current"], number),
                ]
            )
        rows.append(turn("healthy-demo", number, claims=cl, evidence_items=ev, constraints=co, outcomes=out))
    return rows


def sudden_failure() -> list[dict[str, Any]]:
    rows = []
    for number in range(1, 13):
        ev, cl, co, out = base_events(number)
        kind = "high" if number in {8, 9} else "low"
        rows.append(turn("sudden-failure-demo", number, metric_kind=kind, claims=cl, evidence_items=ev, constraints=co, outcomes=out))
    return rows


def stale_replay() -> list[dict[str, Any]]:
    rows = []
    for number in range(1, 13):
        ev, cl, co, out = base_events(number)
        if number == 1:
            ev.append(evidence("ev-short-lived", "credential=old", 1, 2))
        if number >= 8:
            cl.append(claim(f"stale-{number}", "credential", "old", "supported", ["ev-short-lived"], 1))
        rows.append(turn("stale-replay-demo", number, claims=cl, evidence_items=ev, constraints=co, outcomes=out))
    return rows


def unsupported_repetition() -> list[dict[str, Any]]:
    rows = []
    for number in range(1, 13):
        ev, cl, co, out = base_events(number)
        ucr = 0
        if number >= 6:
            cl.append(claim(f"unsupported-{number}", "region_override", "moon-1", "unsupported", [], number))
            ucr = 1_000_000
        rows.append(turn("unsupported-repetition-demo", number, ucr=ucr, claims=cl, evidence_items=ev, constraints=co, outcomes=out))
    return rows


def lost_constraint() -> list[dict[str, Any]]:
    rows = []
    for number in range(1, 13):
        ev, cl, co, out = base_events(number)
        summary = "Compact summary retained." if number < 12 else "Compact summary accidentally omitted the privacy floor."
        rows.append(turn("lost-constraint-demo", number, claims=cl, evidence_items=ev, constraints=co, outcomes=out, summary=summary))
    return rows


if __name__ == "__main__":
    write("gradual_drift.jsonl", gradual_drift())
    write("healthy.jsonl", healthy())
    write("sudden_failure.jsonl", sudden_failure())
    write("stale_evidence_replay.jsonl", stale_replay())
    write("unsupported_repetition.jsonl", unsupported_repetition())
    write("lost_constraint.jsonl", lost_constraint())
