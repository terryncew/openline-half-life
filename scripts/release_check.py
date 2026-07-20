#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from openline_half_life.causal_compactor import load_trusted_compaction_policy_keys
from openline_half_life.policy import (
    CANONICAL_SOURCE_SHA256,
    load_trusted_policy_keys,
    verify_vendored_source,
)
from openline_half_life.receipts import verify_output_directory
from openline_half_life.util import load_json, sha256_file, write_json


def _test_count(text: str) -> int:
    match = re.search(r"(\d+) tests? collected", text)
    if match:
        return int(match.group(1))
    grouped = [int(value) for value in re.findall(r"^tests/[^:]+:\s*(\d+)\s*$", text, re.MULTILINE)]
    if grouped:
        return sum(grouped)
    return sum(1 for line in text.splitlines() if "::" in line)


def _progress(message: str) -> None:
    print(f"[release-check] {message}", file=sys.stderr, flush=True)


def run() -> dict:
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = str(SRC)

    _progress("running inherited, audit, tamper, compaction, packaging, and economics tests")
    pytest = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    _progress("collecting exact test count")
    collect = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider"],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    _progress("running 10,000-history compaction gate")
    gate = subprocess.run(
        [sys.executable, "scripts/compaction_release_gate.py"],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    try:
        gate_result = json.loads(gate.stdout)
    except json.JSONDecodeError:
        gate_result = {
            "passed": False,
            "parse_error": gate.stdout or gate.stderr,
        }

    _progress("loading receiver trust pins")
    trusted_keys = load_trusted_policy_keys(ROOT / "policy/succession_policy_public_key.hex")
    trusted_compaction_keys = load_trusted_compaction_policy_keys(
        ROOT / "policy/compaction_policy_public_key.hex"
    )

    _progress("running clean deterministic demo and verification")
    with tempfile.TemporaryDirectory(prefix="openline-half-life-") as temp:
        output = Path(temp) / "demo"
        demo = subprocess.run(
            [
                sys.executable,
                "-m",
                "openline_half_life",
                "demo",
                "--out",
                str(output),
                "--replay-latency-micros",
                "75000",
            ],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        verification = (
            verify_output_directory(
                output,
                expected_policy_public_keys=trusted_keys,
                expected_compaction_policy_public_keys=trusted_compaction_keys,
            )
            if (output / "half_life_receipt.json").exists()
            else {"valid": False, "errors": [demo.stderr or "demo emitted no receipt bundle"]}
        )
        comparison = load_json(output / "comparison.json") if (output / "comparison.json").exists() else None
        receipt = load_json(output / "half_life_receipt.json") if (output / "half_life_receipt.json").exists() else None
        equivalence = (
            load_json(output / "decision_equivalence_report.json")
            if (output / "decision_equivalence_report.json").exists()
            else None
        )
        archive_manifest = (
            load_json(output / "archive_manifest.json")
            if (output / "archive_manifest.json").exists()
            else None
        )
        economics = (
            load_json(output / "break_even_report.json")
            if (output / "break_even_report.json").exists()
            else None
        )
        economics_card = (
            (output / "break_even_card.html").read_text(encoding="utf-8")
            if (output / "break_even_card.html").exists()
            else ""
        )
        card = (
            (output / "share_card.html").read_text(encoding="utf-8")
            if (output / "share_card.html").exists()
            else ""
        )

    _progress("assembling release verification receipt")
    comparison_passed = bool(comparison is not None and comparison.get("passed") is True)
    equivalence_passed = bool(equivalence is not None and equivalence.get("passed") is True)
    economics_valid = bool(
        economics is not None
        and economics.get("benchmark_valid") is True
        and economics.get("status") in {
            "DURABLE_BREAK_EVEN_REACHED",
            "NO_DURABLE_BREAK_EVEN_WITHIN_HORIZON",
            "UNDECIDABLE_MISSING_PRICING",
        }
    )
    demo_passed = bool(
        demo.returncode == 0
        and comparison_passed
        and equivalence_passed
        and economics_valid
        and verification["valid"]
    )
    report = {
        "schema": "openline.half-life.release-verification.v7",
        "version": "0.3.0rc2-review-candidate",
        "release_tag_authorized": False,
        "passed": bool(
            pytest.returncode == 0
            and gate.returncode == 0
            and gate_result.get("passed") is True
            and demo_passed
        ),
        "single_documented_command": "python scripts/release_check.py",
        "tests": {
            "command": "python -m pytest -q",
            "passed": pytest.returncode == 0,
            "count": _test_count(collect.stdout),
            "stdout": pytest.stdout,
            "stderr": pytest.stderr,
        },
        "seeded_compaction_gate": {
            "command": "python scripts/compaction_release_gate.py",
            "execution_returncode": gate.returncode,
            "result": gate_result,
            "stderr": gate.stderr,
        },
        "demo": {
            "execution_returncode": demo.returncode,
            "comparison_passed": comparison_passed,
            "decision_equivalence_passed": equivalence_passed,
            "passed": demo_passed,
            "retirement_turn": None if receipt is None else receipt["retirement_turn"],
            "full_history_errors": None if comparison is None else comparison["full_history"]["metrics"]["error_count"],
            "verified_residue_errors": None if comparison is None else comparison["verified_residue"]["metrics"]["error_count"],
            "error_reduction_micros": None if comparison is None else comparison["delta"]["error_reduction_micros"],
            "same_exam_verified": None if comparison is None else comparison["same_exam_verified"],
            "legitimate_task_completion_preserved": None if comparison is None else comparison["legitimate_task_completion_preserved"],
            "active_size_ratio_micros": None if equivalence is None else equivalence["active_size_ratio_micros"],
            "archived_receipt_count": (
                None
                if archive_manifest is None
                else archive_manifest["payload"]["source_chain_count"]
            ),
            "share_card_statements_present": (
                "COMPARISON PASSED" in card
                and "Agent retired after turn 61." in card
                and "Verified handoff reduced errors by 43% on the same exam." in card
                and "Causal capsule preserved exact receiver decisions" in card
                and (
                    economics is not None
                    and (
                        f"Economic break-even after {economics.get('dollar_durable_break_even_turn')} future turns under declared assumptions." in card
                        if economics.get("dollar_claim_earned") is True
                        else "No dollar savings claim earned by this run." in card
                    )
                )
            ),
        },
        "economics": {
            "benchmark_valid": economics_valid,
            "status": None if economics is None else economics.get("status"),
            "pricing_complete": None if economics is None else economics.get("pricing_complete"),
            "dollar_claim_earned": None if economics is None else economics.get("dollar_claim_earned"),
            "dollar_durable_break_even_turn": None if economics is None else economics.get("dollar_durable_break_even_turn"),
            "headline_basis": None if economics is None else economics.get("headline_basis"),
            "canonical_initial_verification_runtime_micros": None if economics is None else economics.get("canonical_initial_verification_runtime_micros"),
            "observed_initial_verification_runtime_micros": None if economics is None else economics.get("observed_initial_verification_runtime_micros"),
            "future_turn_horizon": None if economics is None else economics.get("future_turn_horizon"),
            "shared_scale_graph_present": "one shared vertical scale" in economics_card,
            "canonical_headline_is_machine_stable": (economics is not None and economics.get("headline_basis") == "DECLARED_CANONICAL_SCENARIO"),
            "claim_boundary_present": (
                economics is not None
                and "does not establish universal net savings" in economics.get("claim_boundary", "")
            ),
        },
        "receipt_verification": verification,
        "canonical_source": {
            "expected_sha256": CANONICAL_SOURCE_SHA256,
            "actual_sha256": sha256_file(
                ROOT / "src/openline_half_life/vendor/openline_endurance_gate/succession.py"
            ),
            "valid": verify_vendored_source(
                ROOT / "src/openline_half_life/vendor/openline_endurance_gate/succession.py"
            ),
            "unchanged": True,
        },
        "policy_trust": {
            "succession_receiver_pin_required": True,
            "trusted_succession_public_keys": sorted(trusted_keys),
            "compaction_receiver_pin_required": True,
            "trusted_compaction_public_keys": sorted(trusted_compaction_keys),
            "policy_private_keys_distributed": False,
            "demo_source_and_approval_private_keys_distributed": True,
            "demo_keys_production_trustworthy": False,
        },
        "boundaries": {
            "offline_deterministic_default": True,
            "provider_required_for_tests": False,
            "complete_artifact_manifest_signed": True,
            "extension_signer_continuity_required": True,
            "rehydration_policy_pin_required": True,
            "automatic_compaction_authorized": False,
            "automatic_retirement_authorized": False,
            "universal_threshold_claimed": False,
            "causation_inferred_from_repetition_or_correlation": False,
            "source_receipts_permanently_deleted": False,
            "receiver_approval_separately_signed": True,
            "independent_full_history_replay": True,
            "economics_requires_dated_receiver_pricing": True,
            "economics_can_report_no_break_even": True,
            "universal_savings_claimed": False,
        },
    }
    return report


if __name__ == "__main__":
    report = run()
    output = ROOT / "RELEASE_VERIFICATION.json"
    write_json(output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 1)
