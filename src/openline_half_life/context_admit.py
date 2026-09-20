"""context-admit: thin product adapter over the rc3 candidate-admission doorway.

Two operations, composed only of existing Half-Life machinery:

  admit  -- thin wrapper over pipeline.admit_pipeline (the rc3 admission
            doorway). NOT a second admission algorithm. On success the
            admitted-context artifact is the admission output directory, which
            verifies with the existing verify_admission_output_directory.
  check  -- caller-invoked current-standing check: does the admitted compact
            context still match the receiver-protected state implied by a
            supplied current history? CURRENT or REHYDRATE_REQUIRED.

context-admit does not intercept future model calls. A caller must check
current standing before reusing an admitted compact context. If current
history is missing or cannot be verified, the context is not treated as
current.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

from . import __version__
from .candidate_admission import AdmissionRejected, check_evidence_closure
from .compaction import decision_equivalence_report
from .pipeline import admit_pipeline, verify_admission_output_directory
from .reference_replay import reference_projection, source_evidence_index
from .schema import load_trajectory
from .util import canonical_json, load_json, write_json

CHECK_SCHEMA = "openline.half-life.context-admit-check.v1"
CHECK_REASON_ARTIFACT_INVALID = "admitted_artifact_invalid"
CHECK_REASON_HISTORY_MISSING = "history_missing"
CHECK_REASON_HISTORY_UNVERIFIABLE = "history_unverifiable"
CHECK_REASON_EQUIVALENCE_FAILED = "decision_equivalence_failed"
CHECK_REASON_CLOSURE_FAILED = "evidence_closure_failed"

_MAX_MISMATCH_LINES = 10


def _load_policy_public_keys(path: Path) -> set[str]:
    return {
        line.strip()
        for line in path.read_text(encoding="ascii").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def admit_context(
    *,
    trajectory_path: Path,
    candidate_path: Path,
    manifest_path: Path,
    source_signing_key_path: Path,
    output_dir: Path,
    compaction_policy_path: Path,
    compaction_policy_public_key_path: Path,
    operator_approval_signing_key_path: Path,
    replay_latency_micros: int,
    operator_disposition: str = "APPROVE",
) -> dict[str, Any]:
    """Thin wrapper over the rc3 candidate-admission doorway.

    Returns an ACCEPTED record on success (the admission output directory is
    the admitted-context artifact) or a REFUSED record carrying the existing
    rejection reason codes. Raises ValueError for apparatus problems, exactly
    like admit_pipeline.
    """
    try:
        result = admit_pipeline(
            trajectory_path,
            candidate_path,
            manifest_path,
            source_signing_key_path,
            output_dir,
            compaction_policy_path=compaction_policy_path,
            compaction_policy_public_key_path=compaction_policy_public_key_path,
            operator_approval_signing_key_path=operator_approval_signing_key_path,
            replay_latency_micros=replay_latency_micros,
            operator_disposition=operator_disposition,
        )
    except AdmissionRejected as rejected:
        output_dir.mkdir(parents=True, exist_ok=True)
        rejection_path = output_dir / "admission_rejection.json"
        write_json(rejection_path, rejected.report)
        return {
            "schema": "openline.half-life.context-admit-admit.v1",
            "version": __version__,
            "accepted": False,
            "reason_codes": list(rejected.reason_codes),
            "mismatches": rejected.report.get("mismatches", []),
            "rejection_path": str(rejection_path.resolve()),
        }
    admitted_state = load_json(output_dir / "compact_state.json")
    return {
        "schema": "openline.half-life.context-admit-admit.v1",
        "version": __version__,
        "accepted": True,
        "artifact": str(output_dir.resolve()),
        "run_id": result["run_id"],
        "checkpoint_turn": result["checkpoint_turn"],
        "candidate_hash": result["candidate_hash"],
        "compact_state_hash": admitted_state["compact_state_hash"],
        "decision_mismatch_count": result["decision_mismatch_count"],
        "bundle_hash": result["bundle_hash"],
    }


def _fail(reason: str, details: Mapping[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema": CHECK_SCHEMA,
        "version": __version__,
        "current": False,
        "reason_codes": [reason],
        "details": dict(details or {}),
    }
    body.update(extra)
    return body


def check_current_standing(
    *,
    admitted_dir: Path,
    history_path: Path,
    expected_policy_public_keys: set[str],
) -> dict[str, Any]:
    """Caller-invoked current-standing check for an admitted compact context.

    Composed only of existing Half-Life machinery: artifact verification
    (verify_admission_output_directory), trajectory validation
    (load_trajectory: turn schema, run continuity, evidence content binding),
    continuity of the current history against the admitted source handoff,
    the independent reference projection at the current turn, the existing
    decision-equivalence comparison, and the existing evidence-closure check.

    Fail-closed: missing, malformed, incomplete, or unverifiable current
    history NEVER produces CURRENT. Standing is never inferred from the
    admitted artifact itself; it is historical evidence of admission, not
    proof of current standing.
    """
    base = {
        "admitted_dir": str(admitted_dir),
        "history": str(history_path),
    }
    if not expected_policy_public_keys:
        raise ValueError("expected_policy_public_keys must not be empty")

    verification = verify_admission_output_directory(
        admitted_dir, expected_policy_public_keys=expected_policy_public_keys
    )
    if verification.get("valid") is not True:
        return _fail(
            CHECK_REASON_ARTIFACT_INVALID,
            {"verification_errors": verification.get("errors", [])},
            **base,
        )

    checkpoint = load_json(admitted_dir / "checkpoint.json")
    compact_state = load_json(admitted_dir / "compact_state.json")
    candidate = load_json(admitted_dir / "candidate.json")
    handoff = load_json(admitted_dir / "full_history_handoff.json")
    run_id = checkpoint.get("run_id")
    checkpoint_turn = int(checkpoint.get("checkpoint_turn", 0))

    if not history_path.is_file():
        return _fail(
            CHECK_REASON_HISTORY_MISSING,
            {"path": str(history_path)},
            run_id=run_id,
            admission_checkpoint_turn=checkpoint_turn,
            **base,
        )
    try:
        turns = load_trajectory(history_path)
    except Exception as exc:
        return _fail(
            CHECK_REASON_HISTORY_UNVERIFIABLE,
            {"load_error": f"{type(exc).__name__}: {exc}"},
            run_id=run_id,
            admission_checkpoint_turn=checkpoint_turn,
            **base,
        )
    current_turn = len(turns)
    if turns[0].get("run_id") != run_id:
        return _fail(
            CHECK_REASON_HISTORY_UNVERIFIABLE,
            {"run_id_mismatch": {"history_run_id": turns[0].get("run_id"), "admitted_run_id": run_id}},
            run_id=run_id,
            admission_checkpoint_turn=checkpoint_turn,
            current_turn=current_turn,
            **base,
        )
    if current_turn < checkpoint_turn:
        return _fail(
            CHECK_REASON_HISTORY_UNVERIFIABLE,
            {
                "history_ends_before_admission_checkpoint": {
                    "current_turn": current_turn,
                    "admission_checkpoint_turn": checkpoint_turn,
                }
            },
            run_id=run_id,
            admission_checkpoint_turn=checkpoint_turn,
            current_turn=current_turn,
            **base,
        )
    handoff_turns = handoff.get("turns", [])
    if len(handoff_turns) != checkpoint_turn or any(
        canonical_json(handoff_turns[index]) != canonical_json(turns[index])
        for index in range(checkpoint_turn)
    ):
        return _fail(
            CHECK_REASON_HISTORY_UNVERIFIABLE,
            {"continuity_break": "current history does not extend the admitted source handoff"},
            run_id=run_id,
            admission_checkpoint_turn=checkpoint_turn,
            current_turn=current_turn,
            **base,
        )

    try:
        reference = reference_projection(turns, current_turn)
    except Exception as exc:
        return _fail(
            CHECK_REASON_HISTORY_UNVERIFIABLE,
            {"standing_not_computable": f"{type(exc).__name__}: {exc}"},
            run_id=run_id,
            admission_checkpoint_turn=checkpoint_turn,
            current_turn=current_turn,
            **base,
        )

    reason_codes: list[str] = []
    details: dict[str, Any] = {}

    equivalence = decision_equivalence_report(reference, compact_state, source_chain_active_bytes=0)
    if equivalence.get("passed") is not True:
        reason_codes.append(CHECK_REASON_EQUIVALENCE_FAILED)
        mismatches = equivalence.get("mismatches", [])
        details["decision_mismatches"] = [
            {
                "decision_key": entry.get("decision_key"),
                "admitted": entry.get("compact_state"),
                "current": entry.get("full_history"),
            }
            for entry in mismatches
        ]

    closure = check_evidence_closure(candidate, source_evidence_index(turns, current_turn))
    if closure.get("valid") is not True:
        reason_codes.append(CHECK_REASON_CLOSURE_FAILED)
        details["evidence_closure_mismatches"] = closure.get("mismatches", [])

    if reason_codes:
        return {
            "schema": CHECK_SCHEMA,
            "version": __version__,
            "current": False,
            "reason_codes": reason_codes,
            "details": details,
            "run_id": run_id,
            "admission_checkpoint_turn": checkpoint_turn,
            "current_turn": current_turn,
            **base,
        }
    return {
        "schema": CHECK_SCHEMA,
        "version": __version__,
        "current": True,
        "reason_codes": [],
        "details": {},
        "run_id": run_id,
        "admission_checkpoint_turn": checkpoint_turn,
        "current_turn": current_turn,
        **base,
    }


def _admit_human(result: Mapping[str, Any]) -> str:
    if result["accepted"]:
        return "\n".join(
            [
                "ACCEPTED",
                f"Admitted context: {result['artifact']}",
                f"Checkpoint: turn {result['checkpoint_turn']} (run {result['run_id']})",
                f"Candidate hash: {result['candidate_hash']}",
                f"Compact-state hash: {result['compact_state_hash']}",
            ]
        )
    lines = [
        "REFUSED",
        f"Reason codes: {', '.join(result['reason_codes'])}",
        f"Rejection report: {result['rejection_path']}",
    ]
    return "\n".join(lines)


def _check_human(result: Mapping[str, Any]) -> str:
    if result["current"]:
        return "\n".join(
            [
                "CURRENT",
                f"Admitted context matches receiver-protected state at turn {result['current_turn']} (run {result['run_id']}).",
            ]
        )
    lines = [
        "REHYDRATE_REQUIRED",
        f"Reason codes: {', '.join(result['reason_codes'])}",
    ]
    details = result.get("details", {})
    for mismatch in details.get("decision_mismatches", [])[:_MAX_MISMATCH_LINES]:
        lines.append(
            f"  {mismatch.get('decision_key')}: admitted={json.dumps(mismatch.get('admitted'), sort_keys=True)} "
            f"current={json.dumps(mismatch.get('current'), sort_keys=True)}"
        )
    for mismatch in details.get("evidence_closure_mismatches", [])[:_MAX_MISMATCH_LINES]:
        lines.append(f"  evidence {mismatch.get('evidence_id')}: {mismatch.get('reason')}")
    for key, value in details.items():
        if key not in {"decision_mismatches", "evidence_closure_mismatches"}:
            lines.append(f"  {key}: {json.dumps(value, sort_keys=True)}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="context-admit",
        description="Admit an externally produced compact-state candidate, and later check whether the admitted context is still current.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    admit = sub.add_parser("admit", help="admit an externally produced compact-state candidate")
    admit.add_argument("trajectory", type=Path)
    admit.add_argument("--candidate", type=Path, required=True)
    admit.add_argument("--manifest", type=Path, required=True)
    admit.add_argument("--compaction-policy", type=Path, required=True)
    admit.add_argument("--compaction-policy-public-key", type=Path, required=True)
    admit.add_argument("--source-signing-key", type=Path, required=True)
    admit.add_argument("--operator-approval-signing-key", type=Path, required=True)
    admit.add_argument("--replay-latency-micros", type=int, required=True)
    admit.add_argument("--operator-disposition", choices=["APPROVE", "DENY"], default="APPROVE")
    admit.add_argument("--out", type=Path, required=True)
    admit.add_argument("--json", action="store_true")

    check = sub.add_parser("check", help="check whether an admitted context still matches current receiver-protected state")
    check.add_argument("admitted", type=Path)
    check.add_argument("--history", type=Path, required=True)
    check.add_argument("--compaction-policy-public-key", type=Path, required=True)
    check.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    try:
        if args.command == "admit":
            result = admit_context(
                trajectory_path=args.trajectory,
                candidate_path=args.candidate,
                manifest_path=args.manifest,
                source_signing_key_path=args.source_signing_key,
                output_dir=args.out,
                compaction_policy_path=args.compaction_policy,
                compaction_policy_public_key_path=args.compaction_policy_public_key,
                operator_approval_signing_key_path=args.operator_approval_signing_key,
                replay_latency_micros=args.replay_latency_micros,
                operator_disposition=args.operator_disposition,
            )
            if args.json:
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                print(_admit_human(result))
            return 0 if result["accepted"] else 1
        result = check_current_standing(
            admitted_dir=args.admitted,
            history_path=args.history,
            expected_policy_public_keys=_load_policy_public_keys(args.compaction_policy_public_key),
        )
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(_check_human(result))
        return 0 if result["current"] else 1
    except Exception as exc:  # apparatus error: malformed invocation inputs, unreadable keys, broken policy
        print(f"error: {type(exc).__name__}: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
