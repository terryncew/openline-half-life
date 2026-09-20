"""Tests for the context-admit thin adapter (product surface, no new semantics).

admit: thin wrapper over the rc3 candidate-admission doorway (admit_pipeline).
check: caller-invoked current-standing check composed only of existing
       Half-Life machinery (artifact verification, trajectory validation,
       reference projection, decision equivalence, evidence closure).

Fail-closed contract: missing, malformed, incomplete, or unverifiable current
history NEVER produces CURRENT. Standing is never inferred from the admitted
artifact itself.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from openline_half_life.context_admit import (
    admit_context,
    check_current_standing,
    main as context_admit_main,
)

from test_candidate_admission import (
    FIXTURES,
    POLICY,
    POLICY_KEYS,
    ROOT,
    REPLAY_LATENCY_MICROS,
    admission_kwargs,
)

C3_HISTORY = FIXTURES / "context3_history.jsonl"
FROZEN_P5 = ROOT / "evidence" / "frozen-failures" / "p5-evidence-refs-emptied"


def _policy_public_keys() -> set[str]:
    return {line.strip() for line in POLICY_KEYS.read_text(encoding="ascii").splitlines() if line.strip() and not line.lstrip().startswith("#")}


def _admit_kwargs(candidate_path: Path, manifest_path: Path, history_path: Path, *, out: Path):
    kwargs = admission_kwargs("good", "good", out=out)
    kwargs["trajectory_path"] = history_path
    kwargs["candidate_path"] = candidate_path
    kwargs["manifest_path"] = manifest_path
    return kwargs


def _admit_fixture(candidate: str, manifest: str, history: Path, *, out: Path):
    return admit_context(**_admit_kwargs(
        FIXTURES / f"candidate_{candidate}.json",
        FIXTURES / f"candidate_manifest_{manifest}.json",
        history,
        out=out,
    ))


def _admit_context3(*, out: Path):
    return admit_context(**_admit_kwargs(
        FIXTURES / "context3_candidate_good.json",
        FIXTURES / "context3_candidate_manifest_good.json",
        C3_HISTORY,
        out=out,
    ))


def _check(admitted: Path, history: Path):
    return check_current_standing(
        admitted_dir=admitted,
        history_path=history,
        expected_policy_public_keys=_policy_public_keys(),
    )


# A1: honest candidate (live constraint + unresolved contradiction + closure) -> ACCEPTED.
def test_a1_honest_candidate_accepted(tmp_path):
    result = _admit_fixture("good", "good", FIXTURES / "history.jsonl", out=tmp_path / "out")
    assert result["accepted"] is True
    assert result["decision_mismatch_count"] == 0
    assert Path(result["artifact"]).is_dir()
    assert (tmp_path / "out" / "compact_state.json").is_file()


# A2: missing protected constraint -> REFUSED.
def test_a2_missing_protected_constraint_refused(tmp_path):
    result = _admit_fixture("drop_constraint", "drop_constraint", FIXTURES / "history.jsonl", out=tmp_path / "out")
    assert result["accepted"] is False
    assert "decision_equivalence_failed" in result["reason_codes"]


# A3: missing unresolved contradiction -> REFUSED.
def test_a3_missing_unresolved_contradiction_refused(tmp_path):
    result = _admit_fixture("drop_contradiction", "drop_contradiction", FIXTURES / "history.jsonl", out=tmp_path / "out")
    assert result["accepted"] is False
    assert "decision_equivalence_failed" in result["reason_codes"]


# A4: evidence reference retained but required evidence object deleted -> REFUSED.
def test_a4_deleted_evidence_object_refused(tmp_path):
    result = admit_context(**_admit_kwargs(
        FROZEN_P5 / "candidate_p5.json",
        FROZEN_P5 / "manifest_p5.json",
        FIXTURES / "history.jsonl",
        out=tmp_path / "out",
    ))
    assert result["accepted"] is False
    assert "evidence_closure_failed" in result["reason_codes"]


# A5: evidence object altered -> REFUSED.
def test_a5_altered_evidence_object_refused(tmp_path):
    result = _admit_fixture("evidence_altered", "evidence_altered", FIXTURES / "history.jsonl", out=tmp_path / "out")
    assert result["accepted"] is False
    assert "evidence_closure_failed" in result["reason_codes"]


# A6: compiler-different but protected, canonical evidence intact -> ACCEPTED.
def test_a6_compiler_different_candidate_accepted(tmp_path):
    result = _admit_fixture("compiler_different", "compiler_different", FIXTURES / "history.jsonl", out=tmp_path / "out")
    assert result["accepted"] is True
    assert result["decision_mismatch_count"] == 0


# C1: admitted context with fresh current standing -> CURRENT.
def test_c1_fresh_standing_current(tmp_path):
    admitted = _admit_fixture("good", "good", FIXTURES / "history.jsonl", out=tmp_path / "out")
    result = _check(tmp_path / "out", FIXTURES / "history.jsonl")
    assert result["current"] is True
    assert result["reason_codes"] == []
    assert result["current_turn"] == admitted["checkpoint_turn"] == 6


# C2: required evidence stale under existing _fresh() semantics -> REHYDRATE_REQUIRED.
def test_c2_stale_evidence_rehydrate_required(tmp_path):
    _admit_context3(out=tmp_path / "out")
    result = _check(tmp_path / "out", C3_HISTORY)
    assert result["current"] is False
    assert "decision_equivalence_failed" in result["reason_codes"]
    keys = {entry["decision_key"] for entry in result["details"]["decision_mismatches"]}
    assert "tombstone:constraint:c-live" in keys
    assert result["current_turn"] == 7


# C3: required protected constraint stale/DENY -> REHYDRATE_REQUIRED.
def test_c3_stale_constraint_rehydrate_required(tmp_path):
    _admit_context3(out=tmp_path / "out")
    result = _check(tmp_path / "out", C3_HISTORY)
    assert result["current"] is False
    assert "decision_equivalence_failed" in result["reason_codes"]
    by_key = {entry["decision_key"]: entry for entry in result["details"]["decision_mismatches"]}
    assert by_key["constraint:c-live"]["admitted"]["disposition"] == "COMMIT"
    assert by_key["tombstone:constraint:c-live"]["current"] == {"disposition": "DENY", "status": "stale"}


# C4: current history missing -> never CURRENT.
def test_c4_missing_history_never_current(tmp_path):
    _admit_context3(out=tmp_path / "out")
    result = _check(tmp_path / "out", tmp_path / "no-such-history.jsonl")
    assert result["current"] is False
    assert result["reason_codes"] == ["history_missing"]


# C5: current history unverifiable/tampered -> never CURRENT.
def test_c5_tampered_history_never_current(tmp_path):
    _admit_context3(out=tmp_path / "out")
    lines = (C3_HISTORY.read_text(encoding="utf-8").splitlines())
    tampered = [json.loads(line) for line in lines]
    # Schema-valid change inside the admitted checkpoint range: the history no
    # longer extends the admitted source handoff.
    tampered[1]["claims"][0]["value"] = {"tampered": True}
    tampered_path = tmp_path / "tampered.jsonl"
    tampered_path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in tampered) + "\n", encoding="utf-8")
    result = _check(tmp_path / "out", tampered_path)
    assert result["current"] is False
    assert result["reason_codes"] == ["history_unverifiable"]


def test_c5b_wrong_run_history_never_current(tmp_path):
    _admit_context3(out=tmp_path / "out")
    result = _check(tmp_path / "out", FIXTURES / "history_other.jsonl")
    assert result["current"] is False
    assert result["reason_codes"] == ["history_unverifiable"]


# C6: admitted artifact tampered -> never CURRENT.
def test_c6_tampered_artifact_never_current(tmp_path):
    _admit_context3(out=tmp_path / "out")
    copied = tmp_path / "copied"
    shutil.copytree(tmp_path / "out", copied)
    compact = json.loads((copied / "compact_state.json").read_text(encoding="utf-8"))
    compact["current_constraints"][0]["text"] = "tampered constraint text"
    (copied / "compact_state.json").write_text(json.dumps(compact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result = _check(copied, C3_HISTORY)
    assert result["current"] is False
    assert result["reason_codes"] == ["admitted_artifact_invalid"]


# C7: rebuild/re-admit after standing loss -> ACCEPTED then CURRENT.
def test_c7_rehydrate_then_current(tmp_path):
    first = _admit_context3(out=tmp_path / "first")
    assert first["accepted"] is True
    assert _check(tmp_path / "first", C3_HISTORY)["current"] is False
    # Rehydration: recover/rebuild the candidate from preserved source and admit again.
    second = admit_context(**_admit_kwargs(
        FIXTURES / "context3_candidate_rehydrated.json",
        FIXTURES / "context3_candidate_manifest_rehydrated.json",
        C3_HISTORY,
        out=tmp_path / "second",
    ))
    assert second["accepted"] is True
    assert second["checkpoint_turn"] == 7
    result = _check(tmp_path / "second", C3_HISTORY)
    assert result["current"] is True
    assert result["reason_codes"] == []


# CLI surface: exit codes and boring human output.
def _cli_admit_args(history: Path, candidate: str, manifest: str, *, out: Path):
    return [
        "admit", str(history),
        "--candidate", str(FIXTURES / f"candidate_{candidate}.json"),
        "--manifest", str(FIXTURES / f"candidate_manifest_{manifest}.json"),
        "--compaction-policy", str(POLICY),
        "--compaction-policy-public-key", str(POLICY_KEYS),
        "--source-signing-key", str(ROOT / "fixtures" / "demo_source_signing_key.hex"),
        "--operator-approval-signing-key", str(ROOT / "fixtures" / "demo_operator_approval_key.hex"),
        "--replay-latency-micros", str(REPLAY_LATENCY_MICROS),
        "--out", str(out),
    ]


def _cli_check_args(admitted: Path, history: Path):
    return [
        "check", str(admitted),
        "--history", str(history),
        "--compaction-policy-public-key", str(POLICY_KEYS),
    ]


def test_cli_admit_accepted_exit_0(tmp_path, capsys):
    code = context_admit_main(_cli_admit_args(FIXTURES / "history.jsonl", "good", "good", out=tmp_path / "out"))
    assert code == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0] == "ACCEPTED"
    assert "Admitted context:" in out


def test_cli_admit_refused_exit_1(tmp_path, capsys):
    code = context_admit_main(_cli_admit_args(FIXTURES / "history.jsonl", "drop_constraint", "drop_constraint", out=tmp_path / "out"))
    assert code == 1
    out = capsys.readouterr().out
    assert out.splitlines()[0] == "REFUSED"
    assert "decision_equivalence_failed" in out


def test_cli_check_current_exit_0(tmp_path, capsys):
    _admit_fixture("good", "good", FIXTURES / "history.jsonl", out=tmp_path / "out")
    code = context_admit_main(_cli_check_args(tmp_path / "out", FIXTURES / "history.jsonl"))
    assert code == 0
    assert capsys.readouterr().out.splitlines()[0] == "CURRENT"


def test_cli_check_rehydrate_required_exit_1(tmp_path, capsys):
    _admit_context3(out=tmp_path / "out")
    code = context_admit_main(_cli_check_args(tmp_path / "out", C3_HISTORY))
    assert code == 1
    out = capsys.readouterr().out
    assert out.splitlines()[0] == "REHYDRATE_REQUIRED"
    assert "decision_equivalence_failed" in out


def test_cli_check_missing_history_never_current_exit_1(tmp_path, capsys):
    _admit_context3(out=tmp_path / "out")
    code = context_admit_main(_cli_check_args(tmp_path / "out", tmp_path / "missing.jsonl"))
    assert code == 1
    out = capsys.readouterr().out
    assert out.splitlines()[0] == "REHYDRATE_REQUIRED"
    assert "history_missing" in out
    assert "CURRENT" not in out.splitlines()[0]


def test_cli_check_json_mode(tmp_path, capsys):
    _admit_context3(out=tmp_path / "out")
    code = context_admit_main([*_cli_check_args(tmp_path / "out", C3_HISTORY), "--json"])
    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["current"] is False
    assert payload["schema"] == "openline.half-life.context-admit-check.v1"
