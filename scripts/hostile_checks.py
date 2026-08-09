from __future__ import annotations

import copy
import json
import shutil
import tempfile
from pathlib import Path

from openline_half_life.compaction import candidate_hits_tombstone, derive_compact_state
from openline_half_life.pipeline import run_pipeline, verify_output_directory
from openline_half_life.schema import load_trajectory
from openline_half_life.util import load_json, write_json

ROOT = Path(__file__).resolve().parents[1]
POLICY_KEYS = {line.strip() for line in (ROOT / "policy/compaction_policy_public_key.hex").read_text().splitlines() if line.strip()}


def _copy(base: Path, root: Path, name: str) -> Path:
    target = root / name
    shutil.copytree(base, target)
    return target


def _invalid(path: Path) -> bool:
    return verify_output_directory(path, expected_policy_public_keys=POLICY_KEYS)["valid"] is False


def run_checks() -> dict:
    checks: list[tuple[str, bool]] = []
    with tempfile.TemporaryDirectory(prefix="half-life-hostile-") as tmp_text:
        tmp = Path(tmp_text)
        base = tmp / "base"
        run_pipeline(
            ROOT / "fixtures/demo_trajectory.jsonl",
            ROOT / "fixtures/demo_source_signing_key.hex",
            base,
            compaction_policy_path=ROOT / "policy/compaction_policy.json",
            compaction_policy_public_key_path=ROOT / "policy/compaction_policy_public_key.hex",
            operator_approval_signing_key_path=ROOT / "fixtures/demo_operator_approval_key.hex",
            replay_latency_micros=75_000,
        )

        def mutate_json(name: str, filename: str, mutator) -> None:
            path = _copy(base, tmp, name)
            value = load_json(path / filename)
            mutator(value)
            write_json(path / filename, value)
            checks.append((name, _invalid(path)))

        mutate_json("policy_tamper", "compaction_policy.json", lambda value: value["trigger"].__setitem__("active_receipt_bytes_budget", value["trigger"]["active_receipt_bytes_budget"] + 1))
        mutate_json("checkpoint_tamper", "checkpoint.json", lambda value: value.__setitem__("checkpoint_turn", value["checkpoint_turn"] - 1))
        mutate_json("approval_tamper", "operator_approval.json", lambda value: value.__setitem__("disposition", "DENY"))
        mutate_json("compact_state_tamper", "compact_state.json", lambda value: value.__setitem__("objective", "attacker"))
        mutate_json("equivalence_tamper", "decision_equivalence_report.json", lambda value: value.__setitem__("passed", False))
        mutate_json("archive_manifest_tamper", "archive_manifest.json", lambda value: value["payload"]["entries"][0].__setitem__("file_sha256", "0" * 64))
        mutate_json("compaction_receipt_tamper", "compaction_receipt.json", lambda value: value["payload"].__setitem__("checkpoint_turn", 1))
        mutate_json("bundle_tamper", "receipt_bundle.json", lambda value: value.__setitem__("policy_hash", "0" * 64))
        mutate_json("source_payload_tamper", "receipt_bundle.json", lambda value: value["source_chain"][0]["payload"].__setitem__("turn", 999))
        mutate_json("source_signature_tamper", "receipt_bundle.json", lambda value: value["source_chain"][0].__setitem__("signature", "AAAA"))
        mutate_json("anchor_tamper", "receipt_bundle.json", lambda value: value["source_anchor"].__setitem__("expected_count", 1))
        mutate_json("extension_parent_tamper", "receipt_bundle.json", lambda value: value["compaction_receipt"].__setitem__("parent_hash", "0" * 64))

        path = _copy(base, tmp, "archive_file_tamper")
        archived = next((path / "cold_archive/receipts").glob("*.json"))
        archived.write_text("{}\n")
        checks.append(("archive_file_tamper", _invalid(path)))

        path = _copy(base, tmp, "archive_file_missing")
        next((path / "cold_archive/receipts").glob("*.json")).unlink()
        checks.append(("archive_file_missing", _invalid(path)))

        path = _copy(base, tmp, "required_artifact_missing")
        (path / "compact_state.json").unlink()
        checks.append(("required_artifact_missing", _invalid(path)))

        turns = load_trajectory(ROOT / "fixtures/demo_trajectory.jsonl")
        state = derive_compact_state(turns, len(turns))
        stale = next(item for item in state["tombstones"] if item["item_type"] == "claim")
        candidate = {"item_type": "claim", "slot": stale.get("slot"), "value": None, "item_id": stale.get("item_id")}
        # item-id matching must still block a replay even if value bytes are absent.
        checks.append(("tombstone_replay", candidate_hits_tombstone(state, candidate)))

    failures = [name for name, passed in checks if not passed]
    return {"schema": "openline.half-life.hostile-checks.v1", "check_count": len(checks), "passed_count": len(checks) - len(failures), "failures": failures, "passed": not failures}


def main() -> int:
    result = run_checks()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
