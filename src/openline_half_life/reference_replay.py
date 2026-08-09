from __future__ import annotations

from typing import Any, Mapping, Sequence

from .schema import validate_turn
from .util import canonical_json, sha256_bytes


def _evidence_index(turns: Sequence[Mapping[str, Any]], checkpoint_turn: int) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for turn in turns:
        if int(turn["turn"]) > checkpoint_turn:
            break
        for item in turn["evidence"]:
            result[item["id"]] = dict(item)
    return result


def _fresh(refs: Sequence[str], evidence: Mapping[str, Mapping[str, Any]], checkpoint_turn: int) -> bool:
    if not refs:
        return False
    for ref in refs:
        item = evidence.get(ref)
        if item is None or checkpoint_turn > int(item["observed_turn"]) + int(item["expires_after_turns"]):
            return False
    return True


def _claim_tombstone_identity(claim: Mapping[str, Any], status: str) -> str:
    return f"claim:{claim['slot']}:{sha256_bytes(canonical_json(claim['value']))}:{status}"


def reference_projection(turns: Sequence[Mapping[str, Any]], checkpoint_turn: int) -> dict[str, Any]:
    normalized = [validate_turn(item, expected_turn=index) for index, item in enumerate(turns, 1)]
    selected = [item for item in normalized if int(item["turn"]) <= checkpoint_turn]
    if not selected or int(selected[-1]["turn"]) != checkpoint_turn:
        raise ValueError("checkpoint turn not present")
    evidence = _evidence_index(selected, checkpoint_turn)
    projection: dict[str, Any] = {}

    by_slot: dict[str, list[Mapping[str, Any]]] = {}
    for turn in selected:
        for claim in turn["claims"]:
            by_slot.setdefault(str(claim["slot"]), []).append(claim)
    for slot, claims in sorted(by_slot.items()):
        eligible = []
        for claim in claims:
            if claim["support_status"] != "supported":
                status = "rejected" if claim["support_status"] == "unsupported" else "unresolved"
                projection[f"tombstone:{_claim_tombstone_identity(claim, status)}"] = {"disposition": "DENY", "status": status}
            elif not _fresh(claim["evidence_refs"], evidence, checkpoint_turn):
                projection[f"tombstone:{_claim_tombstone_identity(claim, 'stale')}"] = {"disposition": "DENY", "status": "stale"}
            else:
                eligible.append(claim)
        if not eligible:
            continue
        latest_turn = max(int(item["last_verified_turn"]) for item in eligible)
        latest = [item for item in eligible if int(item["last_verified_turn"]) == latest_turn]
        values = {canonical_json(item["value"]) for item in latest}
        if len(values) > 1:
            contradiction_id = f"claim-slot:{slot}:{latest_turn}"
            projection[f"contradiction:{contradiction_id}"] = {"disposition": "QUARANTINE"}
            for item in latest:
                identity = _claim_tombstone_identity(item, "quarantined")
                projection[f"tombstone:{identity}"] = {"disposition": "DENY", "status": "quarantined"}
            continue
        chosen = sorted(latest, key=lambda item: str(item["id"]))[-1]
        projection[f"claim:{slot}"] = {"disposition": "COMMIT", "value_hash": sha256_bytes(canonical_json(chosen["value"])), "evidence_refs": sorted(chosen["evidence_refs"])}
        for item in eligible:
            if item is not chosen:
                identity = _claim_tombstone_identity(item, "superseded")
                projection[f"tombstone:{identity}"] = {"disposition": "DENY", "status": "superseded"}

    constraints: dict[str, Mapping[str, Any]] = {}
    for turn in selected:
        for item in turn["constraints"]:
            prior = constraints.get(item["id"])
            if prior is None or int(item["last_verified_turn"]) >= int(prior["last_verified_turn"]):
                constraints[item["id"]] = item
    for item_id, item in sorted(constraints.items()):
        if item["active"] and _fresh(item["evidence_refs"], evidence, checkpoint_turn):
            projection[f"constraint:{item_id}"] = {"disposition": "COMMIT", "text_hash": sha256_bytes(canonical_json(item["text"])), "evidence_refs": sorted(item["evidence_refs"])}
        else:
            status = "inactive" if not item["active"] else "stale"
            projection[f"tombstone:constraint:{item_id}"] = {"disposition": "DENY", "status": status}

    outcomes: dict[str, Mapping[str, Any]] = {}
    for turn in selected:
        for item in turn["outcomes"]:
            outcomes[item["id"]] = item
    for item_id, item in sorted(outcomes.items()):
        if item["confirmed"] and _fresh(item["evidence_refs"], evidence, checkpoint_turn):
            projection[f"outcome:{item_id}"] = {"disposition": "COMMIT", "text_hash": sha256_bytes(canonical_json(item["text"])), "evidence_refs": sorted(item["evidence_refs"])}
        else:
            status = "retracted" if not item["confirmed"] else "stale"
            projection[f"tombstone:outcome:{item_id}"] = {"disposition": "DENY", "status": status}

    questions: list[str] = []
    for turn in selected:
        for question in turn["unresolved_questions"]:
            if question not in questions:
                questions.append(question)
    for question in questions:
        projection[f"question:{sha256_bytes(question.encode('utf-8'))}"] = {"disposition": "QUARANTINE"}
    return dict(sorted(projection.items()))
