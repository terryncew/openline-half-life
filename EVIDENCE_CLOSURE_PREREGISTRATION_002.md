# 002 Preregistration — Evidence Closure Discrimination

Frozen before implementation runs. No input or expected outcome below may be
altered after observing results. The 001 lane
(`feat/compiler-neutral-admission-001` @ `0b80bd4`) and its frozen
counterexample (`evidence/frozen-failures/p5-evidence-refs-emptied/`) stay
byte-identical.

## D1 — the 001 falsifier becomes the first regression case (must REFUSE)

Input, unmodified: `evidence/frozen-failures/p5-evidence-refs-emptied/candidate_p5.json`
with `evidence/frozen-failures/p5-evidence-refs-emptied/manifest_p5.json`
against `tests/fixtures/candidate_admission/history.jsonl`, checkpoint_turn 6,
admitted output to a scratch dir (never into the frozen dir).
Expected: `AdmissionRejected`, reason code `evidence_closure_failed`,
mismatches naming `ev-batch-1`, `ev-constraint-1`, `ev-outcome-1`,
`ev-region-2` as `evidence_not_carried`.

## D2 — altered contents refused (new fixture)

Input: good candidate with one evidence object's contents changed
(`ev-batch-1` `sha256` field rewritten), same ID, own recomputed manifest.
Fixture: `tests/fixtures/candidate_admission/candidate_evidence_altered.json`
+ `candidate_manifest_evidence_altered.json`.
Expected: `AdmissionRejected`, reason code `evidence_closure_failed`,
mismatch naming `ev-batch-1` as `evidence_altered`.

## D3 — compiler-different candidate accepted (new fixture)

Input: hand-authored candidate, same protected contents as the good
candidate but a different shape: supported claims in a different order,
evidence_references reversed, evidence object field order shuffled, item
field order shuffled. Contents identical; canonical hash differs (array
order), so this is a genuinely different candidate, not a copy.
Fixture: `tests/fixtures/candidate_admission/candidate_compiler_different.json`
+ `candidate_manifest_compiler_different.json`.
Expected: admitted, `accepted: true`, zero mismatches. This case proves the
repair is evidence closure, not byte identity with Half-Life's output.

## D4 — the 12 lettered 001 fixtures retain their exact 001 outcomes

`good` → admit; `drop_constraint`, `drop_question`, `drop_tombstone`,
`resurrect`, `alter_claim`, `drop_contradiction`, `empty` →
`decision_equivalence_failed`; `extra_material` → `candidate_schema_invalid`;
`mutated` (bytes) / `mutated` (manifest) / `wrong_source` →
`manifest_binding_mismatch`.

## D5 — perturbation suite expectation change (explicit, contract-driven)

`test_p5_emptied_evidence_refs_still_admit` is updated to expect REFUSE with
`evidence_closure_failed`. The frozen 001 expectation encoded the wrong
outcome under a contract that has since been shown false; the change is
required by D1, not by any observed run. P1–P4 perturbation tests keep
ADMIT.

## D6 — verify-path tamper tests retain their outcomes

All `test_verify_admission_detects_*` tests keep passing on newly admitted
packages.

## Release gate

`python scripts/release_check.py` runs unweakened if and only if D1–D6 all
pass. Exit code, full summary, seeded-gate, wheel/import, source-closure,
and demo results recorded as observed.
