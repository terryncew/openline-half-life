# HALF-LIFE-CONTEXT-ADMIT-DISCRIMINATION-001 — Preregistration

Frozen before any case-3 fixture is generated or any test is run.
Branch: feat/compiler-neutral-admission-001 @ 4162554 (002 merged).
No source-code changes are planned; fixtures + test code only.
No model calls, no LCC, no adapter, no new repo, no external contact.

## Question

Candidate admission is repaired (002). Is continued use of an ADMITTED
compact context conditioned on the standing of its evidence dependencies,
using only existing Half-Life machinery?

## Existing standing machinery found (survey, no code changes)

- Tombstones (reference_replay.py / compaction.py): claims tombstoned as
  rejected / unresolved / stale / quarantined / superseded; constraints as
  inactive / stale; outcomes as retracted / stale. Tombstone keys carry
  disposition DENY.
- Supersede: same-slot claim — latest last_verified_turn wins, losers
  tombstoned superseded; constraints — latest last_verified_turn wins.
- Evidence freshness: `_fresh()` in reference_replay.py — evidence is stale
  when `checkpoint_turn > observed_turn + expires_after_turns`; any item
  citing only stale evidence is tombstoned stale.
- Rehydration conditions: carried as policy data in the compact state
  (compaction.py REHYDRATION_CONDITIONS =
  constraint_changed, evidence_revoked, compaction_policy_changed,
  trusted_key_changed, unresolved_state_changed, decision_mismatch).
  They are verified for equality with policy, NEVER evaluated at runtime.
  No evaluator for any rehydration condition exists in src/.
- verify (verify_admission_output_directory): tamper-checks the frozen
  package — re-derives the reference projection from the package's OWN
  stored history at the admission checkpoint. It does NOT check standing
  against a later source history.
- Evidence closure (002): enforced at admit time only.

## Case 1 — positive control (admit)

Input: existing frozen fixtures tests/fixtures/candidate_admission/
history.jsonl + candidate_good.json + candidate_manifest_good.json
(live constraint c-budget, unresolved contradiction claim-slot:cache_ttl:4,
evidence closure satisfied).
Expected: admit_pipeline ACCEPTS; verify_admission_output_directory valid.
Reason: reruns 001 case A in the context-admit frame; proves the doorway
still discriminates the full protected set including a contradiction.

## Case 2 — drop either protected item (refuse)

Inputs: existing frozen fixtures candidate_drop_constraint.json and
candidate_drop_contradiction.json with their manifests (same history).
Expected: BOTH refused with decision_equivalence_failed; no admitted
artifacts. (Split into two runs: drop constraint only; drop contradiction
only.) Reason: reruns 001 cases B and C; proves admission discriminates
each protected item independently.

## Case 3 — continued use after an evidence dependency loses standing

### Simulation of "loses standing"

New fixture history tests/fixtures/candidate_admission/context3_history.jsonl
(run_id "context-admit-003", 7 turns), built with the same deterministic
generator convention as generate_admission_fixtures.py:

- Turns 1-2: supported claims deployment_region / max_batch_size
  (evidence expires_after_turns=100), outcome o-cutover confirmed.
- Turn 3: contradiction pair on slot cache_ttl (values "60"/"120", both
  supported, last_verified_turn 3, evidence ev-flag exp 100).
- Turn 5: live constraint c-live, active, citing evidence ev-c-short
  with observed_turn=5, expires_after_turns=1.
- Turn 6: questions only. CHECKPOINT 6.
- Turn 7: questions only. No new claims, constraints, or outcomes.

Freshness math (existing `_fresh` semantics, nothing new):
- At checkpoint 6: 6 > 5+1 is False → ev-c-short fresh → c-live live.
- At checkpoint 7: 7 > 5+1 is True → ev-c-short stale → c-live tombstoned
  "stale" by the existing reference_projection. Every other protected item
  is unchanged at turn 7 (all other evidence exp 100; contradiction pair
  still contradictory at latest last_verified_turn 3).

The "loss of standing" is therefore computed by existing machinery
(tombstone:constraint:c-live → DENY/stale appears in the turn-7 reference
projection), not by any new judgment.

### The admitted compact context (3a)

Input: context3_candidate_good.json derived from derive_compact_state at
checkpoint 6 via the same strip-to-candidate-contract used for 001
(candidate_from_state), manifest via build_candidate_manifest.
Expected: admit_pipeline ACCEPTS at checkpoint 6; verify valid.
This is the positive control for the case-3 fixture itself.

### The continued-use check (3b)

"Next protected use" is modeled as a receiver-side standing check composed
ONLY of existing functions: reference_projection(turns, 7) compared against
the admitted compact_state.json via decision_equivalence_report (the same
comparison function the admission pipeline uses; no new judge, no new
semantics — the dispositions come from the two existing projections).
Expected: passed is False; mismatches include constraint:c-live (compact
says COMMIT, reference says nothing) and tombstone:constraint:c-live
(reference says DENY/stale, compact says nothing); reference projection at
7 contains tombstone:constraint:c-live with status "stale".
Interpretation: the standing-loss signal IS expressible with existing
machinery — the compact context is detectably invalid at turn 7, and the
carried rehydration_conditions name exactly this situation
(evidence_revoked, constraint_changed, decision_mismatch).

### Rehydration (3c)

Input: context3_candidate_rehydrated.json — candidate derived from
derive_compact_state at checkpoint 7 (c-live tombstoned, not live),
manifest bound to checkpoint 7.
Expected: admit_pipeline ACCEPTS at checkpoint 7; verify valid.
Interpretation: the rehydration procedure (re-run admission at the new
checkpoint) works end-to-end with existing machinery; the refreshed
context is again verifiable.

## What is NOT being tested

- No automatic enforcement gate: nothing in the CLI or pipeline forces
  the 3b check before a receiver's next protected use. The experiment
  discriminates expressibility/detectability, not automatic enforcement.
- No cross-session durability, no production safety, no adapter UX.

## Claim-boundary rule

Report only what the cases discriminate. If all three behave as expected:
admission discriminates protected items at admit time (cases 1-2), and
continued-use standing loss is expressible and detectable with existing
machinery with a working rehydration path (case 3) — but nothing in
Half-Life forces that check before the next protected use; the
conditioning is available to the receiver, not automatic. State explicitly
whether that earns "context-admit as thin product adapter" or only the
narrower claim.

## Frozen inputs/outputs

- Preregistration: this file (committed before fixtures/tests).
- New fixtures: context3_history.jsonl, context3_candidate_good.json,
  context3_candidate_manifest_good.json,
  context3_candidate_rehydrated.json,
  context3_candidate_manifest_rehydrated.json,
  generate_003_fixtures.py (generator, checked in like the 001 generator).
- New tests: tests/test_context_admit_discrimination.py (6 tests).
- 001/002 fixtures and frozen evidence are untouched.
- Do not alter preregistered inputs or expectations after observing results.
- Do not repair anything; discrimination only.
