# Changelog

## 0.4.0rc4

- Adds the `context-admit` CLI as a thin product adapter over the rc3 candidate-admission doorway. `context-admit admit` wraps the existing admission pipeline (same independent replay, same evidence closure, same rejection codes); the admitted-context artifact is the admission output directory. `context-admit check` is a caller-invoked current-standing check composed only of existing machinery: admitted-package verification, current-history validation and binding to the admitted source handoff, the independent reference projection at the current turn, the existing decision-equivalence comparison, and the existing evidence-closure check. Missing, malformed, incomplete, or unverifiable current history never yields CURRENT; standing is never inferred from the admitted artifact itself.
- Exit codes: 0 for accepted/current, 1 for refused/rehydration-required, 2 for apparatus errors. `--json` gives machine-readable output. No rehydrate command: rehydration is recover or rebuild the candidate from preserved source and run `admit` again.
- No compaction, replay, archive, policy, decision-equivalence, or evidence-closure semantics changed. rc3 remains the sealed historical incumbent.

## 0.4.0rc3

- Adds a compiler-neutral candidate-admission doorway. An externally produced compact-state candidate is admitted only when the existing independent decision replay says the receiver-required projection survived; candidates with corrupted protected state, mutated bytes, an altered manifest binding, or a wrong source binding are rejected deterministically with a rejection report and no admitted artifacts.
- Enforces evidence closure on admission: every evidence reference relied on by protected carried state must resolve to a carried evidence object whose canonical content is identical to the source-bound evidence from the verified source history. The archive is not a substitute for required carried evidence state. Closure is canonical-content identity, not byte identity with Half-Life's own compiler output.
- The admission doorway's frozen 001 experiment terminalized FAIL: a candidate that deleted required evidence-reference state while preserving citation IDs was admitted by the first doorway contract. The 001 counterexample remains frozen and visible at `evidence/frozen-failures/`; evidence closure was the repair, verified by the 002 discrimination set.
- Adds a three-case context-admit discrimination (admit positive control with live constraint plus unresolved contradiction; refuse when either protected item is dropped; invalidate a previously admitted compact context when a required evidence dependency loses standing, with rehydration by re-admission). Continued-use conditioning on dependency standing is available to the receiver, not system-enforced.
- Adds the `openline-half-life admit` CLI command and an `admission_receipt.json` binding the candidate, manifest, compact state, decision-equivalence report, source-chain digest, archive manifest, and artifact hashes.
- `openline-half-life verify` detects admission output directories and verifies them independently of the producer.
- Adds a preregistered perturbation attack (serialization reorder, canonical re-serialization, irrelevant item fields, summary-only later turn, emptied evidence references) that the boundary must survive.

## 0.4.0rc2

- Fixes release verification after an editable install by excluding standard `*.egg-info/` packaging metadata from source-closure checks.
- Keeps unsealed source files fail-closed; only known tool-generated paths are excluded.
- Prevents the release sealer from including editable-install metadata in a future manifest.
- Adds a regression test for the exact GitHub Actions failure seen in v0.4.0rc1.
- Removes the unused `build` development dependency; release packaging uses `pip wheel` directly.
- No compaction, replay, archive, policy, or decision semantics changed.

## 0.4.0rc1

- Narrows the maintained product to verified state compaction.
- Removes the old model-replacement scoring path from the active package, CLI, policy, fixtures, tests, and documentation.
- Uses the final verified turn, or an explicitly selected earlier turn, as the compaction checkpoint.
- Requires an operator-owned signed compaction policy, a separately signed checkpoint approval, a pinned source signer, and a pinned approval signer.
- Keeps supported claims, live constraints, confirmed outcomes, unresolved questions, contradictions, tombstones, evidence references, source bindings, and rehydration conditions.
- Requires independent replay from the raw history before accepting compact state.
- Keeps all source receipts in a hash-addressed archive and verifies every archived receipt on reload.
- Preserves the 10,000-history cryptographic equivalence, tombstone, and archive-recovery release gate.
- Removes the old headline model-replacement demo and related generated artifacts from the maintained release tree.

Earlier research and release artifacts remain available in Git history.
