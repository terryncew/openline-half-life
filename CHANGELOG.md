# Changelog

## Unreleased

- Adds a compiler-neutral candidate-admission doorway. An externally produced compact-state candidate is admitted only when the existing independent decision replay says the receiver-required projection survived; candidates with corrupted protected state, mutated bytes, an altered manifest binding, or a wrong source binding are rejected deterministically with a rejection report and no admitted artifacts.
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
