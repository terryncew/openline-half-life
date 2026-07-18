# Changelog

## 0.2.0rc5 review candidate

- Fix clean CI wheel construction by installing the declared setuptools build backend in the development environment used by the offline `--no-build-isolation` packaging test.
- Preserve full Ed25519 creation and verification across all 10,000 seeded histories.
- Supersedes rc4, which passed the compaction gate but failed the clean packaging test because the build backend was only available in the authoring environment.

## 0.2.0rc4 review candidate

- Removes the sampled cryptographic fast path from the 10,000-history release gate. Every seeded history now receives full Ed25519 chain creation, signature verification, parent continuity verification, and signed-anchor completeness verification.
- Adds a regression that requires the cryptographically verified history count to equal the seeded history count.
- Keeps the 10,000-history decision-equivalence, tombstone-replay, archive-recovery, and 20% median-size gates unchanged.

## 0.2.0rc3 review candidate

- Binds the complete required artifact manifest into the signed terminal compaction receipt and requires exact outer-manifest coverage, preventing unsigned hash coverage from being removed or rewritten.
- Requires both extension receipts to use the verified source-chain signer and rejects signer discontinuity before archive output is written.
- Requires an external receiver policy pin during archive rehydration, re-verifies the policy envelope and semantics, and checks policy, capsule, source-chain, checkpoint, and manifest bindings before recomputation.
- Adds permanent regressions for missing artifact coverage, rewritten outer hashes, extension-signer mismatch, missing recovery pins, and altered recovery policy.

## 0.2.0rc2 security review candidate

- Replaces the command-line approval word with a separately signed, per-run receiver approval bound to the checkpoint, source-chain digest, compaction policy, and archive destination.
- Rechecks source-signer trust in the public verifier and binds the receiver approval into the capsule, compaction receipt, artifact bundle, and final verification result.
- Replaces self-comparison with an independent full-history replay engine; a defect in compaction state can no longer certify a copy of itself.
- Rejects future-dated claim or constraint verification, unsigned rehydration triggers, source-signed mechanism self-admission, unsafe manifest paths, symlink escapes, and weakened signed policy semantics.
- Implements authenticated cold-archive restoration and recomputation.
- Adds seven adversarial regression tests and removes artificial summary padding from the seeded size gate. All 10,000 histories receive independent semantic replay; a deterministic 1-in-100 sample also receives full Ed25519 chain creation and verification.

## 0.2.0rc1 review candidate

- Adds `causal_compactor.py` with receiver-pinned compaction-policy verification, pressure proposals, exact decision-equivalence checks, compact causal capsules, tombstones, and fail-closed receiver approval.
- Archives every source receipt in SHA-256-addressed cold storage and signs the complete manifest using the existing OLP receipt schema and Ed25519 chain.
- Preserves explicit admitted mechanisms while refusing to promote repetition or correlation to causation.
- Adds automatic rehydration proposals for mechanism failure, constraint change, evidence revocation, policy/key change, contradiction change, or decision mismatch.
- Extends the demo, verified-residue handoff, receipt bundle, verifier, share card, CLI, package data, and CI without changing the pinned v0.10.0 Succession Calibrator.
- Adds hostile tests for forged policy keys, tampering, stale replay, tombstone replay, causal promotion, contradiction loss, policy/key changes, archive omissions, premature compaction, decision mismatch, and automatic retirement.
- Adds a deterministic 10,000-seeded-history gate requiring zero decision mismatches, zero tombstone replays, full archive recovery, and median active size at or below 20% of the full chain.
- Remains an untagged review candidate.

## 0.1.1

- Requires a receiver-owned policy signer pin for policy loading, assessment, pipeline execution, and output verification; the release policy private key is not distributed.
- Recomputes the complete unsigned policy body with the pinned v0.10.0 fitter, preventing a trusted signature from blessing altered thresholds.
- Binds the exact signed calibrator policy into the receipt bundle as `calibrator_policy.json`.
- Rejects evidence-ID rebinding when an existing ID is presented with a different SHA-256 artifact.
- Resolves outcomes by latest observation, honors explicit retractions, and requires fresh evidence for confirmed outcomes.
- Makes failed comparisons produce an explicit failed share card and a non-zero CLI exit code.
- Recomputes comparison semantics during verification instead of trusting the stored `passed` field.
- Packages demo fixtures, exam, policy, policy public key, and signing fixture inside the wheel so `demo` works outside a source checkout.

## 0.1.0

- Initial deterministic full-history versus verified-residue succession benchmark.
