# OpenLine Half-Life

## Verified state compaction

This repository turns a long signed job history into a smaller state package **only when an independent replay produces the same downstream decisions as the full history**.

The maintained workflow is deliberately narrow:

1. verify the signed source history and operator-owned compaction policy;
2. bind an exact checkpoint before compaction;
3. require a separately signed operator approval;
4. derive compact state from the verified history;
5. replay the raw history through an independent implementation;
6. reject compaction if any decision differs;
7. copy every source receipt to a hash-addressed archive and verify recovery.

The compact state keeps supported claims, live constraints, confirmed outcomes, unresolved questions, contradictions, negative-state tombstones, evidence references, policy bindings, source hashes, and rehydration conditions. Source receipts are never deleted by this tool.

This component does **not** decide whether one agent or model should replace another. It does not predict hidden agent condition or future failure. It does not authorize a protected action. Its job is state preservation under compression.

## Quick start

```bash
python -m pip install -e '.[dev]'
openline-half-life demo --out build/demo
openline-half-life verify build/demo \
  --compaction-policy-public-key policy/compaction_policy_public_key.hex
```

A successful demo reports:

```text
Verified state compaction passed at turn 70.
Independent replay mismatches: 0.
Compact state: 7.5% of the verified source receipt chain.
```

The percentage is a property of the bundled deterministic example, not a universal compression rate.

## CLI

Compact another history:

```bash
openline-half-life run path/to/history.jsonl \
  --compaction-policy policy/compaction_policy.json \
  --compaction-policy-public-key policy/compaction_policy_public_key.hex \
  --source-signing-key path/to/source-signing-key.hex \
  --operator-approval-signing-key path/to/operator-approval-key.hex \
  --replay-latency-micros 75000 \
  --out build/result
```

By default the final turn is the checkpoint. `--checkpoint-turn N` selects an earlier existing turn.

Admit an externally produced compact-state candidate:

```bash
openline-half-life admit path/to/history.jsonl \
  --candidate path/to/candidate.json \
  --manifest path/to/candidate_manifest.json \
  --compaction-policy policy/compaction_policy.json \
  --compaction-policy-public-key policy/compaction_policy_public_key.hex \
  --source-signing-key path/to/source-signing-key.hex \
  --operator-approval-signing-key path/to/operator-approval-key.hex \
  --replay-latency-micros 75000 \
  --out build/admission
```

## External candidate admission

The compactor that produced a compact state and the authority that admits it need not be the same system. An arbitrary external producer can propose a compact state; Half-Life admits it only when its own independent replay says the receiver-required projection survived.

The candidate is untrusted input. Admission runs the same decision-equivalence replay used for internally derived states, against the same protected projection: current supported claims, active constraints, confirmed outcomes, unresolved questions, contradictions, and negative-state tombstones. A candidate that drops a constraint, resurrects a superseded claim, loses a tombstone, or contradicts the replay is rejected, and nothing is admitted: no admitted state is produced, no archive entry is written, no receipt is signed. The CLI exits nonzero and writes only a deterministic rejection report (`admission_rejection.json`) with the reason codes and the exact mismatches.

Admission never repairs a candidate into correctness. The admitted compact state projects byte-for-byte like the candidate did; Half-Life adds only its own trusted metadata (archive custody, operator approval, source bindings, rehydration conditions, the admission receipt). The admission receipt binds the candidate content hash, the manifest hash, the compact-state hash, the decision-equivalence report, the source-chain digest, the archive manifest, and the artifact hashes, so a third party can verify the admission without trusting the producer.

`openline-half-life verify` detects an admission output directory (by the presence of `admission_receipt.json`) and verifies it with the same independent checks: candidate and manifest integrity, checkpoint and source bindings, compact-state bindings, equivalence-report integrity with re-derivation of both decision hashes, archive reload, receipt and bundle tamper.

## context-admit

Agents compact context. A compact form can stay syntactically valid after a dependency it relies on changes. Two operations: admit this candidate, and later: is it still current?

```bash
context-admit admit path/to/history.jsonl \
  --candidate path/to/candidate.json \
  --manifest path/to/candidate_manifest.json \
  --compaction-policy policy/compaction_policy.json \
  --compaction-policy-public-key policy/compaction_policy_public_key.hex \
  --source-signing-key path/to/source-signing-key.hex \
  --operator-approval-signing-key path/to/operator-approval-key.hex \
  --replay-latency-micros 75000 \
  --out build/admission
```

context-admit does not intercept future model calls. A caller must check current standing before reusing an admitted compact context. If current history is missing or cannot be verified, the context is not treated as current.

Before reusing the admitted context:

```bash
context-admit check build/admission \
  --history path/to/current_history.jsonl \
  --compaction-policy-public-key policy/compaction_policy_public_key.hex
```

`check` prints CURRENT or REHYDRATE_REQUIRED with reason codes. `admit` is a thin wrapper over the `openline-half-life admit` doorway: same independent replay, same evidence closure, same rejection codes. `check` reuses only existing machinery: the admitted package is verified, the current history is validated and bound to the admitted source handoff, and the admitted decision projection is compared against the independent reference projection at the current turn. Rehydration is recover or rebuild the candidate from preserved source and run `admit` again. Exit codes: 0 for accepted/current, 1 for refused/rehydration-required, 2 for apparatus errors. `--json` gives machine-readable output. The discrimination evidence is in `CONTEXT_ADMIT_PREREGISTRATION_003.md`.

## Trust boundary

The policy signer, source-history signer, and operator-approval signer are separate trust roles. The policy pins the allowed source signer and operator-approval key. A valid signature from an unpinned key does not earn trust.

Compaction is proposed only when a declared active-history or replay-latency budget is crossed. The operator still has to approve the exact checkpoint and source-chain digest. The operator can also deny compaction.

The demonstration private keys under `fixtures/` are intentionally public so the example is reproducible. They are not production credentials.

## Independent replay

`src/openline_half_life/reference_replay.py` does not import the compaction implementation. It reads the raw turn history and independently reconstructs the decision projection. The compact state is accepted only when the two projections match exactly.

The comparison covers current supported claims, active constraints, confirmed outcomes, unresolved questions, contradictions, and negative-state tombstones. A stale, rejected, retracted, quarantined, or superseded item cannot disappear merely because the state was made smaller.

## Archive custody

Every signed source receipt is written to `cold_archive/receipts/<receipt-hash>.json`. The archive manifest binds the source-chain count, tail hash, chain digest, source anchor, destination, and each archived file hash. Verification reloads every archived receipt and checks it against the original signed receipt.

Rehydration triggers are retained in the compact state so later evidence or policy changes can force a rebuild from the archived history.

## Release gate

```bash
python scripts/release_check.py
```

The release gate runs the unit/adversarial suite, deterministic demo, packaged-output verification, wheel build/import, source-closure checks, and the 10,000-history seeded gate.

The seeded gate requires:

- 10,000/10,000 signed receipt histories verify;
- zero independent-replay mismatches;
- zero successful tombstone replays;
- zero archive serialization/recovery failures;
- median compact state no larger than 20% of the signed source receipt chain.

Synthetic release tests establish implementation behavior only. They do not establish production key custody, completeness of external evidence, or universal memory savings.
