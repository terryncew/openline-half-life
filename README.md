# OpenLine Half-Life

## Your agent should survive changing models

OpenLine is a cross-platform save file for AI agents: save the verified state of a job on one model, load it on another, and continue with the record intact. **You own the job. The model is the console.**

This repository contains Half-Life, the part of the OpenLine stack that makes the save file small enough to carry. It turns a long verified receipt history into a compact causal capsule, but permits that compression only when an independent replay proves the capsule produces the same receiver decisions as the full chain.

The portable state includes supported claims, evidence references, live constraints, commitments, confirmed outcomes, unresolved questions, contradictions, tombstones, policy versions, and source hashes. It does not transfer model weights, hidden thoughts, private chain of thought, or a provider's internal memory.

Receipts record what happened. Half-Life compacts the verified record. Verified Model Swap loads it into another model. Receipt Gate decides what the transferred evidence earns. Verified Commit gives the receiving model fresh permission for one exact action.

Cost savings are secondary. A smaller save file can reduce repeated context loading for long-running agents, but the economics benchmark may honestly report that a short task never breaks even.

## Run the reference save-file demo

After publication to PyPI:

```bash
uvx openline-half-life demo
# or
pipx run openline-half-life demo
```

From a checkout:

```bash
python -m pip install -e '.[dev]'
openline-half-life demo --out build/demo
```

The default CLI prints a short human receipt. Add `--json` for the complete machine-readable result.

## Trust boundary

Both the Succession Calibrator policy and the compaction policy require public keys supplied by the receiver outside the signed files. A malicious self-signed policy fails even when its Ed25519 signature is valid. Compaction also requires a receiver signature distinct from the source-receipt signer and bound to that run's chain and checkpoint.

The source-chain signer must also sign both compaction extension receipts. The terminal compaction receipt binds the complete non-circular artifact manifest, while the receipt file itself is bound as the verified chain tail. Removing coverage, rewriting an outer hash, or changing a required artifact fails verification.

The keys under `fixtures/` are public demo identities whose private halves are intentionally disclosed for reproducibility. They provide no production trust. A deployment must replace the demo source key, receiver-approval key, policies, and outside trust pins.

The pinned v0.10.0 Succession Calibrator remains unchanged at:

`src/openline_half_life/vendor/openline_endurance_gate/succession.py`

κ, ε, Δhol, φ*, and UCR remain separate. UCR is only an evidence-sufficiency check. `RETIRE` remains a succession candidate requiring receiver approval. Automatic retirement and automatic compaction are forbidden.

## Causal compaction rule

The compactor accepts:

- a verified OLP receipt chain;
- a receiver-owned signed compaction policy;
- a separately signed, per-run receiver approval;
- explicitly trusted policy keys;
- a current verified checkpoint;
- active-memory and replay-latency budgets.

Before compaction it verifies chain continuity, signer trust and continuity, run binding, checkpoint binding, freshness, evidence coverage, policy hash, archive destination, and the receiver approval signature. Missing or undecidable inputs fail closed.

The active capsule keeps supported claims, admitted mechanisms with evidence pointers, live constraints and commitments, unresolved questions and contradictions, tombstones, policy and key versions, source hashes, and rehydration conditions.

It archives duplicates, repeated observations, superseded versions, settled intermediate steps, and bulky source details. Source receipts are never deleted. Each receipt is copied to a SHA-256-addressed cold archive and covered by a signed manifest receipt using the existing OLP receipt schema and Ed25519 chain.

The compactor never turns repetition or correlation into causation. Only a causal or mechanism relation carrying a trusted receiver-signed admission and fresh evidence may enter `admitted_mechanisms`.

Decision equivalence is not computed from two copies of compactor state. A separate reference replay reads the raw verified history and produces the full-history receiver decision table independently.

## Compaction economics

The economics benchmark compares two cumulative paths over a receiver-declared future horizon:

- repeatedly load the measured full-history handoff into the model;
- pay the observed deterministic compaction-verification cost, then load the measured compact handoff, with declared recompaction and rehydration events.

Model context cost, deterministic verification runtime, fixed verification overhead, recompaction, and rehydration remain separate. Dollar claims are withheld unless the receiver supplies complete dated pricing assumptions. A valid result may report a durable break-even turn, no break-even within the horizon, or an undecidable dollar claim. If same-exam preservation or decision equivalence fails, the economics claim is blocked.

The benchmark holds the measured packet sizes constant across the declared horizon. It is a disclosed scenario calculation, not a forecast of universal savings. Long-running histories may grow differently in production.

## Outputs

A demo emits:

- `half_life_receipt.json`
- `calibrator_policy.json`
- `compaction_policy.json`
- `receiver_approval.json`
- `full_history_handoff.json`
- `verified_residue_handoff.json`
- `comparison.json`
- `causal_capsule.json`
- `archive_manifest.json`
- `decision_equivalence_report.json`
- `compaction_receipt.json`
- `share_card.html`
- `cost_assumptions.json`
- `break_even_report.json`
- `break_even_curve.csv`
- `break_even_card.html`
- `cold_archive/receipts/<receipt-hash>.json`

`archive_manifest.json` and `compaction_receipt.json` are ordinary `openline.endurance.receipt.v1` receipts extending the same chain. No new receipt family or cryptographic method is introduced.

## One-command release gate

Python 3.12 or newer is required.

```bash
python -m pip install -e '.[dev]'
python scripts/release_check.py
```

That command runs all inherited, audit, tamper, packaging, compaction, and economics tests; the deterministic demo; economic artifact verification; archive verification; and the 10,000-seeded-history gate.

The seeded gate replays all 10,000 histories through both independent decision engines. Every history receives full Ed25519 receipt-chain creation, signature verification, parent-chain verification, and signed-anchor completeness verification; no synthetic or sampled signature path is used.

It requires:

- zero full-history versus capsule decision mismatches;
- zero successful tombstone replays;
- every archived receipt recoverable and hash-verifiable;
- median active capsule size no larger than 20% of the full receipt chain.

## Three-minute demo

```bash
python -m openline_half_life demo \
  --out build/demo \
  --replay-latency-micros 75000

python -m openline_half_life verify build/demo \
  --policy-public-key policy/succession_policy_public_key.hex \
  --compaction-policy-public-key policy/compaction_policy_public_key.hex
```

The sample still earns the original result:

> Agent retired after turn 61. Verified handoff reduced errors by 43% on the same exam.

The share card also states the measured active-memory ratio only after exact receiver-decision equivalence passes. The demo emits a separate break-even card and curve. Under the bundled synthetic assumptions, the headline crossing uses a declared canonical 100,000 µs verification-runtime scenario. The actual wall-clock runtime is preserved separately as measured evidence, so faster and slower machines do not rewrite the checked-in headline. It is not a provider-price claim.

## Run another trajectory

```bash
openline-half-life run path/to/trajectory.jsonl \
  --exam exams/heldout_exam.json \
  --policy policy/succession_policy.json \
  --policy-public-key policy/succession_policy_public_key.hex \
  --compaction-policy policy/compaction_policy.json \
  --compaction-policy-public-key policy/compaction_policy_public_key.hex \
  --signing-key path/to/private-key.hex \
  --receiver-approval-signing-key path/to/receiver-approval.private.hex \
  --economics-assumptions path/to/cost-assumptions.json \
  --replay-latency-micros 75000 \
  --receiver-disposition APPROVE \
  --out build/result
```

Budgets live in the signed receiver policy. There are no hardcoded universal compaction thresholds.

## Rehydration

Authenticated later receipts propose rehydration when a retained mechanism is weakened or overturned, a constraint changes, evidence is revoked, the compaction policy or trusted key changes, an unresolved contradiction changes, or a successor decision diverges. Unsigned or disconnected receipts are rejected.

Rehydration requires the receiver's external compaction-policy pin, verifies the signed policy again, checks its capsule binding, restores and verifies the archived receipts, then recomputes state. The system may update evidence state. It may not rewrite policy or approve its own compaction.
