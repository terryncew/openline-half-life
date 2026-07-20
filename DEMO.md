# Three-minute save-file demo

## 0:00–0:30 — Create the save file

```bash
uvx openline-half-life demo
```

Until the package is published, use the checkout command:

```bash
python -m openline_half_life demo --out build/demo
```

The CLI prints the retirement point, same-exam result, active-state ratio, reference break-even turn, decision-mismatch count, and path to the share card. Add `--json` for the full result.

## 0:30–1:10 — Inspect what survived

Open `build/demo/causal_capsule.json` and `build/demo/verified_residue_handoff.json`. The save file keeps supported claims, evidence pointers, live constraints, commitments, outcomes, unresolved questions, contradictions, tombstones, policy versions, and source hashes.

It does not contain model weights, hidden thoughts, private chain of thought, or a provider's internal memory.

## 1:10–1:45 — Check that the job state is equivalent

Open `build/demo/decision_equivalence_report.json`. An independent full-history replay and the compact capsule produce the same disclosed Receipt Gate decisions. A revived rejected claim, missing contradiction, changed constraint, or altered supported value blocks compaction.

## 1:45–2:15 — Check the original record

Open `build/demo/archive_manifest.json` and `build/demo/cold_archive/receipts/`. Source receipts are never deleted. Every archived receipt remains recoverable and hash-verifiable.

## 2:15–2:40 — Inspect the same-exam handoff

Open `build/demo/comparison.json` and `build/demo/share_card.html`. The full-history and verified-residue successor conditions receive the same held-out exam. Legitimate task completion must survive or the comparison fails.

## 2:40–3:00 — Inspect the secondary economics result

Open `build/demo/break_even_report.json` and `build/demo/break_even_card.html`. The break-even headline uses a declared canonical scenario; observed runtime remains separate evidence. A short task may honestly show no savings.

**Category:** You own the job. The model is the console.
