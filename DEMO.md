# Three-minute demo

**0:00–0:35 — Run the same-exam test and compactor**

```bash
python -m openline_half_life demo --out build/demo --replay-latency-micros 75000
```

The receiver policy budgets are signed. Crossing either budget proposes compaction; it does not authorize it. The demo supplies a separate receiver-signed, per-run `APPROVE` disposition.

**0:35–1:15 — Inspect the active state**

Open:

- `build/demo/causal_capsule.json`
- `build/demo/verified_residue_handoff.json`

The capsule keeps supported claims, the privacy constraint, confirmed outcomes, the unresolved latency question, evidence pointers, and tombstones. Unsupported, stale, revoked, and superseded states cannot quietly return.

**1:15–1:50 — Inspect equivalence**

Open `build/demo/decision_equivalence_report.json`.

An independent replay of the full chain and the capsule decision hashes match exactly. A missing contradiction, revived rejected claim, changed constraint, or altered supported value produces a mismatch and blocks compaction.

**1:50–2:25 — Inspect cold storage**

Open:

- `build/demo/archive_manifest.json`
- `build/demo/cold_archive/receipts/`

Every source receipt remains recoverable by hash. The archive manifest and compaction receipt use the existing OLP receipt schema and extend the original chain.

**2:25–2:45 — Inspect break-even**

Open:

- `build/demo/break_even_report.json`
- `build/demo/break_even_curve.csv`
- `build/demo/break_even_card.html`

The two cumulative paths use one shared vertical scale. The report may earn a durable crossing, report no crossing, or withhold a dollar claim. The bundled prices are synthetic declared assumptions, not provider quotes. The headline uses the declared canonical 100,000 µs verification-runtime scenario; the actual observed runtime is shown separately as evidence.

**2:45–3:00 — Verify everything**

```bash
python -m openline_half_life verify build/demo \
  --policy-public-key policy/succession_policy_public_key.hex \
  --compaction-policy-public-key policy/compaction_policy_public_key.hex
```

Then open `build/demo/share_card.html`.

The public result remains:

> Agent retired after turn 61. Verified handoff reduced errors by 43% on the same exam.

The card adds the measured capsule-size ratio only because decision equivalence passed. The economics line appears only because the same-exam, legitimate-completion, and decision-equivalence gates passed and complete dated assumptions were supplied.
