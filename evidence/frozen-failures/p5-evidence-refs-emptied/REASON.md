# FROZEN FAILURE — p5-evidence-refs-emptied

Terminal disposition: **FAIL — CANDIDATE ADMISSION ALLOWED LOSS OF REQUIRED EVIDENCE-REFERENCE STATE**

Frozen: 2026-09-20 ~16:00 PDT, branch `feat/compiler-neutral-admission-001`.
This is a frozen counterexample, not a development test. Do not repair the
mechanism before preserving this record. Do not silently convert it into a
passing-style test.

## What happened

The preregistered perturbation attack P5 ("emptied evidence refs") produced a
candidate identical to the good fixture except for one field:

- `candidate_good.json`: `"evidence_references"` = 4 evidence objects
  (`ev-batch-1`, `ev-constraint-1`, `ev-outcome-1`, `ev-region-2`)
- `candidate_p5.json`: `"evidence_references"` = `[]`

The admission verifier **accepted** it with `decision_mismatch_count: 0`.
The admitted `compact_state.json` carries **0 evidence objects**, while its
`supported_claims`, `current_constraints`, and `confirmed_outcomes` still
carry per-item `evidence_refs` pointing at the now-absent evidence IDs:

- claim `deployment_region` -> `['ev-region-2']` (object gone)
- claim `max_batch_size` -> `['ev-batch-1']` (object gone)
- constraint `c-budget` -> `['ev-constraint-1']` (object gone)
- outcome `o-cutover` -> `['ev-outcome-1']` (object gone)

A candidate that severed all required evidence objects from the carried-forward
state was admitted as equivalent. This is the central falsifier from the work
order: "A materially incorrect candidate — one that changes the
receiver-protected projection — is admitted as equivalent."

## Why the frozen contract says this state was required

1. The receiver-owned compaction policy (`policy/compaction_policy.json`) lists
   `evidence_references` in `keep`. `compaction.py` enforces
   `set(body.get("keep", [])) == KEEP_RULES`, and `KEEP_RULES` contains
   `"evidence_references"`. The keep rules are the receiver's declaration of
   what must survive compaction.
2. The internal compactor (`derive_compact_state`) always populates
   `evidence_references` with the evidence objects referenced by the admitted
   items (`used_refs`). The candidate contract *requires* the field but
   permits it to be empty — the schema does not enforce non-emptiness.
3. The original work order explicitly forbade weakening the `evidence
   references` invariant and named this as the central falsifier.

## Exact reason the verifier missed it

`compaction.compact_projection()` (the projection used on both sides of
`decision_equivalence_report`) reads per-item fields only:

- `supported_claims`: slot, value hash, `evidence_refs` (the ID list)
- `current_constraints`: id, text hash, `evidence_refs`
- `confirmed_outcomes`: id, text hash, `evidence_refs`
- `unresolved_questions`, `contradictions`, `tombstones`

It never reads the top-level `evidence_references` collection. The projection
compares evidence *reference IDs*, never the evidence *objects* those IDs
point to. Emptying the collection is therefore invisible to the equivalence
check: `compact_projection(p5) == compact_projection(good)` and both match
the independent `reference_projection`.

The boundary is drawn at "the same IDs are cited" instead of "the cited
evidence survives." A producer can delete every evidence object and still
pass, as long as the (now dangling) IDs are repeated on the items.

## Artifacts in this directory

- `candidate_p5.json` — exact candidate bytes admitted (frozen)
- `manifest_p5.json` — exact manifest (frozen)
- `admission_result.json` — exact admission result (`accepted: true`,
  `decision_mismatch_count: 0`)
- `reference_projection.json` — exact independent projection result
- `candidate_projection.json` — projection derived from the P5 candidate
  (identical to the good candidate's projection: the loss is invisible here)
- `admission_out/` — the full admitted output package, including
  `compact_state.json` (0 evidence objects, dangling refs) and
  `decision_equivalence_report.json`
- `reproduce.py` — minimal reproducer (standalone; NOT wired into pytest)
- `HASHES.txt` — sha256 of every frozen file

## Reproduction

```
cd <repo root>   # branch feat/compiler-neutral-admission-001
PYTHONPATH=src python3 evidence/frozen-failures/p5-evidence-refs-emptied/reproduce.py
```

Expected (frozen) behavior: exit 0 after asserting admission accepted with
zero mismatches. If a future mechanism change makes this script fail, the
boundary has moved — investigate, do not delete the record.
