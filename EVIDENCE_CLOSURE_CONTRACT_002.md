# Evidence-Closure Contract — HALF-LIFE-CANDIDATE-ADMISSION-002

Frozen before implementation. Committed to branch
`feat/candidate-admission-002-evidence-closure` before any code change.

## The invariant (verbatim)

**Every evidence reference relied on by protected candidate state must resolve
to the exact source-bound evidence required by receiver policy.**

## Terms

1. **Protected candidate state.** The candidate's `supported_claims`,
   `current_constraints`, and `confirmed_outcomes` — the items whose per-item
   `evidence_refs` feed the decision projection. The closure set is the union
   of all evidence IDs cited in their `evidence_refs`.

2. **Resolution.** Each cited ID must resolve to an evidence object present in
   the candidate's top-level `evidence_references`.

3. **Exactness.** Each resolved object must be content-identical (canonical
   JSON equality) to the source-bound evidence object with that ID taken from
   the verified source history at the admitted checkpoint — the same evidence
   index the independent replay uses (`reference_replay`, later turns winning).
   Half-Life compares against the source, never against a producer's
   preservation report.

4. **Carried, not archived.** The evidence objects must be present in the
   admitted compact state. Availability in the recoverable archive is not a
   substitute for carried state.

5. **Ambiguity rules.** A cited ID absent from `evidence_references` fails
   (`evidence_not_carried`). A cited ID with no source-bound evidence fails
   (`evidence_not_in_source`). Two carried objects under one ID with
   divergent contents fail (`evidence_ambiguous`). An object whose contents
   differ from the source-bound object fails (`evidence_altered`).

6. **What this is not.** This is not byte identity with Half-Life's own
   compactor output: ordering and serialization may differ; canonicalization
   applies. This is not trust in any compiler preservation report.

## Enforcement

An independent closure check runs in `admit_pipeline` after the existing
decision-equivalence match and before any admitted artifact is written.
Refusal is deterministic: `AdmissionRejected` with reason code
`evidence_closure_failed` and mismatches naming each unresolved or altered
ID. No repair, no substitution, no silent carry-over. The internal `run`
path is untouched.

## Archive-vs-carried resolution (sourced)

The receiver-owned compaction policy lists `evidence_references` in `keep`
(`policy/compaction_policy.json`; enforced against `KEEP_RULES` in
`compaction.py`). The keep rules govern what must survive compaction into the
carried-forward compact state — and the trusted internal compactor implements
this rule by deep-copying the full evidence objects backing every cited ref
into the compact state's `evidence_references` (`compaction.py:379`):
`"evidence_references": sorted((copy.deepcopy(evidence[ref]) for ref in
used_refs), ...)`. The archive (`cold_archive/receipts`) preserves the raw
source chain as the recoverable backstop; it does not carry the compact
state's required material. Existing semantics are not ambiguous on this
point: the policy requires evidence objects **carried in the admitted compact
state**, and archive availability must not substitute for that carried state.

## Claim boundary

This establishes evidence closure for candidate admission. It does not
establish semantic preservation of arbitrary LLM behavior, production memory
safety, or compatibility with any external compiler.
