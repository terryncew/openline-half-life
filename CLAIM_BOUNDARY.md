# Claim boundary

This repository verifies state-compaction mechanics.

A successful run can establish that the supplied source receipt chain verified under a pinned signer, the exact checkpoint and policy were bound before compaction, a separately pinned operator key approved that checkpoint, the compact state reproduced the independent full-history decision projection, and the source receipts were recoverable from a hash-addressed archive.

It does not establish that the source evidence was complete or true, that production key custody is secure, that the compact state is universally smaller, that a model is better than another model, or that any protected action may execute.

## Candidate admission (0.4.0rc3)

A successful candidate admission can additionally establish that an externally produced compact-state candidate preserved the receiver-protected decision projection under independent replay, and that every evidence reference relied on by its protected carried state resolved to a carried evidence object whose canonical content was identical to the source-bound evidence from the verified source history. Evidence closure is checked against the source history, not against Half-Life's own compiler output; the archive is not a substitute for required carried evidence state.

It does not establish arbitrary model-behavior equivalence, compatibility with any external compactor or language model, production safety, demand, or adoption. Continued use of an admitted compact context is not automatically conditioned on the standing of its evidence dependencies; the standing-loss signal and the rehydration path are available to the receiver, not system-enforced.

## context-admit (0.4.0rc4)

The `context-admit` CLI productizes the receiver-invoked standing check: a caller can ask whether an admitted compact context still matches the receiver-protected state implied by a verifiable current history. A CURRENT answer establishes that the admitted package verified, the current history was available and verifiable, standing was computable, the admitted protected state was equivalent to the current protected state, and required evidence standing held.

It does not establish that the check ran, that any caller invoked it before reuse, or that future model calls are intercepted. The conditioning remains caller-invoked, not automatic. A missing or unverifiable history is never treated as current.
