# Claim boundary

This repository verifies state-compaction mechanics.

A successful run can establish that the supplied source receipt chain verified under a pinned signer, the exact checkpoint and policy were bound before compaction, a separately pinned operator key approved that checkpoint, the compact state reproduced the independent full-history decision projection, and the source receipts were recoverable from a hash-addressed archive.

It does not establish that the source evidence was complete or true, that production key custody is secure, that the compact state is universally smaller, that a model is better than another model, or that any protected action may execute.
