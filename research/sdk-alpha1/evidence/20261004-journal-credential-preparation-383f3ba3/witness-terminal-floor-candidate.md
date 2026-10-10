Candidate bounded terminal retirement for coupled witness renewal

Status: isolated design input, not implemented or proved.

Existing root-signed credential renewal already binds strictly increasing predecessor/successor roster checkpoints (identity/renewal.rs:192). A per-subject monotonic successor-roster-version floor may reject delayed prepares after their terminal record is acknowledged and pruned. An exact pending/terminal slot binds proposal, grant, operation and statement; close and apply compete atomically for that slot. Terminal acknowledgement requires exact slot identity, and the client must durably retain its terminal classification first. An absent or pruned slot reports unknown/retired, never NoCommit.

A close received before prepare can store an exact Closed outcome and consume that signed target version. A later distinct grant from the still-current predecessor must choose a higher successor roster version. The original closed grant cannot be assigned a fresh unbound sequence to escape the floor. Ordinary Advance, Fence and roster control-plane mutation must not bypass a prepared joint transaction. An applied exact transition remains recoverable after expiry, but recovery does not release an expired owner.

The two-target finite model explores 56 states and 80 edges under explicit trusted-grant, freshness, atomic-storage and single-writer assumptions. Removing the floor admits reserve -> close -> local terminal retention -> ack/prune -> delayed prepare -> apply of the closed original operation. Allowing ordinary replay after local preparation admits an immediate head/authority split. These are model counterexamples and bounded checks, not implementation reproductions or cryptographic security proofs.

Before implementation: verify subsequent roster-refresh interactions, original credential lineage, same-version conflicting operations, historical grant parsing after expiry, policy closure, storage format migration, exhaustion, exact fresh signed status, delayed acknowledgements and global operation bounds. Recheck the chosen floor against the final threat model; do not enable required-witness enrollment merely because this model passes.
