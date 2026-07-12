# Continuity canonical-projection EasyCrypt diagnostics

This directory is intentionally separate from the paper's ContextBound binding
development. `LifecycleContextV1.ec` machine-checks three narrow facts about the
non-normative lifecycle candidate:

- the modeled LP8 lifecycle body is injective over its ordered common fields and
  variant-tail field list;
- the policy-bound K-CTX and durable digest preimage preserve that injectivity;
- omitting either `policy_digest` or `direction` admits an explicit structural
  collision between distinct modeled contexts.

`PrekeySelectionV1.ec` separately proves injectivity of the sixteen-field LP8
selection projection and its nested digest preimage. Named omission controls
cover the suite, responder credential, bundle epoch, directory checkpoint,
manifest, both mode bytes, and all four signed/selected prekey identifiers.

Run:

```sh
EC="$HOME/.opam/default/bin/easycrypt" make check
```

This is not a protocol proof. Fixed-width field encoders, field authenticity,
semantic completeness, Rust correspondence, SHA3 collision resistance, decoding,
state advancement, FS/PCS, directory consistency, manifest membership, unique
leasing, prekey consumption, persistence and device behavior remain outside this
development. The frozen Rust/Python vectors are separate executable evidence; a
future refinement or translation-validation gate must connect the two.
The Makefile uses EasyCrypt's `-no-eco` mode so a diagnostic run cannot introduce
an untracked compiled cache into the canonical source inventory.
