# fips204 0.5.0 adapter and lock review

This packet qualifies the dependency update against SDK integration base
`56eb5dca95a913539040d0939c733d1f11f89d50`.

The original PR #115 changed the backend manifest and detached fuzz lock but
left the main lock at 0.4.6. Its recorded check failed at Cargo's `--locked`
admission. Version 0.5 also replaces the `Ph` message-taking interface with a
digest and DER-encoded OID. The adapter now computes the same 32-byte SHAKE128
digest explicitly and passes `pre_hash::SHAKE_128`. Its public message-taking
API, context, caller randomness, key validation and output atomicity remain.
The SHAKE state, reader and temporary digest retain zeroizing storage.

The upstream [0.5.0 release](https://github.com/integritychain/fips204/releases/tag/v0.5.0)
and downloaded registry archive were inspected. Archive SHA-256:
`a823e139c2d539b1b735d31cdce8b0b356671585eac3d54dec79d1d15052093b`.
The former and current pre-hash constructions use the same 32-byte digest and
OID `060960864801650304020b`; the new interface hashes the message once.

## Validation

- All 73 Rust tests pass: 68 backend unit tests and five integration tests.
  They include the three ML-DSA parameter sets' retained NIST pure, contextual,
  hedged and SHAKE128 HashML-DSA vectors; independent RustCrypto byte comparisons;
  malformed-key rejection; and output atomicity. The final test command uses
  `--locked --offline` and Rust 1.94.0.
- Four existing package-scope and lock-drift tests pass. The exact fuzz count
  changes from 47 to 46 because fips204 no longer needs SHA2 0.10.9 there.
  The workspace still needs that package and retains its 271-entry registry
  scope. The prior arbitrary/derive_arbitrary 1.5.0 update remains present.
- Full `cargo metadata --locked` succeeds for the root workspace, fuzz,
  Continuity candidate, OpenSSL native peer and reference application. Each
  resolves fips204 0.5.0. The compressed outputs preserve the complete graphs.
- Independent review verifies the archive identity, API adaptation and all
  five lock diffs. The only package version replacement is fips204; the only
  additional graph changes remove unused SHA2 0.10.9 and activate the existing
  SHA3 0.10.9 dependency's zeroize edge. Cargo also removes now-unneeded version
  qualifiers from remaining SHA2 0.11.0 edges.
- `rustfmt` and `git diff --check` pass.

The five live locks advance together. Frozen paper sources, prior execution
packets and the published 0.1.5 cohort retain their original dependency and
source identities. Current dependency documentation names the new adapter.
Hosted qualification remains attached to the subsequently published commit.

`evidence-manifest.json` binds the retained logs, graph outputs and independent
review. `focused-validation.json` records the final test commands and timings.
