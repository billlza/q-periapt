# Retained native-consumer lock inventory repair

The native and WASM Rust analysis jobs in [run 42959257074](https://github.com/billlza/q-periapt/actions/runs/42959257074)
stopped at `tracked workspace lock inventory differs`. The run checked merge
`834c67183c403fd10d65600252ecbcb950c1af11`, combining PR #115 head
`3c9df1feeb7857e53ac4d6269788d20c87851459` with integration source
`56eb5dca95a913539040d0939c733d1f11f89d50`. The native job is
`130321600057`; the WASM job is `130321599982`.

Git's `*Cargo.lock` pathspec includes the retained
`research/sdk-alpha1/evidence/20261110-native-distribution/consumer-Cargo.lock`.
This evidence file already exists in the integration source. Its exact bytes
now join the two pinned paper locks in the archival inventory. The eight live
Cargo roots retain their exact names and order. Each discovered archive must
retain its pinned SHA-256 and have no adjacent `Cargo.toml`; the native packet's
prefixed `consumer-Cargo.toml` remains an archival record. Unknown prefixed
locks still fail the live-root inventory check.

## Verification

`inventory-review.json` records an independent reproduction against the exact
7,817-entry integration Git index. A temporary checkout materialized the
three archived files from that commit. The prior implementation rejected the
actual inventory; the repaired implementation returned all eight original
live roots after checking the three archival hashes. This experiment exercises
inventory admission, before compilation and query evaluation.

`focused-tests.log` retains 38 passing checks: all 34 Rust analysis-profile
tests and four existing Rust package lock-scope and drift tests. The new
regression uses a real Git index to exercise suffix matching, accepts the
pinned prefixed archive, and rejects an unreviewed prefixed lock. Existing
rejection cases cover changed archived bytes, adjacent regular or symlinked
`Cargo.toml`, and missing, added, substituted or duplicated live roots.

`validation.json` binds the changed source hashes, retained evidence hashes,
test command and hosted failure identities. Compilation, the full query suite
and paired publication retain their existing admission checks.
