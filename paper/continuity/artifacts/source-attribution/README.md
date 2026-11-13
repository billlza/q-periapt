# Executed-source attribution and signing reservations

This artifact connects an executed-slot selector to the original sources of an
accepted native rekey. It contains the complete proof, an independently reviewed
manuscript module, exact source identities and executable finite controls.

The stable source slots, accepted-allocation association, signature component
adapters and generic signing-coin separation appear in
[`source_attribution_proof.md`](source_attribution_proof.md) and the main
[`source-attribution.tex`](../../source-attribution.tex) module. The independent
review files in this directory record the reviewed hashes and concrete
counterexample checks.

## Established connections

Original generation and encapsulation indices are registered before their first
private computations return. They keep the reservation's original sampling
event. Persist-before-compute and exact retained-plan transitions make these
registered sources stable within one authoritative local epoch. The signed
body and complete-wire checks then imply that eligible source-association
failure requires a fresh-body signature event or a relevant hash collision.
The signature event stops before the first target key/file disclosure.

The signature service preserves original randomizers and replay. For its
declared owner interface, the native hybrid signature has an exact reduction to
the reservation-aware ML-DSA component. Its deterministic RFC 6979 P-256
component additionally gives a classical ordinary-EUF-CMA reduction. The owner
interface exposes public metadata and signing reservations, with no earlier
byte-dependent observation of the target secret-seed file. Both native
signature components remain required by the protocol.

The generic separation appends a one-time-padded secret-key encoding to a base
signature. Its ordinary signing transcripts have exact simulators in both
directions; opening the original randomizer recovers the secret. This is a
separation of interfaces, not a claimed vulnerability in ML-DSA. The
post-quantum branch names its reservation-aware ML-DSA assumption explicitly.

## Reproduce the finite and source checks

From the manuscript repository root, the finite model runs on its own:

```sh
sh artifact/python-run.sh paper/continuity/artifacts/source-attribution/check_source_attribution.py --finite-only --output paper/continuity/build/source-attribution-finite.json
```

The full audit also requires the seven native files at
`72acaaccde1ca9ea27e5af022da5fbce932ed4e9`. The dedicated manuscript branch keeps
these sources in a separate sparse checkout. To prepare a fresh checkout and
run the full audit from the manuscript repository root:

```sh
SOURCE_ATTRIBUTION_NATIVE="$PWD/paper/continuity/build/source-attribution-native"
SOURCE_ATTRIBUTION_COMMIT=72acaaccde1ca9ea27e5af022da5fbce932ed4e9
git init "$SOURCE_ATTRIBUTION_NATIVE"
git -C "$SOURCE_ATTRIBUTION_NATIVE" remote add origin https://github.com/billlza/q-periapt.git
git -C "$SOURCE_ATTRIBUTION_NATIVE" sparse-checkout set --no-cone \
  research/continuity-identity-candidate/src/crypto.rs \
  research/continuity-identity-candidate/src/crypto/persistence.rs \
  research/continuity-identity-candidate/src/durable/messages/rekey.rs \
  research/continuity-identity-candidate/src/durable/messages/rekey/response.rs \
  research/continuity-identity-candidate/src/durable/messages/rekey/completion.rs \
  research/continuity-identity-candidate/src/durable/messages/tests/classical_alias.rs \
  research/continuity-identity-candidate/src/contract.rs
git -C "$SOURCE_ATTRIBUTION_NATIVE" fetch --depth 1 origin "$SOURCE_ATTRIBUTION_COMMIT"
git -C "$SOURCE_ATTRIBUTION_NATIVE" checkout --detach "$SOURCE_ATTRIBUTION_COMMIT"
test "$(git -C "$SOURCE_ATTRIBUTION_NATIVE" rev-parse HEAD)" = "$SOURCE_ATTRIBUTION_COMMIT"
git -C "$SOURCE_ATTRIBUTION_NATIVE" rev-parse HEAD > paper/continuity/build/native-source-commit.txt
sh artifact/python-run.sh paper/continuity/artifacts/source-attribution/check_source_attribution.py --repository "$SOURCE_ATTRIBUTION_NATIVE" --output paper/continuity/build/source-attribution-check.json
```

An existing checkout of that checkpoint can also be passed directly with
`--repository`. The file hashes in `source_identity.json` must still match.

The full command passes **44 checks**, including seven exact native-source
identities and their extraction assertions. The portable command passes
**24 finite checks**. Each source model explores **34 recovered states**,
over at most three original draws and two epochs, with **486 call-boundary
edges** across the generation and encapsulation models. Six deliberate
source-tracking mutations are rejected by explicit causal traces. A fixed
expected matrix checks offer, response and final signature aliases. Signature
models preserve original randomizers and private-query ledgers across failed
publication, and enumerate all 64 assignments in the small separation example.

The native code pin inspected by this increment is
`72acaaccde1ca9ea27e5af022da5fbce932ed4e9`.
[`source_identity.json`](source_identity.json) records complete file hashes;
five files also match the earlier pinned confirmation artifact. Historical
native and formal-tool executions are unchanged. These new commands execute
finite Python models and source audits, with **no native Rust or formal-verifier
execution**. The mathematical results are the separately reviewed arguments.

The manuscript CI fetches the same seven paths in a second, commit-pinned
checkout, verifies its `HEAD`, and runs the full command with `--repository`.
It retains `native-source-commit.txt` and the exact check receipt alongside the
compiled manuscript and source export.
