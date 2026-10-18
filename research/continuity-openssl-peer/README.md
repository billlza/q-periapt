# Independent Continuity interoperability peer

This unpublished Python endpoint implements a first, deliberately bounded part
of the candidate protocol independently of the Q-Periapt engine. It constructs
and authenticates real protocol flights; it does not call the Rust candidate to
parse, verify, derive, encapsulate or finish its own operation. Cryptographic
primitives use `cryptography 48.0.1` with OpenSSL. PyCA's own provider bindings
contain Rust, but contain no Q-Periapt protocol implementation.

The separate `native` executable is the actual Rust **responder** and a test
enrollment authority. It issues fresh credentials for the Python-owned signing
public key and independently owned Rust responder. Its public-only files supply
explicit test trust pins and untrusted signed material through separate inputs.
This is controlled enrollment for the experiment, not a network registration or
trust-distribution protocol. No private key or KEM secret crosses the control
pipe. Three-flight payloads use the unchanged candidate bytes.

The current supported profiles use reusable-both prekeys, a two-leaf manifest,
and the stated fixed SDK algorithm policy. Local-only sessions and sessions with
one explicitly pinned required witness have separate creation/opening APIs.
Local and volatile entry points reject required-witness policies. One-time modes
and other manifests/policies fail instead of selecting a weaker mode.
The peer independently verifies SDK and protocol policy, both
identity chains, exact roster heads, validity, key separation, the manifest and
both leaf proofs. It constructs the canonical selection and role-ordered context
before doing the policy-bound hybrid KEM and confirmation schedule.

The protocol code is in `peer/wire.py`, `peer/authority.py`, `peer/kem.py`,
`peer/bootstrap.py`, `peer/traffic.py`, and `peer/rekey.py`. The bounded runner and Rust test
counterpart are separate.
Failed replies leave the original operation pending. Successful replies pin the
exact bytes; identical replay returns the same final, and a conflicting reply
fails. Bootstrap owner operations check the supplied trusted time. Close is idempotent
and prevents future operations.

## Run

Use the repository-pinned Rust toolchain and the committed separate lockfile:

```sh
cargo build --release --locked \
  --manifest-path research/continuity-openssl-peer/native/Cargo.toml
sh artifact/python-run.sh research/continuity-openssl-peer/run.py \
  --provider-root /absolute/path/to/site-packages \
  --native /absolute/path/to/q-periapt-independent-peer-counterpart \
  --output /absolute/path/to/new-result-directory
```

The explicitly supplied provider directory must contain the pinned
`requirements.txt` dependencies. The CI workflow installs only hash-pinned
CPython 3.14 wheels into a new job-local directory, using `--no-deps` and
`--require-hashes`. The hardened repository launcher remains in use;
the runner does not process `.pth` files, import `site`, or use `PYTHONPATH`.
Nothing is installed globally. This first control-pipe runner supports POSIX.
Each control exchange has a 30-second deadline and a 32768-byte response cap.
Failures terminate the owned native process group and remain failures.

`RESULT.json` records actual versions, loaded provider/source hashes, the native
binary hash, canonical-byte agreement, real native responses and rejected cases.
Public signed input files and the three successful protocol flights are retained.
The controls exercise each signature component, malformed envelopes, pin and
validity violations, invalid confirmation with valid signatures, exact replay,
conflicting replay and closed owners. The native invalid-ciphertext control is
re-signed with the real initiator key so it reaches KEM confirmation.

## Limits and next integration

The second experiment transfers a confirmed root into independent epoch-zero
traffic and exchanges real application ciphertext with a Rust `DeviceJournal`.
It covers both directions, empty/ordinary/16-KiB plaintext, up to 1-KiB application
AD, reordered delivery, rejected tags/AD, skipped keys, exact outbox replay,
contiguous consumption ACKs and retired IDs. Five Rust journal close/reopen
boundaries retain reply, completed bootstrap, skipped keys, outbox and ACK state.
Traffic runs at trusted time 170 after the prekey advertisement expires at 160;
the credentials, rosters and policy remain valid until 200. An authenticated stale
ACK leaves the current higher floor unchanged. This is interoperability evidence
for the root/traffic schedule, not merely agreement on the public session ID.

`peer/traffic.py` is explicitly **volatile**: it does not supply commit-before-
release or independent persistence. `traffic_checks.py` contains the separate
experiment driver. Rust enrollment, control framing and durable operations are
separate modules. Private Rust fixture files stay outside the public artifact
directory and are retained, including on failure; only their path is recorded.
No wrapping key or encrypted private image is uploaded. Reopen here is within
the original process; it is not a process-crash or power-loss experiment.

The [independent storage/session implementation](STORAGE.md) now separately
persists waiting bootstrap, confirmed roots, traffic epochs, exact send reservations,
four-flight rekey and consumption. It reopens the original material in fresh OS processes and tests
real process interruption before results are returned. Identity signing keys stay
outside the session journal. `storage_checks.py` covers the file transaction;
`durability_checks.py` covers persisted protocol recovery against the Rust peer.
The separate `rekey_checks.py` lane now computes all four signed rekey flights
with independent KEM, root/confirmation and epoch traffic/ACK derivations. Eight
alternating exchanges interoperate with real Rust journal cutovers, including
asymmetric progress after final, cached control replay and bidirectional traffic.
The computational lane remains volatile. The subsequent `durable_rekey_checks.py`
uses the journal-owned `Session`, an explicit upgrade from `QPREFS01`,
separate directional cutovers, exact control outboxes and the aggregate unconfirmed
send budget. It retains unsettled epochs and resumes after process loss.
`control_checks.py` exercises signed progress requests and one-step control driving
without dummy application traffic. `QPREFS03` adds the retained request; both older
formats remain readable without implicit migration. The new driver requires
explicit upgrade, including when a version-two send or rekey is already pending.
Control calls select one target, replay committed output and distinguish local
confirmation from delivery of the final receipt. The host bounds retries and
continues servicing peer controls. The following outcome-reporting lane adds
`QPREFS04`: an explicit freeze of a closed epoch, an immutable report and the host's
separate durable acknowledgement. Unconfirmed sends then remain `DeliveryUnknown`;
the original acknowledgement floor is preserved. Frozen old operations cannot
release traffic, while new epochs remain usable. Versions one through three stay
readable without implicit migration. Network transport/scheduling and full identity
lifecycle remain required.
No completed exchange count asserts post-compromise security.
The earlier volatile class remains a cryptographic core, not a durable facade.

This is not an admitted independent Continuity product implementation. Authority
renewal, revocation, account fanout, the complete installation/migration
lifecycle, network carriers and installed-package qualification remain required.
`resolution_checks.py` exercises process interruption, exact report recovery,
application accounting and subsequent history collection. `resolution_capacity_checks.py`
uses the direct host API for all 64 retained 16-KiB plaintexts; the bounded test
pipe is not an application report transport. `resolution_disclosure_checks.py`
gives an isolated forge function only one old sending chain. A real Rust peer
consumes two forged old messages and emits an out-of-range ACK; the independent
sender refuses it and retains its genuine outbox. Explicit unknown-outcome
accounting allows the same later rekey offer to proceed. This does not establish
post-compromise confidentiality or undo effects of old forged traffic.

The Rust side is
a separate Cargo consumer of the current source graph. Root transfer into the
volatile experiment is one-use and adds no root-export hook to the Rust SDK.
The synthetic confirmation control changes a test verification key directly;
that context is never passed to the real Rust counterpart.

Python bytes and provider temporaries do not provide the Rust SDK's zeroizing
owner guarantee; dropping references does not prove erasure. Private session state
is sealed in its store; public artifacts omit wrapping keys and private images.
The peer's fixed authority snapshot and trusted-time input do not implement
concurrent policy replacement. Local-only stores have no whole-store rollback
protection. Required-witness stores reject a local image that differs from the
live witness, assuming the witness retains its own state independently.
Deployment and the remaining lifecycle still need integration before this lane
can close the independent implementation requirement.

`witness_checks.py` exercises the required profile against an actual Rust
`AnchorStore` and an actual required-witness Rust session journal. Explicit
inactive provisioning exports only an operator-approved genesis; normal peer
requests cannot register it. Fresh challenged queries and authority checks gate
ordinary outputs, and exact signed advancement precedes local publication.
Three real process cuts cover creation intent, remote advancement and local
publication. Lost replies preserve the original intent, even when an already
committed transition must be reconciled after expiry. Cached output still needs
current authority. Restored client backups and a changed writer fence fail.
The loopback TCP bridge is test orchestration for the signed witness byte carrier;
it is not a separately deployed witness or an application network carrier.

The byte contract is [WIRE_V1](../../docs/continuity/WIRE_V1.md), with the
[bootstrap KDF graph](../continuity-identity-candidate/BOOTSTRAP.md#three-flights)
and SDK purpose schedule in `crates/q-periapt-sdk/src/purpose.rs`. Provider API
references are the official [ML-KEM](https://cryptography.io/en/48.0.0/hazmat/primitives/asymmetric/mlkem/)
and [ML-DSA](https://cryptography.io/en/48.0.0/hazmat/primitives/asymmetric/mldsa/)
documentation; the executed package and OpenSSL versions are recorded per run.
