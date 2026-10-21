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

The protocol code is in `qperiapt_continuity_reference`, including `wire.py`,
`authority.py`, `kem.py`, `bootstrap.py`, `traffic.py`, and `rekey.py`.
The [host enrollment exchange adapter](ENROLLMENT_EXCHANGE.md) accepts public
invitations and issued results against separately supplied host, current-roster
and signed-policy expectations using the original protected registration owner.
The bounded runner and Rust test counterpart are separate.
The [`publication` adapter](../continuity-reference-app/NATIVE_SESSION.md) also
consumes public advertisements from the native enrollment CLI without a built-in
issuer. It authenticates through the same independent verifier and prepares the
original `EnrollmentClient`. The native reference serves bootstrap, durable inbox
delivery and rekey control over file and explicit TCP carriers. The independent
[session CLI](SESSION_CLI.md) sends and receives on that original confirmed
connection, with durable host inbox commands and process recovery. Opposing
application sends release local owners during network I/O and revalidate their
original operation on completion. Simultaneous rekey and cross-host deployment
remain separate acceptance gates.
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

### Install the Python reference

`pyproject.toml` builds the unpublished `qperiapt-continuity-reference` wheel.
Its import namespace is `qperiapt_continuity_reference`; the generic `peer`
namespace is no longer used. The wheel contains the protocol and explicit
provider loader, without the test issuer, native process driver or private
fixtures. The reference version is `0.0.0`, with CPython 3.14 and the pinned
provider below. Current qualification is for the stated POSIX profiles; the
pure-Python wheel tag does not qualify other operating systems.

From this directory, build in a dedicated virtual environment:

```sh
python3.14 -m venv /absolute/path/to/build-environment
/absolute/path/to/build-environment/bin/python -I -m pip install \
  --no-deps --require-hashes -r build-requirements.txt
/absolute/path/to/build-environment/bin/python -I -m pip wheel \
  --no-index --no-deps --no-build-isolation --wheel-dir /absolute/path/to/dist .
```

In a separate consumer environment, install the fixed provider requirements and
the produced wheel:

```sh
python3.14 -m venv /absolute/path/to/consumer-environment
/absolute/path/to/consumer-environment/bin/python -I -m pip install \
  --no-deps --require-hashes -r requirements.txt
/absolute/path/to/consumer-environment/bin/python -I -m pip install \
  --no-index --no-deps /absolute/path/to/dist/qperiapt_continuity_reference-0.0.0-py3-none-any.whl
```

Select the provider before importing protocol modules:

```python
from pathlib import Path
import sysconfig
from qperiapt_continuity_reference.provider import load_provider

load_provider(Path(sysconfig.get_path("platlib")))
from qperiapt_continuity_reference.registration import Registration
```

`Registration` still requires the separately approved intent and protected local
state described in [REGISTRATION.md](REGISTRATION.md). Installation does not
choose trust roots or turn a received bundle into account authentication.
The qualification consumer runs with `-I -S -B`, a private empty cache prefix,
and explicit installed/provider directories; normal virtual-environment use
does not by itself promise that stronger import-path isolation.

The CI consumer uses `artifact/continuity_independent_python_run.py` to inspect
the wheel, install it with pip into a fresh directory outside the checkout, and
run the existing registered-owner scenario there. Only the test harness and
inventory inputs are copied; current protocol modules must come from the wheel. The
probe records every loaded module and checks isolated import paths. Installed
files, original wheel, native binary and selected source bytes are checked again
after execution. The helper uses the existing Git provenance boundary and
requires an ordinary checkout with a real `.git` directory. Failed states stay
available for diagnosis; a missing or failed installation is never treated as
a successful source-tree run.
The installation runner also requires local and witnessed policy renewal,
full-store expiry/recovery, and sequential policy/credential/roster composition
ending with removal of the real traffic peer. Schema9 checks all four 3/32-device
composition profiles using installed protocol modules and the selected native
counterpart; source-only results cannot satisfy them. See
[POLICY_RENEWAL.md](POLICY_RENEWAL.md) for the retained-history boundary.
The archived migration scenario additionally copies the declared old-writer
capture and its manifest, bound to the selected commit. It loads that writer in
a separate namespace, then uses the installed current package to continue the
same journal. Only the known capture has a 32-MiB input allowance; normal
qualification inputs and protocol limits retain their existing bounds.

### Counterpart built from installed archives

The native fixture can also be built outside the checkout from a separately
hash-pinned SDK package report and a freshly packaged current Continuity crate:

```sh
sh artifact/python-run.sh artifact/continuity_independent_package.py \
  --report /absolute/path/to/sdk-rust-package/RUST_SDK_PACKAGE.json \
  --report-sha256 EXPECTED_REPORT_SHA256 \
  --toolchain-root /absolute/path/to/rust-1.98.1-toolchain \
  --output target/independent-installed-new
```

This checks current source against the crate contents, builds and lints the
original counterpart with eight installed SDK crates plus Continuity, and
requires the original external dependencies and complete lockfile unchanged.
Only the counterpart is a workspace member. The output contains the generated
manifest, Cargo graph, binary and `INSTALLED_COUNTERPART.json`. The public
bootstrap importer example is also built and linted from the installed Continuity
crate in the same dependency graph; its executable is `importer`. Both executable
hashes are recorded. A new registry
cache is used by default; `--cargo-home` may explicitly select a cache without
configuration or credentials. Supported hosts are Apple Silicon and Linux x86_64.

Pass `target/independent-installed-new/counterpart` as `--native` to the existing
drivers, including `registration_checks.py`, and pass the sibling `importer` as
`--importer` to `public_input_checks.py`. A successful build report explicitly
has `runtime_qualified: false`; execution receipts must name that binary's hash.
This archive boundary does not establish a deployed issuer, an independently
installed Python distribution, a cross-host network carrier or release admission.

Source qualification uses the SDK packaging provenance check and requires a clean
ordinary checkout with a real `.git` directory. Linked worktrees should be copied
to a clean checkout at the same commit for this entry point.

The independent CI workflow accepts optional `sdk_run_id` and
`sdk_report_sha256` dispatch inputs. Supplying both builds the counterpart from
that same-repository SDK artifact, including the public importer, before running the protocol checks;
the report and crate bytes must still match current SDK sources. Supplying only
one input fails. The default workflow retains direct-source qualification.

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

`qperiapt_continuity_reference/traffic.py` is explicitly **volatile**: it does not supply commit-before-
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

The next state format, `QPREFS05`, retains independently approved remote same-key
credential renewals and signed peer roster changes for the original established
session. Exact predecessor, retained original lineage, full key, operation, policy and
target checkpoint must match. Committed peer revocation denies cached output,
new traffic and rekey; a later roster cannot revive the observed old generation.
The original transcript, keys, outbox IDs and ciphertexts remain unchanged.
The local owner still needs current authority. Same-account updates require the
separate local account coordinator; this entry cannot bypass that joint workflow.

An already established peer session may have started with an intermediate
credential `C1`. It can adopt a root grant naming `C0, C1 -> C2` when the retained
current credential and roster match that exact predecessor. Peer verification
checks the complete pinned identity and the grant's retained-established
permission; subsequent grants must preserve the first admitted original lineage.
Local installation renewal still requires its exact original credential and
storage owner. `peer_intermediate_checks.py` exercises real C1 bootstrap, a
process kill during G2 adoption, original ciphertext/plaintext recovery, rekey,
and revocation with both local and required-witness stores. Its explicit fixture
clocks are not a real-time expiry or complete same-account lifecycle test.

The `AccountState` model keeps one account roster, up to 256 retained device
generation records, and the root grants that justify same-generation credential
changes. `AccountRequest` serializes the complete local-and-companion collection
and compares requests by signed statement identity. The owning coordinator must
retain the first saved bytes when a semantically identical request is retried. The
local verifier continues to require the exact original installation credential;
verifying a companion grant does not grant a local owner.
`account_state_checks.py` exercises native-signed three- and 32-member changes,
lineage substitution, incomplete collections, root-signed resurrection and
generation rollback, and canonical account/request decoding. Its native example
is a source-built test authority even when the traffic counterpart uses installed
SDK crates. Those model checks establish pure transitions only.

Registered common-account sessions use `QPREFS09`: the unchanged version-five
business image plus one bounded common account and its renewal record.
`stage_account` under a local-only policy and `prepare_account` under a required
witness accept the complete local-and-companion collection. Every changed active
credential must have its root grant; a single-role update cannot silently split
the roster. Both roles derive authority from that one authenticated account.
The first saved request bytes, original signing key, session, reserved sends and
outboxes survive retries and process cuts. See [common-account renewal](SHARED_ACCOUNT.md)
for the conditional formats, recovery and qualification boundaries.
Same-credential shared roster changes use the original registered
[roster coordinator](ROSTER_REFRESH.md), selecting conditional format ten and
its exact witness transition. The generic peer-only owner cannot bypass it.

An independent [joint local credential coordinator](LOCAL_RENEWAL.md) now binds
the original required-witness head transition to the actual root grant. It retains
the exact sealed target and terminal before ACK, permits historical cleanup, and
reopens the same session under its adopted local authority. `QPREFS06` is selected
only for that explicit separate-account transition; separate-account creation and
generic upgrade stay at five. Common-account creation selects nine.

For an original local-only policy, [LocalCredentialRenewal](LOCAL_CREDENTIAL.md)
retains Pending, current local authority, abandonment and a time floor in the
same journal. Conditional `QPREFS08` preserves the original session and outbox
while coordinating expiry and exact-target recovery. It refuses required-witness
contexts and preflights capacity for the completed identity before staging.
Its bounded lifecycle allocation permits renewal of a full original business
store after credential expiry. Version seven remains readable with its original
limits; an already Pending operation completes in that version.

This is not an admitted independent Continuity product implementation.
Policy renewal and retirement, account fanout,
the complete installation/migration
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
The peer's original policy and local identity snapshot do not implement
concurrent policy replacement. Explicit peer authority changes are now retained
separately from the immutable bootstrap inputs. Local-only stores have no whole-store rollback
protection. Required-witness stores reject a local image that differs from the
live witness, assuming the witness retains its own state independently.
Deployment and the remaining lifecycle still need integration before this lane
can close the independent implementation requirement.

`witness_checks.py` exercises the required profile against an actual Rust
`AnchorStore` and an actual required-witness Rust session journal. Explicit
inactive provisioning exports only an operator-approved genesis; normal peer
requests cannot register it. Fresh challenged queries and authority checks gate
ordinary outputs, and exact signed advancement precedes local publication.
At operational result release, one fresh authority reply checks both the recovered
head and current permission; it replaces a separate Query immediately followed
by the same head check. Historical release still queries the head. Recovery of
the exact pending intent, signed response validation, permission checks and
owner closure on failure remain required. The release controls include a real
signed reply with current permission but a different fenced head.
Three real process cuts cover creation intent, remote advancement and local
publication. Lost replies preserve the original intent, even when an already
committed transition must be reconciled after expiry. Cached output still needs
current authority. Restored client backups and a changed writer fence fail.
The loopback TCP bridge is test orchestration for the signed witness byte carrier;
it is not a separately deployed witness or an application network carrier.

`peer_lifecycle_checks.py` covers local and required-witness owners, an actual
archived version-four writer, two chained remote grants, original traffic/rekey,
process cuts, explicit revocation and refused reappearance. Its independent
operations cross the peer's signed expiry at test times 210 and 310; the native
protocol counterpart retains its fixture time 170. It therefore qualifies this
remote acceptance/recovery path, not the native peer's local enrollment renewal.
`peer_reply_release_checks.py` verifies that a host witness callback committing
revocation cannot release a result under the earlier permission. Both callback
cases have preserved failing pre-fix runs and passing repaired runs.
`local_renewal_checks.py` verifies original joint targets across real process
cuts, lost Commit/Close/ACK replies, two local grants and policy-expired cleanup.
It also preserves the refusal to replace unrelated expired pending work.
`local_credential_checks.py` exercises the separate local-only contract with
29 real process cuts, original reserved sends, expiry floors and combined peer
metadata. `local_credential_capacity_checks.py` checks the full 123-row business
boundary across two renewals after original expiry, original seven-to-eight
continuation and independent metadata/file limits. It preserves messages and
does not perform unknown-outcome cleanup to make room. Physical disk or directory
quota exhaustion still fails explicitly.

The independent [pending-write recovery](PENDING_WRITE_RECOVERY.md) owner prepares
complete public views without replaying an expired ordinary write. Its separate
controller approval and fresh Query confirmation preserve the original sealed
target and leave renewal and traffic authorization separate.

The byte-oriented [public input API](PUBLIC_INPUTS.md) accepts the existing
QPBNDL01 container with separate trust expectations. Original-state reconstruction
uses the retained context digest and current trusted time, without a fixed fixture
admission time or a new operational grant.

The [protected registration owner](REGISTRATION.md) now retains its own identity,
original proof-of-possession request, accepted authority and original child
installation. Borrowed session and recovery owners share that lifetime; the
reference does not require a cleartext test signer file for these operations.

The [local enrollment client](ENROLLMENT_CLIENT.md) coordinates original host
configuration, request export, credential acceptance and reopen through an
installed CLI. Its authorization inputs are supplied by the embedding host;
it introduces no account signup requirement. The same API now borrows the
registered session, rekey, credential renewal and pending recovery under the
client lifetime. Full session CLI integration and the documented pre-publication
first-use recovery boundary remain open.

The [account-root statement verifier](ACCOUNT_ROOT_PROTOCOL.md) independently
reconstructs approved plans and verifies complete signed freezes, retirement
and distinct plan/decision closures. Its installed-wheel tests consume public
native operator outputs and check both signature components and exact target
bindings. Durable independent root selection and original session-owner fencing
remain separate controller work; these historical proofs do not grant traffic.

`enrollment_extension_session.py` exercises the explicit preinstallation extension
through the installed client and a native durable peer. The original credential
and policy expire at fixture time160. The native issuer retains those signed
materials, extends the same device key, and issues a separately pinned policy.
Both peers bootstrap at210, exchange bidirectional traffic and complete one PQ
rekey at220, then reopen their owners and recover the original ciphertext. Local
and required-witness profiles refuse expired original policy, retargeting after
child preparation, and use after the extended credential expires. The witness
profile uses the real native store through a bounded loopback bridge.

This separate fixture requires `--registration --registration-extension` and
cannot be mixed with the older local/peer renewal fixtures. Its bootstrap,
traffic and initial witness clocks are explicit; the existing fixtures keep
their original clock contracts. Installed Python receipt schema2 requires this
additional workload and its selected binary/module identities. It does not prove
real account approval, a deployed TLS channel, physical power-loss recovery or
credential renewal of the newly extended bilateral session.

The byte contract is [WIRE_V1](../../docs/continuity/WIRE_V1.md), with the
[bootstrap KDF graph](../continuity-identity-candidate/BOOTSTRAP.md#three-flights)
and SDK purpose schedule in `crates/q-periapt-sdk/src/purpose.rs`. Provider API
references are the official [ML-KEM](https://cryptography.io/en/48.0.0/hazmat/primitives/asymmetric/mlkem/)
and [ML-DSA](https://cryptography.io/en/48.0.0/hazmat/primitives/asymmetric/mldsa/)
documentation; the executed package and OpenSSL versions are recorded per run.

`policy_renewal_proof_checks.py` verifies the native two-root policy-only approval
format independently. Its native producer derives both request scopes from the
same original enrollment and journal, including a second policy adoption and a
separate case following real same-key credential renewal. Both root signatures,
the exact original owner, current credential/roster, previous authorization and
unchanged policy profile are mandatory. Historical signature verification grants
no current permission. This is a proof interoperability prerequisite: independent
durable policy adoption, witness admission and post-expiry session continuation
are not provided by this verifier alone. The separate
[original policy coordinator](POLICY_RENEWAL.md) connects the proof and record to
the registered original journal and existing session. Its required-witness path
uses a separately typed P transaction and fresh policy admission before work and
output. Its full-store driver covers expired targets and original-state recovery;
installed witness qualification and G/R composition after P retain their own
acceptance boundaries.

`policy_record_checks.py` reuses those exact native inputs to check bounded
Pending/Committed/ExpiredUncommitted metadata and sequential predecessor binding.
It preserves the first signatures on retries, refuses another pending operation,
and keeps historical completion separate from current permission. This record
model is also used by the local coordinator; the record tests themselves do not
establish durable or session behavior.
