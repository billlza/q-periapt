# Native service initialization and ownership

`DeviceInstallation` is the independent, exclusively locked initialization record
for one configured device lineage. `DeviceService` holds that lease with the
existing `DeviceJournal` and `SessionArchiveStore` for its complete lifetime. This
unpublished native layer supplies an initialization contract for subsequent SDK
binding integration; it neither publishes a language API nor installs account trust.

## Explicit provisioning and restart

The host first provisions its immutable `JournalKey` once and retains its protected
file independently of journal backups. `InstallationPaths::new` requires three
distinct normalized absolute UTF-8 paths: configuration, journal and archive index.
Their parent directories must already satisfy the shared private-directory policy.
Provisioning is an explicit first-install decision. An error opening configuration,
a missing file or a failed invocation is never authorization to provision again.

`DeviceInstallation::provision(paths, &key, device, policy, now)` checks current
device/policy admission and refuses existing journal/index paths. It generates and
durably retains the fresh public journal identity before creating either child.
The exact original wrapping-key commitment, device storage owner, signed policy
checkpoint, required-witness binding and all three configured paths are retained
in the same record. The key is not stored in this database or exported by the owner.
The private-file provider durably reserves the filename in its pinned parent before
the initializer runs; redb uses the existing immediate two-phase transaction.

For restart use `DeviceInstallation::open` with the original paths, key, independently
verified device and exact policy. This reads existing trusted configuration, rather
than choosing an expected journal ID from the incoming journal. Missing, malformed,
wrong-key/scope/path and busy configuration fail explicitly. A closed or expired
policy cannot obtain a service. Policy renewal, credential replacement and relocation
require separate lifecycle operations; this API never silently changes a binding.

| Retained phase | Preparation | Activation |
| --- | --- | --- |
| `Creating` | Create missing initial children or read back their exact empty genesis; return no operating journal | Require both existing children and original genesis; commit `Active` before releasing the service |
| `Active` | Refuse, including when a child is missing | Open only existing original children; never create replacements |

`prepare` consumes a freshly reopened original key owner. It verifies an existing
journal's exact identity, key, protection and empty revision-1 roster state, or
exclusively provisions that genesis under the already committed creation intent.
Its index must have the same identity and be empty. Partial, advanced or conflicting
files remain errors and are not overwritten or deleted. Repeating successful
preparation returns the same genesis. `Creating` cannot have released operational
state through this interface, so a genuinely absent initial child can be created;
once `Active` is durable that permission is permanently gone.

Local-only preparation returns `InstallationPreparation::Local`. Required-witness
preparation returns only `RequiresEnrollment(original genesis)`. The host must enroll
that exact genesis independently using the existing witness enrollment contract.
No network bytes install a witness and no preparation method enrolls it implicitly.

`activate` consumes the installation owner and original key. It opens the original
journal/index, freshly verifies the required witness, and checks genesis when the
configuration is still `Creating`. It then commits and reads back `Active` before
returning `DeviceService`. It rechecks policy and original witness after that commit.
A missing witness is `AnchorRequired`, not local-only fallback. An already active
restart also requires fresh witness admission/release; cached configuration is not
evidence of a current journal head.

Any activation failure returns no service and drops the journal, index and
configuration leases. A commit or witness error may leave `Active` durable even
though the caller received no service. Reopen the original configuration to observe
the actual phase and retry the same identity; do not infer absence from the error.
A crash before the initial configuration transaction commits can leave a partial
configuration file. It remains refused without implicit repair. No journal has been
created at that point, but this does not turn an arbitrary open error into first use.

## Existing sessions after public snapshot expiry

A prekey advertisement's lifetime does not set an established session's lifetime.
Fresh bootstrap still uses `BootstrapBundle::verify` at current trusted time.
For an existing session use the explicit two-stage path:

1. `bundle.request_reopen(policy, independent_requirements, local_role, session, now)`
   authenticates the original snapshot into an opaque `SessionReopenRequest`.
2. `DeviceInstallation::reopen_session(paths, key, request, now, anchor)` admits it
   against the original Active installation and returns `ReopenedSession`.
3. `into_parts()` transfers the same `DeviceService` and `Arc<BootstrapContext>`
   to the existing protocol engines. `session_id()` and `role()` identify the
   checked session; no private keys are exported.

The request supplies no operational context. It derives a candidate historical
instant from the maximum start of the signed policy, both credential/roster
snapshots and all supplied baseline/selected leaves. It then invokes the complete
ordinary bundle verifier at that instant. Every signature, exact independent pin,
identity, membership proof, interval and manifest-containment check still applies.
A future or non-overlapping snapshot is refused. Time hints are not authority.
Current policy, runtime and both device credential lifetimes are also checked.

The installation step never creates files or activates Creating state. It matches
original paths, wrapping key, local device owner, policy and witness binding, opens
existing children, requires the exact session closure archive, and checks the
persisted message session's context, local role and signed send budget. Current
journal rosters and the required independent witness remain authoritative. The
old snapshot is not installed as a newer roster. Closing/closed sessions, missing
sessions or archives, revoked membership, expired current credentials/policy and
closed owners return no operating service. Required witness failures never fall
back to local-only. All acquired owners are dropped on refusal.

This reconstructs the original context commitment; reissuing a bundle against a
new roster would change that commitment and cannot substitute for restoration.
Subsequent operations still perform their current admission checks. In particular,
a restored context with expired advertisement cannot start a fresh bootstrap.
Credential/policy renewal and cross-installation migration remain separate work.
`InstallationRecovery` retains its distinct cleanup-only authority.

The native regression includes expiry, durable roster updates/revocation, both
roles, exact original outbox replay, duplicate owner refusal, missing configuration/
children/archive, closed owner, Creating and closing-state refusal. Required-witness
checks inject loss before and after each actual exchange. The public consumer test
`reopen::public_session_reopen_after_expiry_reconciles_unknown_commit_over_real_tls`
uses independent receiver processes and real TLS: an application commit followed
by process exit, explicit protocol-clock advancement past advertisement expiry,
restoration of both peers, exact retry and durable acknowledgement with two
independent application-file readbacks. Only the protocol clock is injected; no
wall-clock change or long-lived deployment is claimed by that test. C, Swift and
Kotlin gain explicit restoration owners in `65c0b5c0`; their real-current-clock
expiry and separate required-witness constructor traces complete both installed
package profiles at `a897ba54`. The later shared-service addition below has its
own targeted native evidence and still requires foreign owner integration.

## Lifetime and protocol integration

For a freshly verified context, `service.admit_peer(context, role, now)` checks
the original active installation's local owner and policy/witness scope, current
advertisement/credential/runtime validity, current local and known-peer rosters,
and the original witness. An unknown remote account is checked against its
independently verified initial snapshot and remaining roster capacity. This call
does not install or advance any roster, reserve a prekey/operation, create a
session or acquire another storage lease. `BootstrapPeer` retains only the public
context owner and checked local role. Actual bootstrap repeats admission and
persists a new account roster with its first operation reservation. Retaining an
earlier descriptor cannot bypass a subsequent durable revocation.

For an already active service, `service.reopen_peer(request, now)` restores an
additional established peer without reopening those leases. `ReopenedPeer`
retains the exact session ID, local role and verified context owner. The request
must match the service's original local owner, signed-policy digest and witness
profile; current identity/roster/budget/witness admission and the original archive
remain mandatory. The original key commitment is retained privately in memory to
check that same installation scope, without exporting key bytes or changing the
persisted scope format. The whole-installation `reopen_session` entry uses this
same peer-admission path.

A peer descriptor is not durable operation authority and cannot reopen a closed
service. Protocol calls still recheck current authority. Dropping a descriptor
does not close the service or retire a session, and descriptors do not hold an
independent storage lease after service close. Fresh admission and existing-session
restoration remain distinct: expired advertisements cannot be admitted for a new
bootstrap. Foreign parent/child ownership remains separate integration work.

At `469ccf31`, current Rust 1.98.1 Debug and minimum Rust 1.90.0 Release each pass
30 installation tests, six roster tests and the two-peer account transaction test.
Admission preserves configuration/journal/archive bytes, unknown-roster absence
and full-capacity refusal. Tests retain loss before/after each of the two original
witness exchanges; closing policy or runtime after either authenticated reply
also returns no descriptor. All three public TLS harness tests, strict Clippy and
no-TLS compilation pass. The full 342-test suite and fresh foreign packages were
not rerun for this addition.

At `caf5ab1e`, Rust 1.98.1 Debug and Rust 1.90.0 Release each pass all 25
installation tests plus a two-peer account transaction test covering both local
and remote account recipient sets, omitted-recipient refusal without mutation,
complete aggregate delivery and exact replay after restart. The public TLS
workload passes all three harness tests; strict Clippy and no-TLS compilation
pass. These are targeted checks; the complete 336-test library suite and fresh
foreign packages were not rerun for this addition.

`DeviceService::stores` borrows the existing journal and archive engines together.
The caller can supply both engines to the existing connection `Actor`, inventory,
message or rekey methods. No duplicate protocol/transport implementation or private
key getter is introduced. `close` and Rust drop release the child owners before the
installation lease. A failed lower-level journal operation retains its existing
close/reconciliation behavior; restart explicitly closes the service and reopens
the same installation. Methods on a closed service return `Closed`.

The service does not own the host's application transactions, signing owner,
trusted clock or independently verified policy/roster objects. Their existing
lifetimes and operation-time checks still apply. Filesystem calls are synchronous;
this initialization API makes no preemptive filesystem cancellation promise.
Network deadlines/cancellation remain in the existing connection contract.

## Public consumer and original-service recovery

After `BootstrapBundle::verify`, `BootstrapContext::device(role)` borrows the
already verified device, and `policy()` borrows the original policy owner. These
projections let an external Rust consumer open its installation without repeating
identity decoding or reconstructing permission. They do not refresh roster or
policy state, select a local role, or authorize an operation. Installation and
journal methods still perform their ordinary binding and current admission checks.
Closing that policy is visible through the same context. The shared host-store
`PrivateFileError` implements `Display` and `std::error::Error`, so normal error
propagation retains its type; file admission and failure semantics are unchanged.

`tests/owned_connection.rs` is a separate consumer crate using only public APIs.
It explicitly provisions signed trust, persistent SDK policy stores and both
installations, then opens each original installation with its own persisted
signing key. Receiver processes load only their local private signer. The test
performs actual TLS bootstrap, restart, bidirectional application delivery and,
with `control-tls`, a network rekey. Its application sink durably writes a record
containing session, message ID and plaintext. A receiver exits with status 77
after that fsync and before consumption acknowledgement. The sender observes an
error and retains `Committed`; reopening the original installation and resending
the exact ID/input obtains `Acknowledged` with matching application readbacks.
This is a controlled process-loss case, not a physical power-loss experiment.

Two separate bounded contenders check all eight SDK-policy/installation/journal/
archive leases. Wrong local-role metadata fails installation binding, pre-cancelled
delivery retains `Absent`, and a signed durable SDK policy update disables the
current suite, closes cached runtime admission and prevents stale-policy restart.
The policy projection is checked for original-owner identity and closed-state
propagation. These checks exercise real stores and sockets without private APIs.

Run from the repository root with the configured Rust toolchain:

```sh
cargo test --manifest-path research/continuity-identity-candidate/Cargo.toml \
  --locked --all-features --test owned_connection -- --nocapture
```

The feature-specific command `--no-default-features --features connection-tls`
executes the same connection/recovery path with zero network rekeys. Its receipt
reports that difference explicitly. The helper process test is included in the
two-test integration count; it is not a second independent connection scenario.
By default temporary state is removed. `QPERIAPT_PUBLIC_SERVICE_EVIDENCE` may name
a fresh absolute directory under an existing private parent to retain raw state.
That directory contains test private keys and must not be published. Only the
separate `public-result.json`, validated application hashes and bounded logs may
be used for a sanitized receipt. This reference is still an unpublished native,
same-host, same-implementation execution; installed bindings, cross-host peers
and independent implementations require their own qualification.

## Recovery after operational authority expires

`InstallationRecovery::open(paths, original_key)` opens only existing Active
configuration and its existing archive index. It verifies the original key
commitment and normalized path binding without reconstructing expired device or
policy objects. It holds the configuration/index leases and wrapping key while
the caller enumerates bounded `session_ids`. Those IDs are discovery hints;
journal existence, archive authentication and witness admission are still pending.
Creating, missing or corrupt configuration and invalid indices are refused.

`open_session(id, anchor)` consumes this discovery owner. It authenticates the
indexed archive, matches the original installation journal/device owner and
protection, and opens the existing `SessionClosureJournal`. Required protection
also matches the retained signed-policy digest and original witness binding.
An explicit `open_session_from_archive` accepts separately retained original
archive bytes when the index row is lost; it does not implicitly restore or
overwrite the index. Missing journals, changed archive/key/scope and unavailable,
wrong or refusing witnesses return errors and release the attempted owners.
The original required-witness signer remains necessary, including after policy
closure. Expired witness enrollment does not become permission to operate locally.

`InstalledSessionRecovery::stores` exposes only the existing cleanup journal and
archive index, with both child leases retained before the installation lease is
released. It grants no message, bootstrap, rekey or initialization operations.
Freeze, complete host loss accounting, exact report acknowledgement, explicit
catalogue restoration and closed-row retirement keep their existing semantics.
Closing this owner does not acknowledge a report, refund capacity or recreate
state. Local-only recovery still relies on trusted configuration and retains its
original lack of whole-state rollback detection. This API is a native recovery
entry point; installed language adapters and authority renewal remain separate.

The public consumer now closes its persisted SDK policy, freezes cleanup in a
fresh process, writes the complete metadata-only report, and exits before local
acknowledgement. A second process reconciles that exact report and retires its
index row. A third process authenticates retained archive bytes and independently
confirms the original journal's terminal report. A competing process checks all
three recovery leases. Native tests also retain an actual unconfirmed outbox in
the loss report, exercise original catalogue restoration, and refuse wrong key,
changed configuration, Creating/missing storage and witness request/reply loss.

## Encoding and trust boundary

The configuration contains exactly one `continuity_installation_v1` table and one
`installation` row. Its canonical binding is `QPCINS01`, journal ID, storage owner,
policy digest, domain-separated wrapping-key commitment and configured-path digest
(each 32 bytes), followed by the anchor mode (0, or 1 and the 32-byte witness binding).
The final byte is phase 1 (`Creating`) or 2 (`Active`). All expected bindings are
reconstructed and compared on open. Extra tables/rows, unknown phases, lengths or
bindings are rejected. It has no implicit migration. Candidate journal v21, archive
QPCSCA01/QPCSIX01, network formats and published SDK ABI are unchanged.

This configuration is trusted host state outside journal backups, not an
anti-rollback witness. Do not restore its old `Creating` phase together with an old
journal snapshot or delete it to recover a missing lineage. An older `Creating`
record paired with an advanced journal is refused, but simultaneous rollback of
all trusted state is not detectable in the local-only profile. Required-witness
journal checks retain their original external assumptions. The same trusted host
must select one authoritative configuration path; arbitrary alternate paths or
direct lower-level provisioning cannot establish global device uniqueness.

Native tests use actual files, signed witness replies, journal outboxes, processes
and storage barriers. They cover durable identity before children, exact outbox
restart, active-file loss without regeneration, invalid scope/schema, partial
configuration, six creation/activation process cuts, bounded competing processes,
all measured before/after activation sync failures and every required-witness
request/reply loss on both creation and active restart. These are process-loss and
I/O-fault tests, not physical power-loss, installed package, cross-language or device
qualification. Those release obligations remain open.

The source-bound native Debug/Release suites each pass 277 tests, zero failed or
ignored; runner times are 832.271/826.724 seconds under overlapping load, not a
performance comparison. Both Rust 1.90/1.98.1 strict Clippy, six feature variants,
warning-strict docs/formatting and 95 clean source contracts pass. Frozen source
and exact test executables are retained in the installation cohort referenced by
the release ledger. Later evidence-only document changes retain all Rust bytes.
