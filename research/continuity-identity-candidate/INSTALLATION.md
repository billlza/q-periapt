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

## Lifetime and protocol integration

`DeviceService::stores` borrows the existing journal and archive engines together.
The caller can supply these directly to the existing connection `Actor`, inventory,
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
