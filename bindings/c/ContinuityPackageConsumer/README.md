# Installed Continuity C owner candidate

This is an unpublished `qpc-owner/1` consumer of the same Rust Continuity engine,
not an addition to product ABI 2 or a frozen C API. Its header is
[`qpc_owner.h`](qpc_owner.h). The collector builds it outside the checkout from a
Cargo-produced candidate archive and the same nine pinned SDK archives used by
the native Rust consumer. It must execute the C program and independently read
both peers' application records before reporting completion.

The library holds original `DeviceService`, signing, verified context, SDK policy
and TLS-key owners. It delegates every bootstrap/message/rekey transition to that
shared engine. It exposes no raw private-key/root getter and implements no second
ratchet, KDF or state machine. Independently retained account, device, policy and
directory pins remain separate from untrusted public bundle bytes.

## Scope and original configuration

The initial C caller opens an already provisioned local-profile installation on
macOS/Linux. It does not initialize a new lineage. Required-witness activation
returns the engine's refusal instead of falling back to local mode; the required
witness C adapter, cleanup/recovery API, other language
surfaces and product dependency/ABI admission remain unfinished.

The consumer configuration is the same private fixture layout used by the
archive's public Rust workload: original installation/journal/archive/SDK policy
databases, wrapping and signing files, independently retained policy/account/root/
roster/device-generation/directory pins, canonical bootstrap bundle and local TLS
credentials with an exact peer certificate/name. Public policies are actually
verified when opening. Incoming bundle contents never supply the trust pins or
choose the caller's requested prekey mode. This directory layout is qualification
input, not a frozen product provisioning or migration API.

Missing, corrupt, wrong-role, busy, revoked or expired state is an error. Opening
never provisions, repairs, rewinds or recreates files. An error cannot be treated
as a fresh empty installation. Fixing trusted configuration does not refund any
original operation ID or consumed key.

## Call and lifetime contract

Each loaded library has an explicit registry of up to 64 pending/active owners and
a 64-call admission budget taken before foreign input copies. Handles are
monotonic, process-local references; they never authorize hostile code in the same
address space. An operation obtains exclusive access without blocking another
caller. A conflicting operation or close returns `QPC_BUSY`. Close and cancellation
are exempt from call capacity, so a full budget cannot prevent draining it.

Cancellation is one-way for that owner. Cancel, join the active invocation, close,
then reopen the same original installation to reconcile retained work. A successful
close releases its owned state/leases and invalidates the handle. It neither rolls
back a commit nor acknowledges application consumption/loss accounting. No caller
pointer is retained past the call; inputs must remain valid and immutable while
the call runs, and outputs/diagnostics must be nonoverlapping, aligned and exclusive.

Each invocation returns its own caller-owned, bounded UTF-8 error record, including
an explicit truncation flag. There is no shared last-error buffer. SDK policy
denial, host-store uncertainty/activation failure, durable outcomes and transport
cancellation remain distinct; nested local causes are retained for diagnosis.
An unknown non-exhaustive upstream failure remains an error. No status code is a
universal retryability bit. Outputs other than the diagnostic record are meaningful
only when the return code is zero.

The client retains one original initiation ID or journal-issued message ID across
retries. `Committed`, peer `Acknowledged`, `ResolutionPending`, `DeliveryUnknown`
and `ReservationAbandoned` remain distinct. A successful TLS exchange with a
consumption prefix that does not yet include the ID returns `PrefixPending`, not
successful application consumption. Status queries grant no sending authority.

Client invocations retain the existing finite eight-attempt, 20-second total and
one-second connect bounds. Each owner can bind one explicit listener; repeated
listen is an error and close releases it. Server calls wait up to 20 seconds for
accept, then run the shared carrier's separate 20-second/eight-exchange budget.
Accept cancellation polls every 25 milliseconds subject to OS scheduling.
Filesystem and application callbacks remain synchronous/cooperative; cancellation
does not preempt an arbitrary kernel call, foreign callback or undo a commit.
AD is visible to the TLS endpoint and must not be treated as message-encrypted
private content. This boundary inherits the candidate's trusted-host and logical-
erasure limits; C in-process memory validity still depends on the caller contract.

## Application consumption

`qpc_owner_v1_serve` invokes the caller's synchronous callback only after the shared
engine authenticates and durably commits an inbox delivery. Session, message and
plaintext pointers are borrowed for that callback only; the context belongs to
the caller and remains live until serve returns. The callback must not unwind or
longjmp. Reentrant operations/close return Busy; cancellation remains available
with a separate diagnostic record.

Zero means the application effect and session/message deduplication record are
durable together. Nonzero, including an unknown external commit, returns
`QPC_APPLICATION` with the original callback status in diagnostic text. The inbox
remains unconsumed and a later retry can invoke the same callback/ID again. Hosts
must reconcile rather than repeat an external side effect blindly. A previously
consumed message instead returns `duplicate=1` without calling the application.
The native sender refuses to regenerate already acknowledged/retired ciphertext.
`qpc_owner_v1_serve_rekey` delegates the caller-selected session to the native
control endpoint; it does not mix application and control protocol identifiers.

## Qualification path

Run the existing installed package collector with `--with-c-consumer`:

```sh
sh artifact/python-run.sh artifact/continuity_package.py \
  --report /absolute/SDK-cohort/RUST_SDK_PACKAGE.json \
  --report-sha256 <verified-report-sha256> \
  --toolchain-root /absolute/rust-1.98.1-host-toolchain \
  --output target/continuity-installed-rust-c \
  --with-c-consumer
```

It first executes the original archive-shipped Rust trace. The C phase then builds
both Debug/Release libraries and native C executables, checks the exact eleven
exports and installed sibling-library lookup, and runs the shared archive's Rust
peer fixture. C controls the actual owner open/close, TLS bootstrap, message IDs,
delivery and rekey calls. The client trace covers:

- wrong original local-role metadata and failed-constructor capacity recovery;
- receiver exit after application fsync before ACK, followed by same-ID recovery;
- target-1 network rekey and actual post-rekey application delivery;
- cancellation before a reservation, and cancellation after actual TLS bytes reach
  a held socket, with concurrent close returning Busy;
- original-installation reopen, retained Committed status, exact resend/consumption
  and rejection after a durably signed SDK policy revocation.

The reverse trace pairs a native Rust client with a real C listener/callback. It
covers failure before application output, durable output followed by an unknown
callback result, and process exit after output fsync. Original-ID retries compare
the complete application record and create no replacement effect. A separate
duplicate case opens the original receiver through the public native recovery
consumer, checks the durable C output and calls `consume_message` before the sender
has received any ACK. The C receiver then accepts the retained original ciphertext
without invoking its callback. No journal file is edited or rewound to prepare
this case. The trace also checks reentrant Busy close, cancelled listener release,
refusal to resend acknowledged ciphertext, and a real network rekey followed by
application delivery. This qualifies that explicit native recovery transition;
it does not supply a C cleanup/recovery API.

The call-budget unit is also executed in each profile, including drain availability
at capacity. Each C trace selects one integration test; the other trace and two
included native fixture tests are already executed through the original Rust
collector/C phase, and each peer selects the correct nonempty helper test name.
No test is replaced by a receipt flag. The collector separately checks command logs,
application bytes, distinct epoch IDs, Cargo origins/lock, source/executable hashes
and absence of runtime loader overrides.

The C application and library must load from their private installed directory.
On macOS the library uses an explicit `@rpath` install name and the executable uses
`@loader_path`; on Linux it uses the fixed soname with `$ORIGIN`. A successful start
that still loads the build-tree library is rejected as installation evidence.

Private test runtime directories contain wrapping/signing keys and journal images;
do not publish them. Retain the collector's public JSON, command logs, hashes and
dependency/loader records. Results qualify only the executed source/platform and
these finite local-profile client/server scenarios. They are not a release, independent
implementation, cross-host connection, production C distribution or security proof.
