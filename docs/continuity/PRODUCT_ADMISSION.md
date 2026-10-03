# Continuity product admission boundary

Status: unpublished product integration. The initial adapter review used
`7997282c00342325c79d3c3d2b9d086e718df1e7`; subsequent native account-member
carrier work is noted below.
This records implementation work still required for 0.2.0. It is not a frozen
foreign ABI, a completed provisioning interface or permission to publish the
candidate packages. Product ABI major 2 and the existing KEM/KAT contracts remain
unchanged. The complete [release scope](RELEASE_0_2_SCOPE.md) still governs.

## What the installed consumers currently establish

The C adapter's legacy [`Owner`](../../bindings/c/ContinuityPackageConsumer/src/owner.rs)
contains one `DeviceService`, one device signer, one verified `BootstrapContext`,
one SDK policy store and one pair of exact application TLS credentials. Its
constructor reads the fixed private fixture layout, verifies the independently
retained pins and bundle, opens the existing installation and activates it. It
does not generate local enrollment material or provision an installation.
[`Request`](../../bindings/c/ContinuityPackageConsumer/src/opening.rs) copies the
bounded path, prekey mode and witness selection before activation; it does not
change this trust or storage boundary.

The additive C [`device owner`](../../bindings/c/ContinuityPackageConsumer/src/device.rs)
now opens an Active installation from independently retained local identity,
policy and private-owner configuration. It checks the controlled signer against
the verified local credential without deriving local trust from a peer bundle.
Fresh/restored peer children reuse that same service and witness owner. Parents
and children share the existing bounded registry; idle child disposal does not
take the service's network lock. Parent cancellation signals the active child and
fences later calls; successful parent close releases storage even with retained
idle children. Native errors keep their original reconciliation requirements.
Current C workloads exercise both roles, multiple handles for one context at each
endpoint, lifetime/capacity/identity refusal, real delivery recovery and required
witness profiles. The C account adapter now retains the exact parent and every
selected peer through one native `send_account_member` invocation. A separate
three-installation workload covers two distinct recipient devices, complete-set
refusal, original-message crash/retry, unary replay refusal, reordered targets and
aggregate cancellation/close behavior. Swift and Kotlin retain the same parent
and complete peer set through their typed owners. A separate native mutual-TLS
witness workload now completes both member deliveries after the first receiver
exits following application persistence, preserving the original batch/message
and idempotent readback. The same foreign endpoints now execute this trace and
four committed-witness-reply losses with three distinct devices in one original
signed roster. Both own-account and peer-account delivery refuse an incomplete
recipient set before reservation or application-network access. Broader delivery
faults, authority lifecycle and final product admission retain separate gates.

The [`C header`](../../bindings/c/ContinuityPackageConsumer/qpc_owner.h) exposes
pairwise operations, device/peer preparation, complete-account member delivery and restricted original-session
recovery. Swift and Kotlin now add `ContinuityDevice`, native parent retention,
typed account targets/status/results and complete-account member calls. Their
current installed-package and lifecycle evidence must bind the changed source.
Whole-account abandonment/report traversal, exact acknowledgement and retirement
now reuse the native transaction through all three bindings. Installed cohorts
exercise complete reports after SDK revocation and original-ID recovery under
local, signed-TCP and mutual-TLS witness profiles. The
[qualification ledger](../SDK_0_2_RELEASE_READINESS.md#latest-qualification-checkpoints)
binds each result to its source and carrier. Android/WASM Continuity adapters,
enrollment/renewal and the broader failure matrix remain required. These finite
own-account traces do not qualify the complete multi-device lifecycle.

| Required boundary | Existing implementation to reuse | Foreign integration still missing |
| --- | --- | --- |
| Explicit new lineage and exact restart | `JournalKey::provision/open`, role-specific signing-owner persistence, `DeviceInstallation::provision/open/prepare/activate`; C setup owner and Swift/Kotlin reference transfer delegate Creating/Active transitions with original configured inputs | Public key enrollment and independent trust-input contract, initial-intent/child creation faults and final product provisioning |
| Device-scoped protocol service | Native shared service, C device-parent/peer registry and Swift/Kotlin owners retain one journal and archive index under one installation lease; account calls pin the complete peer set | Android/WASM owners and source-bound qualification on every supported target |
| Account-wide local transaction | `DeviceJournal::send_account_message/resume_account_message`, `FanoutInput`, `FanoutTarget`, per-member outcomes; C/Swift/Kotlin complete-set admission, required-TLS-witness own/peer-account member delivery and cleanup | Broader delivery faults/concurrency, authority lifecycle and Android/WASM integration |
| Authority lifecycle | Signed roster checks and original installation/policy/witness bindings | Product enrollment, credential/policy/witness renewal, device replacement and independently authorized root replacement |
| Platform persistence | Native protected-file/redb engines and exact write-intent reconciliation | Android installation integration and a reviewed durable browser backend with the same commit/recovery contract |

The native fanout methods are in
[`durable/messages/fanout.rs`](../../research/continuity-identity-candidate/src/durable/messages/fanout.rs).
They take all required pairwise contexts and existing session IDs, derive the
recipient set from the installed roster, reserve every input together and commit
all chain/outbox changes before releasing any ciphertext. A binding must delegate
to this transaction. Looping over the pairwise `send` API would permit a partial
local commit and does not implement this contract. Opening a separate current C
owner for each peer also conflicts with the exclusive installation/journal leases.
Neither approach is an acceptable multi-device implementation.

The native TLS carrier now adds `send_account_member`, which takes the original
complete `FanoutInput` and an explicitly selected member session. It checks all
archive/recipient inputs, commits the whole local aggregate, and re-admits that
aggregate on every network retry. Unary replay of a live committed aggregate
member is fenced at the journal boundary. Foreign multi-peer owners must use this
shared carrier and preserve its distinct consumption, pending-resolution, unknown
delivery and retired-history outcomes. This native addition does not supply the
foreign context-registration or provisioning APIs described below.

The native `DeviceService::reopen_peer` entry now restores an established peer
under the already retained installation/journal/archive leases. Its opaque
`SessionReopenRequest` must match the original local owner, policy and witness
scope, session, role and archive, with current native identity/roster/budget/witness
checks. The returned `ReopenedPeer` retains public context ownership and its exact
session/role; it holds no additional storage lease. Closing the service still
closes protocol authority. Both same-account and peer-account tests restore two
contexts, refuse an omitted recipient without partial mutation, execute the
existing complete-roster transaction and replay its exact ciphertext after
original-installation restart. This is the native existing-session prerequisite;
the separate native fresh-admission entry is described next. C parent/child
handles and Swift/Kotlin parent/child owners now reuse both entries. Android/WASM
integration remains unimplemented.

`DeviceService::admit_peer` now admits a freshly and independently verified peer
context against the same active installation. It rechecks current advertisements,
credentials/runtime, local and known-peer rosters and the original witness. An
unknown account's initial verified roster is checked without installation or
advancement; the first actual bootstrap must repeat admission and persist that
roster with its operation reservation. `BootstrapPeer` owns public context and
role, without a session or durable grant. Both roles, later revocation, full roster
capacity, unchanged stores and policy/runtime closure during authenticated witness
queries are tested on current and minimum Rust. This supplies the native fresh
boundary. C registration and Swift/Kotlin owners now delegate to it; enrollment
and the remaining platform lifetimes retain separate obligations.

## Required owner and input separation

The adapter integration requires a device-scoped service owner, bounded
verified peer-context owners and separate setup/recovery authorities. These are
contract roles, not frozen class names or permission to expose raw native handles.

One service must retain the original installation, journal, archive index, local
signer and SDK policy runtime across all its peer contexts. Registering a peer
must verify its public bundle against independently supplied account/root/roster,
device-generation, protocol-policy, directory and requested-mode expectations.
The incoming bundle cannot supply those expectations. Registration must also
match the service's original local storage owner and policy binding; merely
matching a display name, account ID or certificate is insufficient. Reopening
reconstructs the same verified inputs and does not manufacture missing sessions.

Restart also needs separate existing-session and fresh-bootstrap admission.
The current C constructor re-verifies its fixture bootstrap bundle at the wall
clock; that path includes prekey-advertisement validity. The native message
engine deliberately distinguishes this from current session-identity checks.
The native `BootstrapBundle::request_reopen` and
`DeviceInstallation::reopen_session` path now reconstructs the original session
after public snapshot expiry, requiring its Active installation, exact message
state/role and cleanup archive, current installed rosters, credential/policy/runtime
authority, signed budget and fresh required witness. Native and public TLS
qualification is recorded in `research/continuity-identity-candidate/INSTALLATION.md`.
The C candidate now adds `qpc_owner_v1_prepare_reopen`; Swift/Kotlin expose
`prepareReopen` and `reopen` through their existing lifetime owners. The prepared
request copies an explicit session ID and preserves the original activation,
cancellation and deadline boundary. Local-profile development runs exercise all
three public foreign methods with genuinely expired advertisements at the current
foreign clock and real TLS/application readbacks. Separate C/Swift/Kotlin
development runs restore the responder's original session under required signed
TCP and mutual-TLS witnesses, refuse missing/wrong pins and bad signatures, cancel
partial replies and stalled handshakes, and reopen the same session. Public
readback verifies the selected session, command results and original witness/socket
records; the existing constructor workload also passes in all three languages.
The complete `a897ba54` Rust/C/Swift/Kotlin archive producer and independent
package/public-record readback now pass in both profiles. The later `caf5ab1e`
shared-service restoration and `469ccf31` fresh-admission additions have separate
targeted native evidence; their installed foreign packages have not been
requalified. These finite workloads do not cover
all witness-store rollback or credential/root lifecycle transitions. The existing
fresh constructor does not auto-fallback.
Historical material verification must not turn an old timestamp into renewed
operational authority or permit an expired selection to start a new bootstrap.

Operations must select an admitted context explicitly, preserve its current
policy/roster/witness checks, and keep both context and parent service alive until
the operation returns. Closing a peer context cannot acknowledge messages, erase
pending journal work or close an unrelated peer. Device-service close/cancellation
must have defined effects across all its active calls; call and owner capacity
must leave close/reconciliation available. This extension must reuse the native
state machine and its transaction boundaries rather than introducing a second
ratchet in any language binding.

Peer disposal needs its own lifetime boundary. An idle peer's destructor or
Cleaner must be able to retire that peer while an unrelated peer uses the device
service. Requiring the parent's long-running network lock for that cleanup could
return BUSY after the foreign object becomes unreachable and strand capacity.
Active account calls must retain every selected peer and the parent through the
native return, not merely copy their integer IDs. Parent close must invalidate
child operations while preserving already borrowed objects until their calls
drain. The adapter must test these races and budget reclamation explicitly; the
existing single-owner reachability-fence tests do not establish child ownership.

Witness I/O also needs the selected invocation's cancellation owner. The C
adapter now retains the independently configured witness endpoint and credentials,
but snapshots the active call's token and absolute deadline together for each
fresh native exchange. Sequential cancelled calls under one retained endpoint are
tested with distinct tokens and real stalled TCP/TLS sockets. Existing public
owners still reuse their original one-way token. A device parent must fence
new child calls after parent cancellation and signal its active child invocation;
single-peer cancellation must not poison another peer's future calls. This
transport separation is now used by the C parent/child registry. It does not
claim parallel journal operations or supply language-level lifetime owners.

An aggregate result must preserve every member's original session/message IDs and
the distinction between committed ciphertext, peer acknowledgement, pending
resolution, unknown delivery, retired history and abandoned reservation. Local
aggregate commit is not remote atomic application execution. A cancelled or failed
dispatch cannot authorize a replacement aggregate ID or exclude a required device.

## Provisioning is an explicit authority

The native [initialization contract](../../research/continuity-identity-candidate/INSTALLATION.md)
already distinguishes Creating from Active. A foreign setup owner must expose
that same distinction and retain the original public identities before any
dependent durable creation. Generating a key, accepting enrollment material,
preparing empty children, enrolling a required witness and activating a service
are distinct steps with distinct persisted outcomes.

The C candidate now has that separate setup owner: explicit create/resume,
original status/identity, initial storage preparation and activation into the same
device-parent handle. It reuses the original device authority loader and native
installation transactions. Local and required-witness traces exercise actual C
processes, cancellation while a signed reply is held, error cleanup and original
TCP/TLS activation. Its public subject/genesis outputs authorize no witness
enrollment by themselves. Current inputs are still the independently prepared
protected configuration described above; this is not yet a public key enrollment
or credential-issuance interface.

Swift/Kotlin now expose the same explicit setup operations and typed original
journal/phase/genesis values. Successful activation moves the existing native
owning reference into a device wrapper; it creates no second native destructor or
Cleaner. Closing the old setup is harmless after transfer, including Kotlin `use`;
other old-setup methods refuse Closed. Reference cells refuse concurrent transfer
or close while activation runs and permit cancellation without holding a monitor
across native work. A cancellation already admitted may race completion and affect
the successor, so it must be joined. Failed activation retains only the original
setup reference for cleanup and cannot justify new provisioning.

Actual extracted Swift and Maven consumers exercise local and required-witness
setup. They release/collect the old setup, use the successor, retain original
creation identity across restart, and check held-reply cancellation and TCP/TLS
activation. The local activation/close process-cut matrix now calibrates actual
installation syncs in installed C/Swift/Kotlin consumers and interrupts before and
after every observed sync. It distinguishes complete replies already observed
from unknown results, and requires unknown results to cover both Creating and
Active. Independent native readback preserves original journal identity, the next
account position, absent account state and empty archives. Creating rejects ordinary
device access; original resume reconciles either phase and Active cannot recreate
children. The additional returned-EIO workload binds each real sync error to
opening, activation or close using consumer phase receipts. Opening failure (204)
and uncertain activation commit (207) consume operational eligibility; only original
resume resolves the persisted phase. Close-phase metadata sync errors follow a
successful activation commit and cannot be used to relabel an activation error.
The required-witness workload keeps the original authenticated witness alive
across those same process cuts and returned errors. A native controller enrolls
the original prepared genesis and observes the original anchored journal before
the call, after the fault and after reconciliation. The foreign call and recovery
explicitly select signed TCP or mutual TLS; missing witness configuration still
refuses 216. TLS phase counters must show encrypted admissions and no plaintext
fallback during foreign operations. Independent public replay binds the original
subject, genesis image, complete signed-query transcript, native observations,
phase receipts and exact client/controller exits. Native endpoints authenticate
the exchanges; replay is not a second signature implementation. Only selected
public pins, certificates and logs are exported, never TLS private keys.

Complete source-bound archives, initial intent/child preparation faults, witness
process crashes and each supported device remain separate qualifications.
Process interruption and returned EIO are not physical power loss.

An open error must never select provisioning. Existing, partial or conflicting
key/configuration/child files remain errors. Creating may resume only the original
creation intent; Active may only reopen original children. Unknown activation
results must be reconciled against the original configuration even when the call
returned no owner. Required-witness enrollment uses the original committed genesis
and independently selected witness; a timeout cannot select local-only protection.

Secret inputs must remain controlled owners or explicitly reviewed transfer APIs.
The test directory's raw TLS-key file and externally prepared signing/prekey files
are not by themselves a complete public enrollment contract. Account-root issuance,
device credential issuance and local device operation remain different authorities.
The product must define renewal/replacement, including retained sessions and loss
accounting, before accepting a new credential or policy into an Active lineage.

## Platform and release admission

JDK 25 FFM qualification does not exercise Android ART/JNI. The Android adapter
needs its own reference, callback, exception, cancellation and unloading/lifetime
contract over the same engine, then actual extracted AAR/native-library execution.
It must not infer durable Continuity support from the existing in-memory SDK policy
instrumentation workload.

The product WASM entry point currently supplies controlled primitive owners, not
the native filesystem/TCP service. Durable browser admission must specify actual
atomic persistence, revision exclusion, uncertain commits, restart, quota failure,
cancellation and original witness reconciliation before returning protocol output.
A volatile in-memory replacement or successful wasm compilation cannot satisfy
that boundary. Browser transport and persistence capabilities must be explicitly
reported; unavailable required capabilities must fail without changing the signed
security profile. A storage implementation and its target support remain design
and execution obligations, not claims made by this review.

Before admitting the candidate into the release graph, each supported package
must exercise fresh setup from its public entry point, exact restart, at least two
peer contexts in one device service, complete-roster fanout, required-recipient
failure, roster/update races and aggregate unknown outcomes. The same packages must
exercise revoked/expired operational authority with original restricted recovery.
Current-device, cross-host and independent-endpoint evidence remain separate.

Protocol/domain and durable-format freeze, explicit candidate-state disposition,
package/version/export tables, installer failure behavior and maintenance policy
must move together. Renaming a candidate package or retaining a successful pairwise
test report cannot supply the missing product contracts above.
