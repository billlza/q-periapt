# SDK internal implementation review

This record tracks internal code, security-boundary and maintainability checks
for the 0.2.0 work. The inspected product source is
`0e2a670b8e63584632190d50b308e2d8e4eabf7a`; ABI major remains 2. Each conclusion
below names the implementation boundary it covers. Remaining review items are
kept separate from completed observations.

## Owned runtime and C boundary

| Contract | Inspected implementation | Observation |
| --- | --- | --- |
| Runtime configuration must originate from signature/root/state verification | `crates/q-periapt-sdk/src/lib.rs`, `Runtime::from_signed_policy` | Lengths and limits are checked before signed monotonic policy loading. Only the explicitly authenticated absence of a supported suite becomes a disabled runtime; other resolution errors return `PolicyDenied`. No SDK runtime constructor takes a serialized 40-byte decision. |
| Closing between admission checks must release its budget | `State::begin_control`, `Operation::drop`, `Runtime::generate_with` | The operation lease is constructed immediately after reservation and before the second open check. Error/unwind releases the counter. The key lease is likewise established before entropy acquisition and backend preparation. |
| Handles must not wrap or expose unpublished owners | `crates/q-periapt-ffi/src/sdk/registry.rs`, `Registry::reserve`, `Reservation::publish` | IDs use checked increment. Reserved slots remain pending; publication rechecks the live runtime parent. A dropped unpublished reservation removes only its matching pending ID and drops the object after releasing the table lock. |
| Poisoned state must not become usable state | `Object::close`, `Registry::lock`, `Reservation::drop` | Normal acquisition returns `ERR_INTERNAL` on poison. Recovery of the inner value is confined to disposal; the poison flag remains. Key/secret cleanup reports the internal error. |
| Failure must not publish partial C outputs | `crates/q-periapt-ffi/src/sdk.rs`, `execute_with_admission`, `OutputGuard` | Bounds/null/alias checks precede initialization. The output guard commits only on `Ok`; operation errors and caught panics leave its cleanup armed. Public C pointer validity remains the caller's memory contract. |
| Policy activation must have one winner and remain possible at capacity | `crates/q-periapt-sdk/src/policy_update.rs`, `PolicyUpdate::activate_after_persist`; registry activation | Preparation verifies a strictly newer policy using the pinned root and trusted state. Activation uses the previous runtime's atomic close as its admission boundary, with resources reserved before persistence. The raw runtime API's documented host compare/persist obligation is distinct from activation itself. |

Relevant regression names in `crates/q-periapt-ffi/src/sdk/tests.rs` include
`bounds_aliases_and_panics_do_not_publish_success_fragments`,
`unpublished_reservations_are_bounded_and_revocation_prevents_late_publication`,
and `purpose_key_handles_enforce_shapes_type_separation_and_runtime_revocation`.
The Apple workload also exercises actual owner calls, pairwise named-purpose
separation, signed revocation, quota recovery, pre-cancellation and concurrent
asynchronous decapsulation. Its policy-update slot is in-memory; durable-store
review uses the separate host-store implementation and its process tests.

## Durable host policy storage

`crates/q-periapt-host-store/src/policy.rs` opens a descriptor-backed
`FileBackend`, holds its exclusive lifetime lock, and re-reads the same inode's
metadata after lock acquisition. `replace_policy` compares the expected signed
state inside the write transaction, commits policy/signature/root/state together
with immediate durability and two-phase commit, then activates the replacement.
Storage, uncertain commit and post-commit activation failures close the store;
dropping its active state closes retained runtime aliases. `open_configured`
reconciles the application's configured signed policy before returning a runtime.

`filesystem.rs` uses descriptor-relative private-file admission. An unclean redb
image without the two-phase flag is refused before recovery. This is tied to the
documented redb 2.6 format and does not provide a hardware rollback counter.
The existing 15 host-store tests pass on macOS with
`cargo test --locked --offline -p q-periapt-host-store`. They include real commit
failure, persisted activation failure, a competing process lock and a committed
revocation surviving a child process exit that bypasses Rust cleanup. These
observations cover the implemented macOS/Linux store's checked paths; Android
and iOS durable application storage are separate integration responsibilities.

The following product paths were inspected at `99fb979`. Their bytes match
`0e2a670`; the runtime-harness changes have separate validation. These findings
cover the named boundaries and do not imply unrun target execution.

## Foreign asynchronous ownership

- Swift `runOwnedOperation` checks cancellation before dispatch, before native
  work and after its result. The parent awaits the detached worker. Captured
  owners remain retained until the call finishes; cancellation discards result
  wrappers, whose `OwnedHandle.deinit` closes the native handle. `OwnedHandle.use`
  extends both wrapper and parent lifetime through native calls.
- JVM `submitOwned` uses the atomic `CompletableFuture.complete` result. If the
  consumer has already cancelled, the worker closes its undelivered owner.
  `finally` cleans the captured input; failures that cannot be delivered to a
  cancelled future are logged. Native work is not interrupted.
- Android `OwnedTask` serializes `cancel` and result publication, forces
  `cancel(false)` for native work, closes an undelivered result and logs disposal
  failure. Its one-winner `started` guard prevents repeated `run` calls from
  erasing input still used by the admitted worker. The supplied executor retains
  responsibility for bounded queues and execution. Input snapshots are bounded
  before cloning.
- The existing tests `testCancellationDiscardsCompletedNativeOwnerAndReturnsQuota`
  and `cancellationDisposesUndeliveredNativeOwnerAndReturnsQuota` stop workers
  after native generation and before publication; they check cancellation and
  quota recovery. They do not claim forced interruption inside a primitive.

## Transcript and secret storage

- `combine_policy_bound` feeds the same ordered, eight-byte big-endian
  length-prefixed fields as `encode_policy_bound_context`. It emits the outer
  context length before the domain, policy digest and caller context, with
  checked bounded lengths. No field is replaced by a shorter digest.
- `StreamingSha3_256Xof` uses the pinned RustCrypto core and padding. The wrapper
  wipes the complete residual block on drop; `sha3` has its `zeroize` feature.
  Compiler and provider internal copies remain outside owner-level erasure.
- `PreparedMlKem768Key` borrows the paired public field at the fixed expanded-key
  offset, checks generated public output, uses checked/PCT expert import and
  retains native expanded-key validation for every decapsulation.
- Purpose derivation binds the suite, ContextBound profile, trusted policy state,
  root digest, global direction/purpose, protocol label, context and output
  length. The returned PRK is explicitly wiped; HMAC/SHA-256 zeroize features
  are enabled. Export remains an explicit caller-owned copy.

## Reference connection authentication and failure

- `standard::provider` offers only TLS 1.3 suites and X25519MLKEM768. Client and
  server require trusted certificates, disable resumption/early data, and create
  fresh handshakes. The reference engine additionally checks full handshake,
  negotiated group, ALPN and exact peer certificate digest.
- Before application readiness, both roles check policy/root state, application
  context and ordered peer identities against a TLS exporter binding. The
  exporter value uses constant-time equality; confirmation frame types are
  role-specific. The stored binding is dropped after confirmation.
- `Live::check` enforces the absolute current phase deadline and runtime state.
  `Connection::finish` closes on wire/protocol/state failures; failed encrypted
  output is cleared. Framing rejects malformed lengths/sequence/replayed
  confirmations. EOF cannot become an empty successful message.
- Existing connection tests cover missing confirmation/ALPN, cross-session
  exporter replay, exact leaf pinning, fragmentation/reconnect, independent
  policy/context mismatches, capacity, revocation, deadlines and EOF. Actual
  Swift/macOS-to-Rust/Linux execution still requires its selected endpoints.

## Product WASM boundary

The product is `q-periapt-sdk-wasm`; the separate `q-periapt-wasm` crate retains
its existing expert/KAT contract. The product constructor checks original JS
numeric limit types and bounded `Uint8Array` lengths before copying into linear
memory, then calls the shared signed-policy constructor. The SDK enables the
`getrandom` WASM JS backend; entropy failure remains an error. The default web
entry point exports owner APIs, while private transfer has an explicit expert
entry point. Initialization retains a rejected promise after failure. Host policy
persistence, same-realm trust and exported copies retain their documented scope.

## Release cohort and installation

The existing SDK package classifier validates twelve publishable Rust crates
and their production dependency order. Inspecting actual offline Cargo metadata
confirms that the historical ten-crate 0.1.5 uploader lacks `q-periapt-sdk` and
`q-periapt-host-store`; its old order also places `q-periapt-ffi` before its new
`q-periapt-rustls` dependency. That uploader must retain its historical contract.

The SDK package producer already has the required dependency-safe order:

1. `q-periapt-mlkem-native-sys`
2. `q-periapt-core`
3. `q-periapt-kem`
4. `q-periapt-sig`
5. `q-periapt-backends`
6. `q-periapt-policy`
7. `q-periapt-sdk`
8. `q-periapt-host-store`
9. `q-periapt-rustls`
10. `q-periapt-ffi`
11. `q-periapt-wasm`
12. `q-periapt-cli`

The active SDK producers and consumers now select `0.2.0` and `sdk-020`.
This coordinated transition includes exact internal dependencies, archive names,
installed consumers, C contract metadata and the native CBOM profile. Its
source/package qualification and release procedure remain required; the frozen
0.1.5 publisher order cannot publish the twelve-crate cohort.

The SDK now has a separate coordinator and receipt schema for this order.
It shares the existing persistent lock, intent/outcome journal, exact API+sparse
observations and explicit unknown-outcome retry mechanism. Inspection covers
source/report/archive resampling after lock acquisition, complete source-input
maps, exact internal dependency pins and rejection of mixed release receipts.
Source `57334d4` passes 2,311 complete artifact tests and its real hosted package
consumer and coordinator dry-run. No registry upload is part of that check.

The uploader's directory transition has a retained real-filesystem counterexample:
replacing the selected parent previously redirected the output. The repair pins
the private directory descriptor, uses the shared no-replace writer and checks
bytes plus inode before enabling execution. At `a07789f`, CLI output authority
comes from a closed profile and the selected report digest. Its 214 affected
tests pass, the real twelve-crate hosted uploader is materialized, and the
Python scan removes the eleven preceding path warnings without new alerts.
The remaining 41 IDs/rules and thirteen location-file blobs match `10de0c7`;
these existing dispositions retain their prior scope.

## Python input-flow assessment and output admission (2026-09-29)

CodeQL check `109631309472` on `fb98db1c` reports 36 Python path/command
annotations. The retained Python SARIF is analysis `1862706844`, merge
`b1ab7aba235cc8feb808706fb786fea62d43d96e`. All thirteen files on those
reported source-to-sink flows have identical Git blobs at `a9fcf139`; this
comparison does not equate all branch alerts or languages with this snapshot.
The earlier internal dispositions above already identified operator-controlled
harness inputs. The current assessment records the actual flows rather than
relying only on stable alert counts.

| Alert IDs | Reported boundary | Source-specific assessment |
| --- | --- | --- |
| 467, 468 | Android/JVM JDK path checks | Local `JAVA_HOME` read from the invoking environment; no package or network value is the reported source. These commands require a caller-selected trusted JDK. |
| 439 | Shared process launch | Reported callers select JDK/Gradle through environment/CLI and LLVM tooling through the Apple CLI. The helper uses an argv sequence and `shell=False`; it bounds execution, not the caller's authority to select an executable. It must not be exposed as a service accepting untrusted commands. |
| 485–492 | Reference connection files | Local CLI selects binaries and output; `run_boundary` resolves and exclusively creates the output, freezes selected executables and records hashes. Peer protocol messages do not select these paths. This does not sandbox the selected binaries. |
| 493–501 | Installed connection files/output | Local CLI selects pinned archives, report, cache and output. Archive intake uses the existing strict extractor; the output destination is resolved and confined under `target`. Current helper behavior is exercised below. |
| 471, 482, 502–506 | OpenSSL/reference file paths | Sources are local connection CLI arguments. The harness uses resolved/exclusive output and fixed child names; executable identity reads use the bounded no-follow snapshot reader. The operator selects the root, not an HTTP or protocol field. |
| 476, 483 | OpenSSL/reference processes | Fixed command structures contain explicitly selected local tools and fixture paths. Calls use argument lists without a shell. CLI tool selection remains trusted configuration; an arbitrary tool path is intentionally not treated as authenticated package data. |
| 477, 478 | JNI contract compiler inspection | Test-only `JAVA_HOME` selects `javac`/`javap`; fixed flags, fixed source discovery and a disposable compilation directory. It is not a remotely invocable compile API. |
| 472 | Third-party license cleanup | CLI selects the package root. Cleanup names are fixed `THIRD_PARTY/rust[.staging]`; package name/version and license basenames are validated before construction. Cleanup still requires exclusive control of that selected workspace. |
| 473, 474 | WASM runtime identity reads | CLI explicitly selects Node and npm; resolved paths are read through bounded no-follow snapshots and compared after consumption. Archive contents do not select those executables in the reported flow. |
| 484 | Windows static-copy output | Local CLI selects the output; exclusive `xb` creation prevents replacing an existing final entry. This is an operator filesystem operation, not a confined service endpoint. |
| 581 | SPQR variant inventory | Local experiment CLI selects the tree; recorded entries have symlink rejection, bounded snapshots/count/size and retained preparation identity. This is isolated research tooling, not a product receive path. |

These are internal dispositions of the named reported flows under a trusted
local-operator/workspace model, not proof that every caller of those helpers is
safe. No alert has been suppressed or dismissed. They do not assess the whole
223-result Python analysis, later Rust results, missing configurations or the
latest source. Hosted aggregate status and complete release review remain open.

The same inspection found a real adjacent Android output-admission defect:
`Path.absolute()` followed by lexical `is_relative_to(ROOT / "target")` admitted
both `target/../escaped` and `target/redirect/escaped` when `redirect` was a
symlink to an outside directory. Executing the original admission and mkdir
nodes in disposable directories writes actual marker bytes outside the intended
tree. This is an operator-supplied-path confinement violation; the experiment
does not claim a remote exploit or execute a complete Android package build.

Android packaging and the installed connection now share
`evidence_io.fresh_output_directory`. It returns the actual resolved destination,
requires a canonical boundary, rejects final symlinks/existing output/escapes,
and uses `lstat` so a filesystem error cannot masquerade as absence. Tests caught
the non-strict resolver preserving a symlink loop while `exists()` returned
false; both that loop and a non-directory parent now fail explicitly. This is
read-only admission, not a held directory capability. The caller must own the
workspace throughout external-tool execution; hostile concurrent ancestor
replacement is not claimed to be prevented by a returned `Path`.

The old Android code fails three admission regression subcases. The fixed
Android, installed-connection and evidence-I/O modules pass **47 tests** with
Python warnings treated as errors and no skips. The retained old/new filesystem
probe has two old escapes, two new rejections with no output, and valid writes
inside the target on both versions. Three real CLI calls additionally distinguish
invalid destination rejection from the subsequent invalid-pin check, without
creating output or invoking build tools. No primitive, SDK ABI, journal or wire
contract changes. These checks do not replace full Android packaging/device
execution or the preceding native Continuity qualification.

The `f151c136` Windows 2022 and Windows jobs in run `36637764476` subsequently
failed the existing symlink-loop/non-directory-parent checks. The helper returned
only through its `FileNotFoundError` branch: those invalid child lookups could
therefore be mistaken for a valid missing output on Windows. The repair walks
back to an existing parent and requires positive ordinary-directory metadata;
symlinks, Windows reparse points and non-directories are refused. It still creates
nothing and retains the exclusive-workspace assumption. A portable regression
models that reported missing-child result while reading the real parent metadata:
the old helper fails both subcases, and the repaired three affected modules pass
**48 tests** with warnings as errors. This local error-mapping regression does not
claim native Windows execution; exact-head Windows CI remains pending. The prior
hosted failures and their six existing platform skips remain in the raw record;
no new skip or suppression is introduced.

## Validation and remaining review

The clean source passes 2,268 artifact tests in 453.901 seconds without skips,
with its pre/post source gate and the 43-export ABI 2 contract check. The actual
host workload, iOS executable linkage and unsigned app build pass locally. The
new host/iOS CI step also passes at run `36345633624`, artifact `10940517353`
(SHA-256 `ce567e45fd0e4ecf771735a898ad5b332823d2c7d97089ee6ef98a1de0b9e1df`).
This artifact contains host/build logs; device execution has its own capture.

The same source completes all 36 CI jobs in run `36345633624` and all six
CodeQL analyses in run `36345633631`. Its PR merge
`06db6468429b8097f2af0bb9087b49e0e2b55962` has the same tree as the inspected
source. The 41 open alerts retain the preceding IDs and rules; all thirteen
files containing their reported locations have unchanged Git blobs. Existing
internal dispositions therefore retain their source scope. No alert is
dismissed or suppressed, and analysis completion alone is not a security proof.

The named ownership, persistence, asynchronous disposal, transcript/erasure,
WASM and reference-authentication paths now have internal inspection records.
The completed `99fb979` analysis retains the same 41 alert IDs/rules. Twelve of
thirteen location files are unchanged; the three path findings in the changed
AGP consumer were rechecked against its caller-selected directory, fixed bundle
names, bounded readers and exact closure. The new runtime selector does not
construct filesystem paths. Later harness changes still require their own
source-specific analysis. Platform execution, controlled performance and the
coordinated release transaction remain in the
[readiness ledger](SDK_0_2_RELEASE_READINESS.md).


### Archived session cleanup boundary (2026-09-30)

The unpublished native QPCSCA01 archive is authenticated under a dedicated
HKDF-derived journal-wrapping subkey. It binds the original journal, storage owner,
local/peer account, peer device/generation, context/session/role, storage protection
and exact signing-key binding. Preparation takes the retained verified context but
can precede message activation, allowing the host to fsync its archive before that
transaction. Archive parsing alone does not produce any verified authority.

The restricted opener checks MAC and independently expected journal ID before I/O;
then it holds the normal exclusive lease, verifies the existing authenticated image
or original sealed activation target, and reconciles only saved write-intent bytes.
It exposes only closure status, freeze/loss report, terminal acknowledgement and
owner shutdown. It shares the original closure engine and cannot return a live
DeviceJournal or BootstrapContext. Required-witness attachment compares the original
pin and signing key, with the existing subject/current-head/advance protocol. Witness
enrollment expiry still rejects new advancement; no local fallback is introduced.

Public archive fields reveal metadata linkage. Wrapping-key disclosure, historical
image rollback in the local-only profile, host archive/index durability, aggregate
recipient-set archive recovery and witness renewal remain separate assumptions or
integration work. No erased private session data is recovered from the archive.
The new path changes no v20 disk grammar, wire KDF, KAT or published ABI.


### Native connection archive persistence (2026-09-30)

The native Actor now owns both the device journal lease and its separate bounded
SessionArchiveStore lease. Index provisioning/opening reuses the protected database
capability and shared immediate/two-phase transaction helper. The index holds public
MAC-bearing records and no wrapping key. Header/grammar/index scope admission is
separate from archive MAC authentication by the actual journal owner.

The initiator commits its exact archive before sending the final bootstrap flight;
the responder commits its archive before message activation/READY. Both recheck
cancellation/deadline/authority afterward. Unknown index commits close the index
owner and require exact readback/retry; no index error creates a new session ID or
refunds crypto work. Application send/receive additionally require the original
scope/MAC before send reservation or inbox mutation. This is an immutable local
prerequisite, not a new two-database rollback scheme or proof of remote filesystem
compliance. An older index can block availability but cannot reset the protected
journal. No automatic reset, removal, replacement or silent network retry is added.

The native complete path now includes context-free cleanup processes using the
actual indexes. Other bindings/service adapters, catalogue lifecycle, missing archive
restoration, witness renewal and initial-bootstrap cancellation remain explicit work.


### Journal creation identity and enrollment recovery (2026-09-30)

The observed pre-return process cut shows why an ID generated only inside creation
cannot serve as independently retained recovery input. Both native provisioning
entry points now require a public identity retained before the call. Existing open
interfaces and v21 encrypted grammar are unchanged. Missing/partial creation is
refused, with no implicit replacement of a potentially active lineage.

`recover_anchor_genesis` holds the original database lease, authenticates the full
image under the original key/owner and refuses any pending journal intent. It checks
the independently expected ID, local account, exact policy and witness, fence 1,
revision 1 and original roster genesis. The result contains public enrollment
metadata, no DeviceJournal or signing/runtime capability. The original witness
still controls enrollment and fresh admission. redb may perform its own storage
recovery on open; this API performs no application-image transition or intent
reconciliation. An old genesis snapshot is not proof of a current witness head.

Process-cut tests cover local creation before/after commit and required creation
after commit, with bounded competing processes. Exact recovery performs actual
bootstrap/prekey work; an authenticated pending-intent fixture remains unchanged.
The initial full-suite failures were a test-marker publication race. Atomic marker
publication preserves the assertions and removes the partial-observation window;
the frozen Debug and Release suites then each pass 252 tests.

The wrapping-key follow-up now reconciles an exact single-link file through file
and pinned-parent synchronization before returning an owner. A separate real-process
counterexample exposed shared initializer cleanup: a concurrent opener had already
used the complete key for a durable signing owner when the creator's failure
unlinked the wrapping file. `provision_private_file` now propagates the original
error while preserving admitted state. This fixes the root helper used by both the
native candidate and actual SDK policy/authority stores; no replacement file or
permissive fallback is introduced. Private admission failures before initialization
retain their existing empty-file cleanup.

Targeted tests preserve the same dependent signer across creator failure, seven
process cuts and six before/after sync injections. The actual SDK signed-policy
path also preserves a committed image when the creation result is lost; exact
reopening restores its runtime, and closing the store revokes its key aliases.
An incomplete authority-store image stays refused and exclusive provisioning
cannot replace it. redb may change its own recovery header during a refused open;
the preservation assertion is placed around provisioning, not that independent
engine operation. A failed creation can now leave a reserved path that requires
explicit diagnosis; automatically deleting it would reintroduce the observed race.

Installed owner initialization still must retain creation intent and enforce one
authoritative journal per device lineage. A public ID supplies no rollback
protection, and these tests do not prove hardware power-loss behavior.

The same shared storage behavior is exercised through the actual packaged Rust
SDK on Rust 1.98.1 and 1.90. A bounded child process imposes a real kernel file-size
limit and checks explicit failure, preservation, no replacement and no runtime
from partial storage. The native candidate's 258 Debug/258 Release tests and the
shared SDK suites cover the same frozen Rust source. Installed Continuity owners
and independent endpoint/device qualification remain separate unfinished work.

Package qualification also exposed an audit false green: cargo-audit 0.22.2
reported missing fuzz registry entries on stderr while returning zero and empty
JSON warnings. The original result remains unqualified. A failing acceptance
regression now passes with strict diagnostic rejection; fetching both lockfiles
before auditing supplies the missing entries. The corrected real package run has
empty workspace/fuzz/consumer audit stderr and zero reported advisories/warnings.
This closes incomplete audit acceptance, not every dependency or protocol risk.

The archive catalogue recovery path retains the cleanup owner's restricted
authority. Index IDs are only discovery hints; grammar checks cannot authenticate
their MACs or grant message permissions. Restoration checks the independently
pinned journal, original authenticated session scope and fresh witness head before
reconstructing the original QPCSCA01 bytes. The canonical encoder/HMAC and immutable
retention transaction are shared with normal archive preparation/retention.

Retirement additionally requires `Closed` with the exact acknowledged host report
ID. It refuses open/pending state, another report, aggregate abandonment and changed
index bytes. Absence is an idempotent result only after the same fresh witness
checks and a successful schema-checked index read. Storage errors close the index;
witness failures close the cleanup owner before index mutation. Exact reopen/retry
reconciles unknown commits. No journal tombstone, budget, claim, sequence or slot
is removed or refunded. A separate process readback checks the unchanged terminal
journal digest and retained unknown-delivery outcome.

Index rollback/loss still affects discovery and availability, and the original
archive backup is needed when the index is gone. This adds no hardware erasure,
new anti-rollback anchor or operational context reconstruction. Installed service
initialization, authoritative device lineage and binding integration remain open.
