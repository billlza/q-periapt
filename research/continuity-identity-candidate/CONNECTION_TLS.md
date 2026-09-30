# Native bootstrap and application connection

The optional `connection-tls` feature connects independently provisioned native
journals through the SDK's standard hybrid mutual TLS and exporter-bound policy
confirmation. It is an unpublished candidate API. It now carries bootstrap and
application frames across actual sockets; it does not publish a language binding,
provide an account-directory service or qualify physical devices.

## Owners and reference path

`ConnectionEndpoint` binds one independently verified `BootstrapContext` before a
session ID exists. TLS certificate pins are configured separately. The host must
pin the intended account/roster and verify both identities, the policy and prekey
manifest before constructing that context; network bytes cannot install trust.
`Actor` exclusively borrows the corresponding journal, durable `SessionArchiveStore`,
context and controlled device signer. Provision the [archive index](SESSION_ARCHIVE_STORE.md)
explicitly once and reopen it with the independent journal ID on restart. No wrapping key, raw session root or naked prekey enters this API.

The complete reference path is exercised by
`connection_tls_bootstrap_rekeys_and_both_application_directions_use_actual_network`:

1. Provision an encrypted responder inventory and independent sender journal.
   Publish and verify the real inventory public leaves. The temporary external
   prekey owners are closed; the inventory owns the actual private contributions.
2. Retain an `InitiationId`, construct exact pinned TLS endpoints, and call
   `establish`. Initial, reply and final flights use the original journal
   transactions. The server consumes selected one-time keys with its reply outbox,
   confirms the final flight and activates durable traffic state. Both endpoints
   first commit and read back their exact cleanup archive; the client does this
   before sending the final flight. The client verifies the matching activation
   response before its own activation. Cancellation, deadline or archive failure
   at that boundary cannot report an established connection.
3. Use `ControlEndpoint` with that exact session for three alternating network
   rekeys. This is the existing independently identified control carrier; it
   shares the same bounded socket engine, not a second TLS implementation.
4. Retain a journal-issued `MessageId`, call `send` with exact plaintext and AD,
   and serve it on the peer with a durable application `Consumer`. The reference
   consumer fsyncs a single record containing session ID, message ID and actual
   plaintext, atomically publishes it and syncs its directory. Exact duplicates
   compare the retained record instead of repeating the effect.
5. Commit peer consumption, receive and verify its epoch-specific authenticated
   prefix, and confirm the original ID through local journal readback. Independently
   reopen the peer's application file and compare all ID and plaintext bytes.
   Reverse the TCP/TLS roles and repeat under the same established session.
6. Close the original policy owners. New processes load each indexed archive and
   perform loss accounting and terminal acknowledgement without reconstructing any
   verified context. Independently reopen and confirm both terminal identities.

These tests use independent native processes on one host and real TLS sockets,
journals and files. Their trusted enrollment fixtures are local test inputs.
They establish a native reference execution path, not installed cross-language,
independent-implementation, cross-host or device qualification.

The external consumer in [`tests/owned_connection.rs`](tests/owned_connection.rs)
additionally executes this carrier through both original `DeviceInstallation`
owners and persistent SDK policy stores, using only public APIs. Its local-key
loading, uncertain application-commit reconciliation, eight competing owner leases,
pre-cancellation and durable policy revocation are described in
[the installation contract](INSTALLATION.md#public-consumer-and-original-service-recovery).
It is automatically included in all-feature Debug/Release candidate CI.

## Durable application effects and confirmation

`Consumer::commit` is an explicit external transaction boundary. Success means
that both the application effect and its session/message deduplication record
are durable together. The library cannot implement or certify that external
transaction. A handler error, unknown external commit or cancellation after the
external effect leaves the inbox unconsumed. Recovery may call the handler with
the same ID again; the application must reconcile that exact transaction.

The server invokes the handler only after authenticated inbox commit. It then
checks cancellation, deadline and authority, commits `consume_message`, and
releases the original epoch's consumption MAC. The client validates the response
kind and exact epoch, verifies and commits that MAC through the journal, and
queries its original ID before reporting `Consumption::Confirmed`.

`PrefixPending` is an explicit non-completion outcome. A later message can already
be consumed while an earlier gap prevents the authenticated cumulative prefix from
covering it. The transport does not advance that prefix or invent earlier delivery.
When the missing earlier message is actually consumed, the genuine cumulative
ACK can settle both outboxes. An old valid ACK from a different epoch is rejected.

For an already consumed ID, the server does not call the handler again. Above the
contiguous erased prefix it still checks the retained exact input commitment.
Below that prefix, its old message key and input commitment are already gone:
the result proves **prior consumption of the ID**, not authentication or delivery
of replacement bytes in the current request. The ordinary SDK send API prevents
replacement input under an existing outbox ID. A new `send` using an already
retired local ID fails; callers reconcile uncertain local ACK commits through
`message_status` rather than treating new input as successfully consumed.

Bootstrap, messages and external effects can commit before a network error. No
such error proves absence. All retries reuse the original initiation/message ID
and sealed exact input, and re-release through current journal admission. Durable
errors close the journal when required; this carrier never silently reopens it.
A server-side application failure is visible to its host as `Error::Application`;
without a dispatched proof the remote caller has an uncertain network outcome.
It cannot infer that the external effect did not occur.

## Binding and canonical carrier

The SDK connection context is:

`"Q-PERIAPT-CONTINUITY-CONNECTION-TLS/v1/" || bootstrap_context_digest[32]`.

It differs from the session-bound control carrier. Both use the existing SDK
framing, request IDs, one outstanding request and exact certificate pins. Native
socket, TLS progress, cancellation, timeout and retry classification code is shared
with `control-tls`; the QPCCTL01 control grammar remains unchanged.

Every new carrier frame is `QPCNET01[8] || kind:u8 || body`, with a nonempty body
and at most 32,768 bytes overall. Integers are big-endian. The SDK retains its
separate 65,536-byte outer frame bound.

| Kind | Body | Result |
| --- | --- | --- |
| 1 Initial | original initial flight, at most 8,192 bytes | 129 plus original signed reply |
| 2 Final | initial_length:u16, initial, original final flight | 130 plus exact session[32] |
| 3 Application | AD_length:u16, AD, original encrypted message frame | 131 plus original epoch consumption ACK |

The journal's existing strict decoders authenticate and enforce exact flight,
message, AD, context, role, epoch and signature constraints. Carrier kinds, magic,
size, split lengths and reply identities are checked separately. Empty, malformed,
unknown-kind, wrong-epoch and mismatched-session replies cannot become success.
There is no alternate JSON, plaintext, classic-only or public-commitment fallback.
Application direction is independent of TLS or bootstrap role.

## Bounded invocation and lifecycle

`Run` specifies address, TLS name, limits and one-way cancellation. Every request
attempt consumes the finite 1–128 exchange allowance. Bootstrap normally uses two
exchanges. Reconnecting never resets the unchanged total deadline (at most 120
seconds) or the bounded TCP connect (at most five seconds). Only the existing
classified transient network errors are retried; local authority, archive, journal,
application, parsing and trusted-clock failures are explicit errors.

I/O polls at most every 25 ms, with the original deadline checked again. Synchronous
cryptography, filesystem calls and host callbacks are cooperative boundaries, not
forcibly preempted syscalls. Cancellation cannot undo an already committed journal
or external transaction. Socket owners close on all returns; endpoint close also
revokes its SDK connections. The host cancels an invocation before taking its
exclusive journal back to install roster or policy updates.

`serve` handles one accepted connection within the same finite bounds, returning
after final activation or application proof flush. The host retains its listener
for exact reconnect/replay. It supplies current fallible trusted time; no timestamp
is substituted. Listener scheduling, periodic rekey policy, account-wide fanout
routing and platform integration remain explicit host/product work.

## State and qualification boundary

The carrier introduction did not change the then-current journal v19/QPMST010,
cryptographic primitive or wire ratchet version. The later durable lifecycle uses
[session closure](SESSION_CLOSURE.md); QPTEPO04, QPCMSG03, authenticated ACKs, v6 controls and signed
policy bytes retain their contracts. Ordinary `receive_message` still rejects
retired input. The carrier's internal reconciliation path can return only a prior
consumption identity or the ordinary committed plaintext owner.

Targeted process tests kill the server after reply commit, responder activation,
inbox commit, external application commit and consumption commit, before the
corresponding response. The parent observes each actual stage before termination;
there is no timing guess about whether a commit happened. At each cut a separate
bounded contender must refuse journal ownership with Busy. Recovery reuses the
same request/input and observes exactly one external effect. Other cases cover
application failure, unknown external commit, cancellation after external commit,
out-of-order prefix blocking, a genuine old-epoch ACK and pre-dispatch invalid
options/cancellation/clock failure. Existing control-TLS cancellation, socket
closure, certificate, expiry, timeout and reply-loss regressions exercise the
shared native engine as well.

These tests do not prove continuous PQ recovery, atomic remote effects without the
Consumer contract, rollback protection without the configured independent witness,
physical deletion, or full SDK 0.2.0 readiness. Source-bound full results and
remaining release requirements are retained separately in the release ledger.

The complete macOS ARM64 suites pass **200 tests each**, zero failures or ignored
tests: debug 501.18 seconds and release 331.11 seconds in their
runners. They overlapped and are not a controlled performance comparison. Eight
new test functions include the subprocess entry point. Strict all-target/all-feature
Clippy passes on Rust 1.90 and 1.98.1. Separate no-TLS, control-only and
connection-only feature checks, warning-strict documentation, formatting and
45 clean isolation/source-inventory checks also pass for 212 Rust sources.
Initial diagnostics (a fixture error-type import and a redundant test-helper
Result wrapper) were corrected without suppressing checks. The lost-response
tests now observe the actual commit marker before killing the process rather
than relying on a two-second timing window. Raw runs, source hashes and both
test executables are retained in the qualification cohort.

The later [portable-material input](BOOTSTRAP_BUNDLE.md) reuses this execution
path with contexts reverified from saved public bundle bytes in each process.
The existing policy owner, trust pins, intended devices and requested quality
remain independent host inputs. QPCNET01 and journal semantics are unchanged.


The current native path requires [durable archive indexing](SESSION_ARCHIVE_STORE.md)
before activation and authenticates that retained input before data submission or
delivery. This changes the unpublished Actor API and adds Error::Archive; QPCNET01,
v20 journal state, rekey/message cryptography and published SDK bindings are unchanged.
The earlier 200-test cohort above remains a historical carrier checkpoint.
