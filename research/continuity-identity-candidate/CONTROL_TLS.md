# Native control delivery over standard TLS

The optional `control-tls` feature carries the existing v6 rekey controls over
`q-periapt-rustls::connection`. It reuses the SDK's standard hybrid TLS, mutual
certificate validation, exact peer-leaf pins and exporter-bound application-policy
confirmation. There is no plaintext or classic-only fallback and no replacement
KEM/TLS implementation. This is an unpublished native candidate, not an installed
cross-language product service.

## Binding and carrier grammar

`ControlEndpoint::client` and `::server` bind one already admitted Continuity
session and its exact bootstrap-context digest to the TLS connection context:

`"Q-PERIAPT-CONTINUITY-CONTROL-TLS/v1/" || context[32] || session[32]`.

The inner carrier is versioned separately from both the SDK connection protocol
and the signed v6 controls. The SDK supplies its existing request ID, framing and
one-outstanding-request rule. Each request payload is `QPCCTL01 || control_wire`.
The response is either `QPCCTL01 || 01 || control_wire` or exactly
`QPCCTL01 || 00`, indicating that processing produced no further control flight.
Control bytes are nonempty and at most 8,192 bytes; all other tags, discriminants,
lengths and trailing bytes fail. The underlying SDK frame limit remains its
separate, bounded 65,536 bytes.

The transport never treats the empty carrier acknowledgement as a protocol proof.
Only an exact locally confirmed target permits successful return. Incoming control
replies must name this invocation's target before duplicate reconciliation runs.
A valid old receipt cannot complete a newer request. Continuity identity signatures,
key confirmations, current roster authority and required-witness checks remain
enforced by the original journal methods. TLS roles are independent of alternating
rekey proposer roles.

## Owned state and bounded invocation

`Session` exclusively borrows the journal, authenticated context and signing owner.
`Run` selects one target, explicit IP/port, TLS name, limits and cancellation signal.
There are no default retry or timing values. `RunLimits` admits 1–128 exchanges,
a nonzero total timeout of at most 120 seconds and a per-connect timeout of at most
five seconds. Every failed network attempt consumes an exchange; successful steps
also consume exchanges. Reconnect does not reset the overall monotonic deadline.

Only connection refusal/reset/abort, broken pipe, unexpected EOF, timeout,
would-block and not-connected network outcomes are eligible for bounded retry.
Certificate, TLS authentication, policy, signature, malformed framing and durable
failures are terminal for the invocation. Exhaustion returns an explicit error,
retaining the last network error when one caused exhaustion. A durable error is
not retried through an implicitly reopened or reset journal.

Before each dispatch/retry the journal rechecks authority and releases the exact
committed output. It never reuses an unchecked copy after a failed attempt. A new
invocation can redispatch a locally committed final receipt after process loss;
it does not need to guess whether the peer already accepted it. Once a later
local exchange exists, its authenticated dependency already supersedes that older
delivery. Retrying never creates replacement rekey entropy or refunds application
spending.

`Cancellation` is a shared, one-way signal. It stops further dispatch and drops
the TLS/socket owner; it does not undo journal work or acknowledge remote delivery.
I/O wakeups use at most 25-ms polling intervals, with the unchanged absolute
deadline checked again each time. Connect cancellation is observed no later than
the configured connect bound after that system call returns. Synchronous crypto,
filesystem operations and host callbacks are not forcibly preempted; a cancellation
observed afterward prevents their output from being dispatched. These are
cooperative boundaries, not an OS scheduling or syscall-completion guarantee.

The trusted-time callback returns `io::Result<u64>` and is queried at journal and
I/O boundaries. Failure returns `Error::Clock`; no timestamp is substituted and
clock failures are not network-retry candidates. The host must supply the clock
and apply authenticated roster/policy updates. It cancels an exclusive invocation
before taking the journal back to install such an update.

`serve` processes one accepted TLS connection with finite exchange/time limits.
It flushes the exact committed reply, then closes the connection after local
completion. The host keeps its listener available for duplicate control requests:
a lost final reply or carrier acknowledgement must remain reconcilable. The
`Completed` report states the local epoch and invocation exchange count, not
remote application execution, authenticated peer receipt of the last flight, or
continuous PQ secrecy recovery.

## Current execution and remaining boundaries

The real-process tests start from already admitted encrypted journals. Separate
native Rust processes communicate through loopback TCP and the actual standard
TLS/policy-confirmation engine. Both active endpoint roles exercise three
alternating rekeys, then the independently restored journal decrypts application
traffic under the installed keys. These are same-host Rust checks; the bootstrap
network path and installed cross-language transport remain separate requirements.

Actual process termination cuts are placed after the server's journal work and
before dispatch of offer, response, final, receipt and the no-output reply.
The caller observes an explicit failed attempt, the replacement server reopens
the same journal, and the next invocation sends the same retained input and
receives the original committed output. Additional tests cover a cancelled live
ClientHello wait and observed socket closure, endpoint capacity recovery, an
unchanged absolute timeout, protocol-time expiry, trusted-clock failure, a wrong
certificate pin, dishonest empty acknowledgement and an authenticated old receipt.

The old-receipt test first reproduced `Ok(Completed { epoch: 1, exchanges: 1 })`
while epoch 2 was requested. The journal itself stayed at epoch 1; the bug was the
transport's successful completion classification. Checking the target at the
transport boundary repairs that cause without changing the core's legitimate
old-receipt reconciliation behavior. The cancellation fixture also retained its
initial `WouldBlock` failure: the raw test server had not returned its accepted
stream to blocking mode. The production channel already explicitly configured
that mode; the fixture now does too.

All added dependency versions/checksums already occur in the SDK workspace lock;
no existing candidate dependency was upgraded. `rcgen` is a test-only certificate
issuer. The SDK publication graph still excludes this research workspace.

The `5f324607` macOS ARM64 runs pass **175 tests each**, with no failed or ignored
tests: 466.19 seconds in debug and 368.31 seconds in release. These runs overlapped;
their timings are verification observations, not a controlled performance
comparison. Strict all-target/all-feature Clippy passes on Rust 1.90 and 1.98.1;
the optional carrier also leaves the no-default-feature build valid.

Earlier Linux CI jobs reached their unchanged 25-minute limit while the debug
suite continued reporting completed tests. The candidate now optimizes nonworkspace
dependencies in debug builds while retaining their debug assertions and arithmetic
overflow checks; the journal/state-machine crate remains unoptimized. A separate
Rust 1.90 probe records the actual dependency compiler flags and catches an actual
overflow. This adjustment does not omit a test, relax an assertion, alter release
optimization or increase the CI timeout. That commit subsequently passed all three
hosted candidate jobs, including complete Linux debug/release runs on Rust 1.90 and
1.98.1, as part of 42 successful CI jobs and six successful CodeQL analyses.
Later source changes retain their own qualification requirements.

Native Windows/device execution, installed language consumers, real cross-host
endpoints, transport scheduling across multiple sessions, periodic trigger policy,
matched performance and all remaining 0.2.0 requirements are still required.

The socket/TLS/cancellation implementation is now shared with the separately
identified [bootstrap and application carrier](CONNECTION_TLS.md). The original
QPCCTL01 grammar and context/session binding remain unchanged. The combined
reference trace establishes from inventory, performs three network rekeys, and
transfers application bytes in both directions with independent file readback.
Its own source-bound qualification does not retroactively change this checkpoint.
