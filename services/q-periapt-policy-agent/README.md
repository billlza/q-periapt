# q-periapt-policy-agent

Non-publishable reference service that owns migration state, the frozen ABI 2
execution path, KEM private keys, pending secrets, and key-confirmation state.
Applications receive random opaque handles; they never receive a writable ABI 2
decision, a KEM private key, or an unconfirmed session secret.

Migration-state ownership and ABI 2 execution availability are deliberately
separate. The agent authenticates and commits any migration-authority-valid
state, including a post-quantum-only state, a state with a different execution
policy identity, or a state that no longer authorizes ABI 2. Such a state is not
poisoned and remains recoverable after restart, but `public_keys` and session
creation return an explicit execution-unavailable error until a separately
authenticated, exact-compatible policy bundle is configured. There is no
execution fallback.

The local repository uses pinned `redb` 2.6.3 transactions with immediate
durability and two-phase commit. `redb` is pure Rust, ACID, crash-recoverable,
MSRV 1.85, and licensed `MIT OR Apache-2.0`. After an unclean shutdown all
three stores -- repository, witness, and authority -- let `redb` finish its
crash recovery on open. A normal stop is not one of those: `serve-agent` and
`serve-witness` install `SIGTERM` and `SIGINT` handlers whose only action is
to set a flag, the serving loop reads it within one maintenance interval -- or
once the request in flight has been answered or refused -- and returns, and
the store then closes cleanly through its destructor. Recovery
still runs after a crash, a `SIGKILL`, or a stop that outran the service
manager's stop timeout, and after any restart of the authority store, whose
hosting process decides when its own flag is set. Because every commit is two-phase,
that recovery only reconstructs the free-page allocator from the committed
tree: `redb` refuses a corrupted two-phase primary outright rather than falling
back to an older commit, so committed data is never altered by it. A store
left unclean by a writer that did not commit two-phase is refused untouched
before `redb` sees it. `redb` is deliberately not
treated as a rollback anchor: restoring the whole database file restores all of
its history.
Every open, transition, and key release therefore requires an authenticated
external `WitnessPort`. There is no local-only fallback.

Both durable-file paths must be absolute, contain only normal path components,
live in an owner-owned exact-`0700` service directory, and identify an
owner-owned exact-`0600` regular file. On macOS, the service also rejects any
extended ACL on the final directory or file through a descriptor-based native
query; POSIX mode alone is not treated as an owner-only proof. The service
traverses every directory descriptor-relative with `O_NOFOLLOW`, opens the final
file relative to the pinned parent descriptor, and passes that already-open file
into `redb`; the database path is never re-resolved. `redb` also holds an
exclusive database lock, so a second policy-agent process cannot open the same
repository; that lock is part of the cross-process linearization boundary around
witness rechecks and local commits.

The reviewed durable-file boundary supports macOS and Linux. Linux POSIX ACL
grants are reflected in the group-class mode mask and are rejected by the exact
mode checks. Other Unix ACL models are not assumed equivalent and fail closed
until a platform adapter is reviewed.

A signed state or reset envelope is first authenticated and replayed by the
migration state machine. The repository then durably records one operation ID,
the exact old head and fence, the exact next revision and fence, and the
canonical signed envelope. Only then may the mandatory witness perform the
exact CAS. An authenticated applied receipt permits the final local transaction.
An unknown transport result leaves that same operation pending: new operations
are refused and recovery may only query that operation ID. On open, the complete
canonical journal is decoded and reverified before the local head is compared
with the witness. Missing, duplicate, forked, trailing, corrupt, or rolled-back
state has no implicit-genesis repair path.

Transitions are allowed to advance while sessions exist. The final local commit
changes the fence and transactionally removes durable reservations and replay
state; the in-memory linearizer then erases pending and accepted secrets. Every
acceptance rechecks the exact repository and witness head/fence, so a session
from the old head cannot be accepted. A process-boundary test exits immediately
after durable intent without running destructors, then reopens and reconciles
the same operation. This is crash-protocol evidence, not evidence for a specific
filesystem, storage controller, or whole-machine power-loss guarantee.

Finished ordering is determined only by the configured protocol role, not by
which endpoint performs KEM encapsulation. An initiator begin operation returns
I and waits for R; a responder begin operation returns no Finished. The
responder acceptance path rejects the wrong flight, checks transition state and
the exact repository/witness head, verifies I, and derives the accepted key and
R. R is not returned until the durable reservation release and bounded
in-process accepted-key/completed-response retention both succeed. The
initiator likewise rechecks state and witness, verifies R, durably releases its
reservation, retains the accepted key, and only then returns its key handle.
Failure to cancel or release durable state poisons the Agent and returns no key
handle or Finished response.

Authenticated capability session identifiers are retained as bounded durable
replay tombstones for the entire current state. Cancel, Finished rejection, key
acceptance, and restart do not erase them. No tombstone is silently evicted;
capacity exhaustion fails closed. A committed state transition clears the table
only after changing the signed state digest and global generation, so old offers
then fail the current-state checks before reservation. The tombstone is what
makes a Begin exactly-once across the whole current state; the in-process Begin
retry index only lets the process that holds the pending secret repeat its own
answer, and it is bounded by, and evicted with, the pending sessions.

The migration authority and reset/recovery authority must have different,
nonzero key IDs and different ML-DSA-65 verification keys. Endpoint roles also
require distinct key IDs and verification keys. This reference implementation
uses a fixed migration-authority keyring: an envelope that attempts authority
rotation is explicitly rejected rather than being treated as a reset success.
Because those state authorities are ML-DSA-65, the reference service also rejects
a level-5 state certificate before persisting because its configured signer is
below that floor. The generic migration state machine can use a level-5 verifier,
but adding that authority requires an explicit service keyring and configuration
format revision; it is never approximated with the level-3 key.

The reference witness adapter mutually authenticates exact, nonce-bound CAS and
query messages with ML-DSA-65 over bounded TCP frames. A reference witness server
persists its independent head and operation receipts in a separate redb database.
For the rollback claim, that server must run outside the rollback domain of the
agent host. Running both databases on one restorable disk is useful for tests but
does not provide rollback resistance.

TCP witness messages are authenticated and transcript-bound but are not
encrypted; deployment must provide a network boundary when state metadata is
confidential. The reference server processes one connection at a time with a
five-second I/O timeout. This is an explicit resource bound, but an unauthenticated
slow client can occupy that one slot until the timeout.

Every IPC request is answered or refused within one end-to-end deadline of 35
seconds from accept. The client-paced read and the response write are each
additionally capped at 5 seconds, and in between the agent admits every wait
against that deadline: first the acquisition of its one linearizer, then each
authority and witness round trip, refusing a lease-guarded operation whose
least plan no longer fits before it dispatches anything. Cancel, Destroy and
the public-key read make no round trip, so the linearizer is the only thing
they wait for, and they are refused on the same deadline. IPC status 24 means
the request was refused or aborted on its deadline with nothing retained and
its reservation released; it is not a fence, and the request may be retried
under a fresh nonce with a fresh offer where the offer was consumed. A request
that could not reach the agent's linearizer inside its deadline is refused the
same way and consumed nothing at all, its offer included: that retry needs no
fresh offer. An acceptance aborted after its witness read has
consumed its handle as well: that retry is refused with `UnknownHandle`, and
the session has to be re-established from Begin. A status 24 raised on the
coverage snapshot that follows a lapse re-acquire comes after the erasure of
every in-process secret, so the deadline is what a longer one recovers, not the
keys. A committed operation whose response could not be written by the deadline
gets no response at all, which the client sees as a lost response and, for a
Begin or an acceptance, recovers by the exact retry described below; a
transition it reconciles.

The executable IPC face is Unix-only. It does not create its listening socket:
the service manager does, and the daemon adopts the descriptor it is handed,
requires that exactly one was passed, that it is a listening `AF_UNIX`
`SOCK_STREAM` socket, and that it is bound to the path named on the command
line. Absent or mismatched activation is a startup failure with no self-bind
fallback, so a socket whose owner, group and mode nobody configured cannot come
into existence by accident. The daemon authenticates requests under a pinned
ML-DSA-65 client key and rejects unknown, oversized, truncated, or trailing
message bytes.

The daemon cannot verify the socket's owner, group or mode. An `AF_UNIX`
descriptor names a socket object rather than the filesystem node that addresses
it, so `fstat` on the inherited descriptor reports a different inode and mode
than the path does. Those permissions are therefore enforced only by the
deployment templates, which is why they are written explicitly there rather than
left to a default. The admission boundary the daemon does rely on is the parent
directory's mode. These controls do not
provide code-signing identity or protect against hostile code already holding the
authorized client signing key. Non-Unix targets fail explicitly instead of
claiming an equivalent boundary.

Kernel-level process isolation is deliberately delegated to the service
manager rather than claimed by the binary: [`deploy/`](deploy/README.md)
holds the hardened systemd unit (dedicated locked account, read-only OS
view, seccomp `@system-service` filter, empty capability set, no core
dumps) and the launchd daemon template (dedicated uid, owner-only umask,
no core dumps) with the boot-time job that verifies the socket's `0710`,
ACL-free parent directory and the root-owned, ACL-free ancestry above it on
macOS and loads the agent only after that, together with the exact table of
which boundary each
layer enforces and the explicit non-claims. A deployment that starts the
binary outside those templates gets only the daemon's own
filesystem-capability and cryptographic boundaries.

IPC is a hard V2 cut: request, response, and request-digest domains all end in
`/v2`, schema 2 has distinct `AcceptInitiatorFinished` and
`AcceptResponderFinished` commands and role-shaped begin/accept responses, and
there is no V1 decoder or fallback. A consumed IPC nonce is never reusable. If a
successful Begin response is lost while being written, the client may resend the
exact same signed offers and the same peer public keys (encapsulation) or
ciphertexts (decapsulation) under a newly signed nonce; while the pending
session that Begin created remains live in the same process, the agent returns
the same handle, ciphertexts and initiator Finished. Different public input or a
different Begin command under the same capability fails with
`AuthorizationRejected` and erases nothing. Cancel, expiry, acceptance, Finished
rejection, a lease lapse recovered by re-acquire, restart, a committed
transition and fencing end that window. After the first six the durable
capability tombstone answers with `AuthorizationRejected`. After a committed
transition the tombstone table is already cleared, and the old offers fail the
current-state checks instead -- the same `AuthorizationRejected`. After fencing
the instance is retired and every operation, this retry included, is refused
with `InstanceFenced` at the lease phase guard, before the retry index or the
tombstone is consulted. If a successful acceptance response is lost while being
written, the client may send the exact same handle and Finished under a newly
signed nonce; while the same process and retained key remain live, the bounded
completed-acceptance cache returns the same key handle and, for the responder,
the same R. Different Finished bytes fail as a conflicting replay. Destroy,
committed transition, or process restart clears that cache. Neither
`AcceptedSessionKeyV1` nor R is persisted or recovered after a crash; the
durable capability-session tombstone remains, so recovery requires a new
authenticated session rather than reuse.

The executable accepts exactly one of these command shapes:

```text
q-periapt-policy-agent serve-agent SOCKET_PATH REPOSITORY WITNESS_ADDRESS AUTHORITY_ADDRESS CONFIG_DIRECTORY
q-periapt-policy-agent serve-witness LISTEN_ADDRESS WITNESS_DATABASE CONFIG_DIRECTORY
```

`SOCKET_PATH` is the absolute path the inherited listener must already be bound
to. The daemon compares it against the descriptor's own bound address and
refuses to serve on a mismatch; it never binds the path itself. Its directory
must live in a stable, trusted namespace, so that an untrusted UID cannot rename
an ancestor and substitute a different client-visible pathname: the shipped
templates use `/run/qperiapt-agent` on Linux and
`/opt/qperiapt/run/qperiapt-agent` on macOS, where `/private/var/run` fails
this test — it is `root:daemon 0775` without the sticky bit, so any gid-1
process can rename an entry there.

Every address argument -- `WITNESS_ADDRESS`, `AUTHORITY_ADDRESS`, and
`serve-witness`'s `LISTEN_ADDRESS` -- is a numeric `IP:port`. They are parsed as
a `SocketAddr`, which performs no name resolution, so a hostname is rejected at
start as an invalid configuration rather than resolved. That is deliberate: the
Linux template pairs each endpoint with an `IPAddressAllow` entry that systemd
resolves once at unit load and never re-checks, so a name would be the wrong
thing on both sides of the same pairing.

A stale socket is not the daemon's problem to solve, and it does not try: it
never unlinks a path it did not create, and it cannot safely infer that an
existing socket is dead. The socket's whole lifetime belongs to the service
manager, which is the only component that knows whether the previous process is
gone. On Linux the socket unit owns the node across restarts; on macOS launchd
does the same for the entry in its `Sockets` dictionary.

Each server direction also installs its own verification key --
`ipc-server-vk.bin` beside `ipc-server-sk.bin`, and `witness-server-vk.bin`
beside `witness-server-sk.bin`. Startup signs a probe and requires it to verify
under that key. Signing alone only proves the key is well-formed: a valid but
wrong signing key would otherwise start cleanly, commit state, and only then
produce responses every client rejects. This proves the deployment is internally
consistent; it cannot prove clients pinned that key, which is established out of
band.

The executable opens existing stores only. Controlled bootstrap must explicitly
call `StateRepository::provision_new` and `ReferenceWitnessServer::provision`;
a missing store is never provisioned by the runtime. Configuration files are
fixed-name, exact-length owner-only files under the validated `0700` directory.
They include separate migration/recovery roots, local/peer endpoint identities,
signed execution/local/peer policy bundles, IPC request/response keys, witness
request/response keys, and the instance-lease authority material: its
request/response keys plus the pinned wire identity (client and server
identifiers, authority epoch, exact expected state head, and deployment
configuration revision as fixed-length big-endian binary files). Secret-key
files are read directly into zeroizing buffers. `serve-agent` acquires the
exclusive instance lease at startup: it waits for a crashed predecessor's
lease to lapse and fails closed only while a holder that is still renewing
has it. A start that acquires the lease and then fails -- the witness
unreachable, the executor or the policy material rejected -- releases the
lease before returning, so the retry does not wait out a TTL. A guarded
operation renews the lease before it starts, and a secret it produced is
retained only after a fresh authority snapshot, taken after its durable write,
shows the lease still held by this instance with more than one second of
authority time left; snapshots are reads, and are not journaled.

Every lease mutation the agent sends -- the acquire at start, the renew before
each guarded operation, the re-acquire after a lapse, and the release -- is
journaled in the agent's own store before it is dispatched, and the row is
forgotten once the authority's receipt for it has been acknowledged. That
acknowledgement is the only thing that prunes the authority's bounded receipt
table, and it used to be owed from memory alone: a crash with one queued lost
it for good. On every start the agent settles the journal before it acquires:
a receipt the authority still holds is acknowledged and its row forgotten; a
row for an operation the authority never saw is forgotten; a row the authority
cannot answer for is kept and asked about again before each guarded operation.
A re-acquire after a lapse whose reply is lost is remembered, in memory, with
the fence it would have produced; the next guarded operation asks the
authority for that exact operation -- or sees that fence in its snapshot --
before it renews, so the agent's own re-acquired lease is never mistaken for a
successor and the instance is never fenced without one. A stop resolves it the
same way, and when the authority can answer neither it releases that expected
fence.
Settled rows are forgotten by the next journal write, so the steady-state cost
is one durable transaction per lease operation, and a clean release leaves the
journal empty unless a row could not be settled -- notably a re-acquire the
release adopted from a snapshot because the authority was still refusing
queries, whose row and receipt wait for the next start. The journal holds at
most 64 rows, matching the in-memory acknowledgement queue; reaching that takes
the authority refusing 64 consecutive acknowledgements, 64 consecutive lease
operations that failed or stayed indeterminate at dispatch against an authority
that could not then be queried, or as many starts whose acquire was journaled
and dispatched but left unsettled -- half as many when such a start's own
release goes unanswered too and journals a second row. A start against an
authority that cannot answer at all adds nothing: it is refused at the
pre-acquire snapshot, before any dispatch and before any journal write. A full
journal refuses the next lease operation with `InstanceLeaseUnavailable` before
anything is dispatched, and a start that cannot settle any of 64 rows fails
closed the same way, until the authority answers again. A store provisioned
before the journal existed opens without the table; the first journal write
creates it.

Stopping and restarting need no operator action. A normal stop -- `SIGTERM`
from the service manager, or `SIGINT` by hand -- is observed by the serving
loop within one maintenance interval, or once the request in flight has been
answered or refused; the daemon erases every in-process secret -- one durable
commit per pending session, charged to the stop timeout and not to any
deadline, because nothing may be skipped -- then releases the lease under a
30-second budget of its own, and exits 0 only once the authority has
confirmed that release or a snapshot has shown that no lease of this instance
remains, so the next start acquires at once. If the release could not be
settled -- the transport refused it, the journal was full, its outcome stayed
unknown with no snapshot to prove it, the release budget could not cover the
dispatch, or the agent was already poisoned when the stop arrived -- the
daemon exits 1 with a one-line reason and the lease lapses at its TTL, which
the next start waits out. A release that did settle but whose durable cleanup
afterwards failed -- a session cancellation, or the journal forget -- exits 1
too, with its own reason: there the lease is released and the next start
acquires at once. A crash never releases the lease, and the authority lets it
lapse only at its TTL (10 seconds to 5 minutes, as configured on the
authority). A start inside that
window waits for the lapse: it retries the same fail-closed acquire after the
shorter of the lease's remaining life, as a fresh authority snapshot reports
it, and one second -- never sooner than 10 ms after the last attempt, and
after the full second when the snapshot itself cannot be read -- which the
authority refuses while any lease is active, and gives up with
`InstanceFenced` once the longest TTL the authority can grant plus a
five-second margin has passed -- which is what a genuinely live holder that
keeps renewing produces, so a duplicate deployment or a recovery clone is still
refused. The handlers are installed only once the lease is held: a stop that
arrives during the wait ends the process by the default disposition, holding
no lease; one that lands in the few seconds between the acquire and the
handler install ends the process without a release, and the next start waits
that lease out. The daemon writes only a one-line reason to stderr when it
exits with an error -- a refused start, a fatal serving failure, or a stop
whose release did not settle -- and nothing on a clean stop; the exit status
and the authority's own state are the only record of a stop, a wait, or a
refused start.

Reference resource bounds are fail-closed and do not silently evict security
state:

| Resource | Bound |
| --- | ---: |
| Any IPC or witness frame | 16 KiB |
| IPC capability-offer field | 8 KiB, also constrained by the total frame |
| Runtime pending sessions | 256 by default; hard maximum 1024; each carries its Begin retry record (public outputs only) |
| Runtime confirmed keys / completed-acceptance entries | 256 each by default; hard maximum 1024; one cache entry is retained only with its key |
| Runtime session TTL | 5 minutes by default; hard maximum 24 hours |
| Durable session reservations | 1024 |
| Durable capability replay tombstones | 4096 per committed state |
| Durable lease-intent journal (authority receipts awaiting acknowledgement) | 64 |
| Canonical migration history / generation | 4096 |
| Witness operation receipts | 4096 |
| IPC replay nonces | 4096 within a 10-minute window |

Capacity exhaustion is a typed rejection. Pruning, authority rotation, online
configuration replacement, and multi-process horizontal scaling are not
implemented by this reference service and require a separately reviewed
protocol rather than silent eviction or fallback.

This service remains a research/reference boundary. It does not modify the
frozen ABI 2 exports or layouts, and it does not turn local persistence, a mock
witness, a same-process Rust type, or successful ABI 2 execution into proof of
the wider migration formal gates.
