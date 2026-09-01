# q-periapt-policy-agent

Non-publishable reference service that owns migration state, the frozen ABI 2
execution path, KEM private keys, pending secrets, and key-confirmation state.
Applications receive random opaque handles; they never receive a writable ABI 2
decision, a KEM private key, or an unconfirmed session secret.

> **Authority Wire V3 status: pending, isolated prototype.** The V3 wire,
> repository schema, and three-domain coordinator described below exist only on
> the unreleased development branch. They are not evidence about published
> v0.1.4 artifacts and must not be cited as the current paper implementation
> until independent review and release evidence close that gap.

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
MSRV 1.85, and licensed `MIT OR Apache-2.0`. It is deliberately not treated as a
rollback anchor: restoring the whole database file restores all of its history.
Every open, transition, and key release therefore requires an authenticated
external `WitnessPort`. There is no local-only fallback.

The repository storage schema is V3. A V1 store is never opened through the
normal service path. The offline executable command
`migrate-agent-repository-v1-to-v3` replays authenticated history, validates the
head, capability and complete session tables, rejects any legacy pending
transition, and inspects an actually pristine Authority Store (version one,
fresh epoch, exact projected head/config, no lease, receipt, capability, or key)
before one transaction creates the V3 journal, binds that exact authority, and
advances the schema. Repeating the command on the exact V3 binding is
idempotent. The same command recovers the sole fresh-provisioning cut where a
V3 repository committed its empty journal before the pristine authority was
bound; it holds the actual authority store lock through the binding transaction.
There is no V1/V2 runtime decoder, compatibility wrapper, inferred
epoch, or historical receipt backfill.

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
migration state machine. One Agent-redb transaction then stores the canonical
certificate, exact witness CAS intent, exact Authority `AdvanceState` intent,
and authority-journal `Prepared` state. The authority result is recovered only
by the exact operation ID and becomes durable `Resolved` before ACK. Only an
applied authority receipt permits witness CAS; only exact witness application
permits the final local transaction that advances history/head, clears sessions
and capabilities, deletes pending state, and advances the durable authority
binding. The in-process wire head moves by exact compare-and-swap only after that
commit, then a new instance lease is acquired. Unknown results preserve the
single pending operation. Missing, duplicate, forked, non-successor, or
old/new/foreign-head combinations fail closed.

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
then fail the current-state checks before reservation.

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

The product-side authority protocol has a separate, bounded single-slot
`authority_journal` inside the Agent repository. The repository binds it once to the complete
Authority Wire identity `(client, server, epoch, state head, configuration)`. An
exact lease or state-advance intent reaches durable `Prepared` before any dispatch. A known or
exact-query-reconciled receipt replaces it with durable `Resolved`; only that
state can create the acknowledgement capability. A successful or already-absent
acknowledgement atomically clears the active slot and supersedes one exact terminal
checkpoint. The coordinator separately records whether its retained
`AdvanceState` result reached ACK-terminal, so a later lease checkpoint cannot
erase that transition phase. Unknown query or acknowledgement results leave the slot intact and
block another authority operation. An uncertain local commit poisons the live
repository instance so recovery must reopen and inspect the committed old-or-new
state. There is no RAM acknowledgement queue, silent eviction, or default-success
path. The one checkpoint is recovery evidence for the latest terminal authority
operation, not an append-only audit log.

TCP witness messages are authenticated and transcript-bound but are not
encrypted; deployment must provide a network boundary when state metadata is
confidential. The reference server processes one connection at a time with a
five-second I/O timeout. This is an explicit resource bound, but an unauthenticated
slow client can occupy that one slot until the timeout.

The executable IPC face is Unix-only. It binds inside an existing private
directory, requires mode `0700` on that directory, installs mode `0600` on the
socket, authenticates requests under a pinned ML-DSA-65 client key, and rejects
unknown, oversized, truncated, or trailing message bytes. These controls do not
provide code-signing identity or protect against hostile code already holding the
authorized client signing key. Non-Unix targets fail explicitly instead of
claiming an equivalent boundary.

Kernel-level process isolation is deliberately delegated to the service
manager rather than claimed by the binary: [`deploy/`](deploy/README.md)
holds the hardened systemd unit (dedicated locked account, read-only OS
view, seccomp `@system-service` filter, empty capability set, no core
dumps) and the launchd daemon template (dedicated uid, owner-only umask,
no core dumps), together with the exact table of which boundary each layer
enforces and the explicit non-claims. A deployment that starts the binary
outside those templates gets only the daemon's own filesystem-capability
and cryptographic boundaries.

IPC is a hard V2 cut: request, response, and request-digest domains all end in
`/v2`, schema 2 has distinct `AcceptInitiatorFinished` and
`AcceptResponderFinished` commands and role-shaped begin/accept responses, and
there is no V1 decoder or fallback. A consumed IPC nonce is never reusable. If a
successful acceptance response is lost while being written, the client may send
the exact same handle and Finished under a newly signed nonce; while the same
process and retained key remain live, the bounded completed-acceptance cache
returns the same key handle and, for the responder, the same R. Different
Finished bytes fail as a conflicting replay. Destroy, committed transition, or
process restart clears that cache. Neither `AcceptedSessionKeyV1` nor R is
persisted or recovered after a crash; the durable capability-session tombstone
remains, so recovery requires a new authenticated session rather than reuse.

The executable accepts exactly one of these command shapes:

```text
q-periapt-policy-agent serve-agent SERVICE_DIRECTORY REPOSITORY WITNESS_ADDRESS AUTHORITY_ADDRESS CONFIG_DIRECTORY
q-periapt-policy-agent serve-witness LISTEN_ADDRESS WITNESS_DATABASE CONFIG_DIRECTORY
q-periapt-policy-agent migrate-agent-repository-v1-to-v3 REPOSITORY AUTHORITY_DATABASE CONFIG_DIRECTORY
```

`SERVICE_DIRECTORY` is an absolute owner-owned exact-`0700` directory. The
process pins it as its working-directory capability before binding the fixed
`agent.sock` leaf; it does not reinterpret a caller-provided socket pathname.
On macOS, socket isolation is inherited from the revalidated ACL-free parent
capability plus the new fixed leaf and its verified `0600` mode; the service
does not reopen the socket pathname to make a weaker ACL inference.
The directory must also live in a stable, trusted namespace so an untrusted UID
cannot rename an ancestor and substitute a different client-visible pathname.
The dedicated daemon does not restore its working directory. After an abnormal
exit, the service manager must first establish that the old process is gone and
then remove its stale `agent.sock` before restart; the daemon never guesses that
an existing socket is safe to unlink.

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
exclusive instance lease at startup and fails closed while another unexpired
instance holds it.

Reference resource bounds are fail-closed and do not silently evict security
state:

| Resource | Bound |
| --- | ---: |
| Any IPC or witness frame | 16 KiB |
| IPC capability-offer field | 8 KiB, also constrained by the total frame |
| Runtime pending sessions | 256 by default; hard maximum 1024 |
| Runtime confirmed keys / completed-acceptance entries | 256 each by default; hard maximum 1024; one cache entry is retained only with its key |
| Runtime session TTL | 5 minutes by default; hard maximum 24 hours |
| Durable session reservations | 1024 |
| Durable capability replay tombstones | 4096 per committed state |
| Canonical migration history / generation | 4096 |
| Witness operation receipts | 4096 |
| Active durable authority operation | 1 (`Prepared` or `Resolved`) |
| Terminal authority checkpoint | 1, exact latest receipt supersedes the previous checkpoint |
| Authority-server retained receipts | Configured bound; hard maximum 4096 |
| IPC replay nonces | 4096 within a 10-minute window |

Capacity exhaustion is a typed rejection. Pruning, authority rotation, online
configuration replacement, and multi-process horizontal scaling are not
implemented by this reference service and require a separately reviewed
protocol rather than silent eviction or fallback.

This service remains a research/reference boundary. It does not modify the
frozen ABI 2 exports or layouts, and it does not turn local persistence, a mock
witness, a same-process Rust type, or successful ABI 2 execution into proof of
the wider migration formal gates.
