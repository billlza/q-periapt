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
MSRV 1.85, and licensed `MIT OR Apache-2.0`. It is deliberately not treated as a
rollback anchor: restoring the whole database file restores all of its history.
Every open, transition, and key release therefore requires an authenticated
external `WitnessPort`. There is no local-only fallback.

Both durable files must live in a real owner-only (`0700`) service directory
and remain owner-only (`0600`) files. Symlinks are rejected. The protected
parent directory is the race-control boundary. `redb` also holds an exclusive
database lock, so a second policy-agent process cannot open the same repository;
that lock is part of the cross-process linearization boundary around witness
rechecks and local commits.

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
confirmation rechecks the exact repository and witness head/fence, so a session
from the old head cannot be accepted. A process-boundary test exits immediately
after durable intent without running destructors, then reopens and reconciles
the same operation. This is crash-protocol evidence, not evidence for a specific
filesystem, storage controller, or whole-machine power-loss guarantee.

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

The executable accepts exactly one of these command shapes:

```text
q-periapt-policy-agent serve-agent SOCKET REPOSITORY WITNESS_ADDRESS CONFIG_DIRECTORY
q-periapt-policy-agent serve-witness LISTEN_ADDRESS WITNESS_DATABASE CONFIG_DIRECTORY
```

It opens existing stores only. Controlled bootstrap must explicitly call
`StateRepository::provision_new` and `ReferenceWitnessServer::provision`; a
missing store is never provisioned by the runtime. Configuration files are
fixed-name, exact-length owner-only files under the validated `0700` directory.
They include separate migration/recovery roots, local/peer endpoint identities,
signed execution/local/peer policy bundles, IPC request/response keys, and
witness request/response keys. Secret-key files are read directly into
zeroizing buffers.

Reference resource bounds are fail-closed and do not silently evict security
state:

| Resource | Bound |
| --- | ---: |
| Any IPC or witness frame | 16 KiB |
| IPC capability-offer field | 8 KiB, also constrained by the total frame |
| Runtime pending sessions / confirmed keys | 256 each by default; hard maximum 1024 |
| Runtime session TTL | 5 minutes by default; hard maximum 24 hours |
| Durable session reservations | 1024 |
| Durable capability replay tombstones | 4096 per committed state |
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
