# Durable native session archive index

Status: unpublished native candidate. `SessionArchiveStore` persists QPCSCA01
cleanup archives for the actual QPCNET01 reference connection. The `Actor` now
requires a mutable index owner in addition to its journal, verified context and
signer. This is a local service prerequisite; it does not add a wire attestation
of the remote host's filesystem or publish a language binding.

## Provisioning and order

Provision the index explicitly with the independently retained JournalIdentity.
On restart, use `open` with the same pin. Missing, invalid, wrong-journal, busy or
nonprivate paths fail; they never create an empty replacement. The existing shared
private-file/database capability provides the owner-only inode, pinned parent,
nonblocking lifetime lock, size bound and two-phase recovery checks. The index owns
no wrapping or signing keys. Its rows are public archive metadata with their own
MACs, not private session state.

`establish` and `serve` enforce the following order:

1. Validate endpoint/options/current authority and the index's journal identity.
2. Use the existing bootstrap transactions to obtain the exact committed session ID.
3. Prepare its cleanup archive and authenticate it through the active journal's
   wrapping-key owner. Commit the immutable archive/index row with immediate
   two-phase durability, and read it back exactly.
4. Recheck cancellation, the original deadline and current authority.
5. Activate message state through the original journal transaction. The initiator
   requires its own archive before sending the final flight; the responder requires
   its archive before activation and READY. The initiator activates only after the
   matching response, as before.

The two databases are intentionally ordered by an immutable prerequisite. There is
no compensating deletion, cross-store rollback, nonce refund or new handshake ID.
A crash after archive commit but before activation leaves harmless public metadata;
a crash after activation retains its cleanup input. An uncertain index commit stops
this invocation and closes the index owner. Reopen it and retry the same archive:
actual readback may prove the original bytes or genuine absence. Exact duplicates
need no new write, even at the 128-record capacity. Changed bytes conflict.

Before each client application submission and each server application delivery,
the connection verifies the stored archive's MAC, original context, session, owner
and storage protection through the live journal. Missing or changed metadata stops
work before a client send reservation or a server inbox/application effect. If the
client already committed its outbox before discovering a peer-side archive failure,
that exact outbox stays uncertain; no consumption is invented. Explicit restoration
of the original metadata permits retry of the same message.

`Error::Archive` distinguishes index persistence/authentication from network failure,
peer consumption and journal activation. It is not an automatically retried network
error. A remote endpoint that cannot dispatch its response leaves the other peer
with an uncertain network outcome, not a transmitted proof of local absence.
Synchronous filesystem calls remain cooperative cancellation/deadline boundaries.
The post-archive check prevents further activation after such a boundary is crossed;
it does not promise to preempt a blocked operating-system call.

## Schema and admission

The separate redb database has exactly one table named
`continuity_session_archives_v1`, with fixed 32-byte keys and byte-string values.
The reserved zero[32] key contains `QPCSIX01[8] || journal_id[32]`. Every other key is
a nonzero exact session ID and contains one canonical 362-byte QPCSCA01 archive. Opening validates all rows;
the application data path then reads only its indexed row in a fresh read transaction,
without scanning/copying all archives or retaining a stale pre-lock cache.
At most 128 archives plus the header are accepted. Unknown tables, wrong header,
excess capacity, invalid archive grammar or index/archive scope disagreement fail.
There is no implicit migration, record replacement or automatic retirement.

Opening the public index does not authenticate every MAC or grant cleanup authority.
`retain` authenticates its input with the owning journal before writing; actual
message use verifies the retained MAC again. Cleanup uses the restricted
SessionClosureJournal opener with the independent journal ID and wrapping key.
A canonically parsed public archive is not a VerifiedDevice or BootstrapContext.
The 128-entry index is bounded; unused prepared entries still consume capacity.
Explicit retirement of independently closed sessions is described below; prepared
but unadmitted sessions and aggregate abandonment require their separate lifecycle.

The index has no independent anti-rollback witness. Loss or rollback may remove
archive discovery and block the service; it cannot rewind the journal's message,
nonce, roster or witness state. Restoring archival metadata still requires the
correct MAC and the original authenticated session in the current protected journal.
A required-witness session never obtains local-only cleanup permission from this
index. Historical copies and hostile wrapping-key possession remain outside the
logical-erasure and trusted-host guarantees.

## Discovery, exact restoration and terminal retirement

`session_ids` enumerates the bounded index in sorted order through a fresh,
schema-checked read. These public IDs are discovery hints; neither the listing
nor parsing an archive authenticates its MAC, proves that a session exists or
grants an operating owner. A corrupt index is an error, never an empty catalogue.

If original operational context objects are unavailable, open a
`SessionClosureJournal` from the independently retained journal ID, original
wrapping key and backed-up QPCSCA01 archive. Required-witness storage still needs
its original pinned witness and signer. `SessionArchiveStore::restore` then uses
that restricted owner to validate the existing session and fresh witness head,
reconstruct the exact original public archive, and run the same immutable index
transaction as normal retention. Existing equal bytes are idempotent, including
at capacity; conflicting bytes cannot be overwritten. No context, device or policy
is fabricated from the backup. Missing journal state is never replaced or created.
Loss of both the index and its independent archive backup remains an availability
failure; enumeration cannot discover a record no longer retained anywhere.

`retire_closed` requires that same restricted owner and the exact independently
retained host loss-report ID. The protected session must be `Closed(report)`;
`Open`, pending accounting, another report and aggregate abandonment are refused.
Only a byte-identical index row can be deleted. The method returns true after a
durable removal and readback, or false after a successful authoritative absence
lookup. Both outcomes require fresh original-witness checks, including an
already-retired repeat. Journal terminal records, prekey claims, send budgets,
operation IDs and journal capacity are unchanged. No message authority or slot is
restored by retiring or later restoring the public archive.

Storage errors close the index owner; reopen the exact file and repeat the same
restore or terminal report. An unknown commit may have retained or removed the
row, which only readback resolves. A witness failure closes the cleanup owner
without mutating the index. Ordinary recovery never substitutes local-only
admission. The index has no new rollback witness and remains public metadata,
separate from the protected journal and host's full accounting records.

Native tests cover both bootstrap roles, conflicting MACs and journal pins,
closed owners, pending/wrong accounting, all measured before/after sync cuts for
restore and retirement, and witness failures before/after every query for present
and absent rows. Separate processes restore, retire and reconcile absence without
constructing policy/device/context objects; independent journal readback preserves
the exact terminal digest and unknown-delivery disposition. Installed SDK service
initialization, aggregate history retirement and device/root lifecycle remain open.

## Reference recovery and qualification

The actual native reference path now bootstraps, performs three network rekeys,
confirms both application directions with independent disk readback, closes the
original policy owners, and launches separate cleanup processes for both endpoints.
Each process reads its indexed archive and original private wrapping-key file,
without constructing a fixture, policy, verified device or BootstrapContext. It
persists the complete host loss report before terminal acknowledgement. Separate
readback confirms both final terminal identities.

Focused index tests exercise exact idempotence, capacity, wrong identity, busy and
symlink paths, valid-MAC conflicting context, wrong index keys, and all four
before/after faults at two measured storage barriers. Outcomes are classified from
reopened storage, not from the injected cut number. The TLS tests independently
measure two archive barriers on each endpoint and inject all eight corresponding
before/after faults. Neither side reports activation before the failed archive
operation is reconciled under its original session.

Actual client and server process kills observe the committed archive before
activation, alongside the five previous connection kill stages. Server-cut contenders check both journal and index leases; the client-cut
observer also confirms that the index is Busy. Cancellation and an elapsed
absolute deadline immediately after the real archive commit both prevent activation.
Missing and MAC-modified archives block client mutations and server inbox/effects;
a peer-side failure preserves the original committed sender outbox for explicit
metadata restoration and exact retry.

These are native same-host processes and actual files/TLS sockets. They do not
qualify installed foreign-language packages, an independent implementation or
cross-host/current physical devices. Aggregate history retirement, installed
catalogue recovery flows, witness enrollment renewal and device/root replacement
remain separate lifecycle work. Source-bound full suite
results and broader release requirements are recorded in the release ledger.


## Source-bound local result

The final native Debug and Release suites each pass 225 tests, zero failed or
ignored, in 618.479/608.068 runner seconds under overlapping load. The focused
connection run passes 13 tests in 32.224 runner seconds; the separate two-test index
run passes in 9.109 seconds. All 223 Rust source files are retained with the exact
suite snapshot. Both test executables and their hashes are retained separately.
These times include build/qualification work and are not performance measurements.

Rust 1.90/1.98.1 strict all-target/all-feature Clippy, both independent carrier
features and no-default Clippy on each compiler, warning-strict docs, formatting
and 45 clean source/isolation checks pass. Existing disclosure experiments still
recover 12 future messages; this persistence change does not establish a recovery
point. Final explanatory text and the separately tested CI audit move occur after
the complete suites, without changing Rust source.


## Aggregate cleanup admission

`FanoutAbandonmentJournal` uses this same persisted index to authenticate every
member of a whole reserved batch before any saved intent can be reconciled. It
requires no reconstructed policy/context and does not accept a caller-selected
subset. Missing member metadata is `ArchiveRequired`, distinct from an absent
batch. See [archived whole-batch cleanup](FANOUT_ABANDONMENT.md#archived-whole-batch-cleanup)
for the host accounting, witness and metadata-retirement contract.

The exact schema check covers ordinary and multimap table namespaces on open and
every fresh indexed lookup. An unexpected multimap table is corrupt storage, never
an empty index or a missing archive. The rejection regression records the old
opener accepting that unsupported schema and verifies both corrected boundaries.
