# Account roster authority

`AccountPin::verify_roster` authenticates the complete canonical roster under the
independently provisioned account root, policy family, version and body digest.
Both ML-DSA-65 and canonical P-256 signatures remain mandatory. The existing
maximum of 32 uniquely sorted device IDs and exact device-generation/credential
entries remains unchanged. Empty rosters are valid signed revocation snapshots;
they authorize no device.

`VerifiedRoster::authorize_device` checks trusted time, the credential lifetime,
account/root/family and exact active membership. A newer roster can retain an
existing credential. Removing it, changing its generation or credential digest,
using an older roster, or presenting a same-version different-body roster fails.
`VerifiedDevice::roster` exposes the complete authenticated snapshot used at its
initial admission. Device verification now uses this one roster parser; there is
no parallel weaker decoder or alternate signature path. Wire bytes and authority
binding computation are unchanged.

These values are immutable public snapshots. They do not follow updates, establish
which independently signed head is newest or constitute a freshness lease. The
host must explicitly deliver an independently authenticated update to the journal.

## Journal authority and generation history

`DeviceJournal::install_roster` commits one monotonic head per account through the
existing exact write intent and required-witness reconciliation. Lower versions,
same-version forks and changes of root/family fail. An identical canonical head
is idempotent and retains the original signed bytes. An uncertain storage or
witness outcome closes the journal; reopening reconciles the retained exact target
before new work. `roster_checkpoint` is a read-only reconciliation query.

Provisioning stores the local device's authenticated roster. A new bootstrap can
admit a peer's independently verified first snapshot together with its first
operation reservation. Existing contexts cannot implicitly advance installed
heads. Bootstrap and message records contain canonical account references; prekeys
reference only the local account. Missing heads, duplicate references, mismatched
message/bootstrap references and a pending write that changes the local account
are rejected. This prevents a missing peer head from being treated as fresh
admission for an existing operation.

Each account retains the highest observed generation and credential digest for
every observed device ID, including removed devices. A removed generation cannot
reappear in a higher-version roster; a live generation cannot silently change its
credential. The explicit [same-key renewal](CREDENTIAL_RENEWAL.md) grants the bounded
exception: exact predecessor, same full identity/key and strictly extended validity,
with the original storage owner retained. Key/generation replacement still requires
a higher generation and a distinct journal owner. Limits are 64 account heads and 256 historical device IDs per account, in
addition to the existing 32 active devices per roster and 2 MiB image bound.
Capacity exhaustion fails explicitly without dropping history.

Every bootstrap, prekey, message, cached outbox/plaintext and consumption-ACK
operation checks the installed roster before private use and output release.
Committed revocations block cached `BootstrapContext`/`VerifiedDevice` values after
restart. Read-only status and prekey retirement remain available without granting
dispatch or plaintext authority. Established messages use the installed roster's
lifetime, while credential and policy expiry remain binding. Explicit renewal may
retain a still-enrolled credential. Witness enrollment validity and its later
renewal remain a separate authority transition.

The current unreleased outer journal schema is v21: `continuity_device_candidate_v21`,
`QPVLT021`, `QPVIMG21`. The roster authority fields originated in v19; the current
roster payload admits the bounded QPRHST02/03 renewal extensions described in
[CREDENTIAL_RENEWAL.md](CREDENTIAL_RENEWAL.md#encoding-and-compatibility). It rejects earlier journal schemas without reset or implicit
migration. Network bootstrap/message bytes and SDK ABI major 2 are unchanged.
The image contains `local_account[32]`; each record adds a one-byte authority count
and zero to two sorted account IDs. Roster records use kind 5/phase 20 and
`QPRHST01 || roster_length:u32 || retained_roster || history_count:u16 || history`.
Each sorted history entry is `device_id[16] || generation:u64 || credential[32]`.
The retained roster is `QPROWR01 || account[32] || family[32] || version:u64 ||
body_digest[32] || root_public_key || wire_length:u32 || signed_wire`. Reopening
reauthenticates both signatures and canonical shape; operation admission checks
trusted time.

## Validation and remaining scope

The roster tests cover measured before/after-sync cuts, exact-byte recovery, actual
process termination at intent and committed-image barriers, required-witness
exchange loss, restored snapshots, cached message/bootstrap/ACK denial, prekey
release and retirement, expiry/renewal and replacement generations. Malformed
authenticated fixtures test account-reference and local-account invariants.

Local Rust 1.98.1 release validation passes all 131 candidate tests and strict
all-target Clippy; actual Rust 1.90 checks all targets. The roster transition has
four measured sync barriers (eight before/after faults) and four witness exchanges
(eight request/response-loss cases). Two real child-process termination points
cover durable intent and committed image before API return. Independent OpenSSL
verification also passes the unchanged public identity/bootstrap vectors. These
results establish the tested local paths, not the complete release qualification.

The history covers observed updates; it cannot discover a skipped signed
revocation or establish global latest-head agreement. A local-only database still
cannot detect restoration of an entire earlier database. Required-witness mode
rejects an older client snapshot against the independently protected witness head;
the witness itself remains a separate trust boundary. Fresh DH/PQ ratcheting,
continuous recovery, device lifecycle/fanout and product bindings remain required
for the complete 0.2.0 scope.

The native atomic roster/head witness candidate is specified in
[the witness contract](ANCHOR_WITNESS.md#atomic-roster-and-journal-head-refresh-candidate).
Its prepared state preserves the actual old roster and head, and its commit
updates both together. This avoids treating a standalone witness authority update
as proof that the journal adopted the roster. Store-only checks are complete for
the bounded component. Actual sealed targets and typed historical installation
are exercised in the original journal. The original enrollment now retains R
terminal metadata before ACK/cleanup and admits the same current device owner
under P0 or the retained independent P. See the [enrollment coordination
contract](ENROLLMENT.md#original-enrollment-atomic-roster-coordination).
Native original session and complete two-recipient fanout behavior across R are
now checked under the original enrollment owner. Current root-signed peer
revocation denies cached release; the external revocation/replacement control
plane and real G/T composition remain separate qualification gates. A preexisting split legacy authority state
is still refused; this route does not silently repair or reset that state.

## Current device-service admission of remote rosters

`DeviceService::admit_peer_roster` binds a verified remote-account roster to the
original active installation and its explicitly supplied current session policy.
The account must already be known from an admitted original bootstrap. Its root
and family must match the retained authority; rollback and same-version forks fail.
The local account is rejected here and continues to use its enrollment R transaction.
This entry returns a current target checkpoint, not a session or dispatch permission.

The service verifies its actual current local membership, policy and runtime before
the mutation and after witness I/O. Independent P requires its original completed
enrollment authority; a cached P0 is not a fallback. Even an identical target needs
fresh witness/current authority and keeps the first canonical stored bytes without
rewriting the journal. An empty independently signed remote roster is a valid
revocation update; it prevents subsequent cached message or fanout release.

The account authority and canonical target checkpoint identify this public head
update. This is monotonic signed-state installation, not a new terminal/ACK protocol.
Retain the original verified target when a call fails. Existing ordinary QPWINT01
write intent and witness-head recovery preserve the actual sealed image across an
unknown Advance result. Reopen the same owner and retry with current authorization;
do not reset state or manufacture a replacement operation. Error may follow commit,
including a failed final authorization query after the target is already installed.
Success reports that the target is currently present, not which attempt first wrote
it. A later installed head rejects the old retry without claiming historical no-commit.

The native tests cover both local-only and required-witness owners. Local-only
coverage includes both original session roles and independent P after P0 expiry,
with and without real credential renewal. Required coverage includes P0 and
independent P/local R owners, policy and local-credential expiry, closed runtime,
runtime closure during a signed reply,
unknown and processed Advance loss, a post-commit admission failure and measured
before/after-sync faults. Existing original-session, two-recipient fanout, changed
recipient accounting and cached-revocation tests now admit remote updates through
this service entry. They use the same native engine. C/Swift/Kotlin bindings, real
transport integration, installed packages, additional process cuts, real G/T
composition and the external root/issuer decision service remain separate gates.
