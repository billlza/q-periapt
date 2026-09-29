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
which independently signed head is newest, advance journal state or constitute a
freshness lease. Calling `authorize_device` outside the journal transaction cannot
revoke a previously admitted message operation. The durable fence is not yet
implemented.

## Required journal integration

The device journal must own one monotonic roster head per admitted account, bound
to its authenticated root and policy family. Initial independently verified pins
must be persisted before secret operations can release output. A signed update
must reject lower versions and same-version forks and commit through the existing
exact write intent and required-witness reconciliation. An uncertain outcome must
close new work until reopening reconciles that same update. Identical canonical
heads must be idempotent without replacing retained bytes.

Every bootstrap, prekey, message, cached outbox/plaintext and consumption-ACK
release must recheck the installed roster. A committed revocation must block old
`BootstrapContext`/`VerifiedDevice` instances and survive restart. Read-only
operation-status queries can remain available for reconciliation without granting
new dispatch or plaintext authority. A still-enrolled credential must be checked
against the installed roster's lifetime; its own credential expiry remains
binding. Witness enrollment validity and its later renewal require a corresponding
explicit authority transition.

Verification must cover exact post-revocation replay attempts, replacement device
generations, unrevoked peers, expiry, stale and forked updates, every update sync
cut, actual process loss, required-witness outage/unknown outcomes, and restored
snapshots. This prerequisite is part of the complete 0.2.0 revocation and rekey
work, not its completion. Fresh DH/PQ ratcheting, continuous recovery, device
lifecycle/fanout and product bindings remain required.
