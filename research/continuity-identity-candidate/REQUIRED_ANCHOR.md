# Required witness policy and journal

This isolated candidate connects the existing authenticated witness to the actual
device journal. The SDK ABI remains major 2, extension 1 (43 C exports, 26 JNI
registrations); published SDK packages do not depend on this candidate.

## Authority and provisioning

The dual-signed `QPSESP02` session policy explicitly chooses local persistence or
requires one exact witness identity/public-key binding. Its digest enters the
bootstrap context. A required journal additionally seals that policy digest,
witness binding and writer fence into every version-7 image. These fields cannot
change in a saved write intent. A local journal cannot accept a required policy;
a required journal cannot accept a replacement/downgraded policy.

`provision_anchored` creates an inactive empty journal. Its authenticated genesis
must be enrolled explicitly with independently verified device and policy pins.
`activate_anchor` consumes a device signing owner and pinned client, querying the
exact enrolled genesis. `open_anchored` validates journal identity, policy, signer
and witness before reconciliation. The ordinary `open` rejects required images
before applying even a valid pending intent. No enrollment, witness replacement,
policy migration or writer-fence renewal is inferred from a failed query.

The witness signing components must differ from the device, account root, protocol
authority and SDK policy root. Queries allow reconciliation after expiry; new
cryptographic work still uses the existing live policy/runtime/time admissions.
The public volatile initiator/responder APIs reject required policies.

## Transaction and release order

1. Load and authenticate the local image, then send a newly challenged witness
   query. Require its complete `(fence, revision, ciphertext_digest)` to match.
2. Seal the next image once and persist the authenticated `QPWINT01` intent using
   the existing immediate two-phase transaction.
3. Derive `Advance(expected_head, exact_target_digest)` from that intent. The
   command identity is deterministic across attempts; each signed attempt has
   a new unpredictable challenge.
4. Require `Advanced` or `AlreadyAppliedExact` for this exact command and next
   head. Only then atomically install the saved ciphertext and remove the intent.
5. Query again before continuing. Recheck at initial/reply/final/prekey release,
   including cached replay paths. Failure closes the journal and withholds output.

After a lost response, reopening sends the same advance derived from the saved
intent. If the witness committed, only its matching last-command receipt permits
application. Exact last-command confirmation is read-only and remains available
after authority expiry; an unperformed advance still requires current authority.
A fork, later head, changed fence, different policy or stale challenge
fails. After local application with a lost acknowledgement, a fresh query admits
the existing exact image without another logical advance. The journal never adopts
a higher writer fence automatically. Queries are individual freshness admission
points, not leases that prevent a later concurrent revocation.

## Byte carrier and deadlines

`AnchorClient` owns the device signer, witness pin and transport. It verifies the
complete signed response independently of transport bytes, with a finite nonzero
budget of at most 60 seconds. It checks the deadline after exchange and verification.
`AnchorTcpTransport` uses one configured socket address and one connection per
attempt, with a four-byte big-endian length prefix. Requests are exactly 3674 bytes
and replies 3659 bytes; oversized/truncated replies fail. Partial reads/writes use
the remaining absolute budget, so a trickling peer cannot reset the deadline.
Custom transports must honor the deadline contract; the synchronous trait cannot
preempt arbitrary application code. Errors retain an unknown command outcome.

This carrier authenticates through the existing dual signatures and exposes public
metadata to its network path. Encrypted transport deployment, asynchronous
cancellation and service operation remain separate work.

## Validation and scope

Tests use the actual signing, SDK KEM, encrypted redb journals and witness provider.
They cover both handshake roles through completion/reopen, required-policy bypass
attempts, inactive prekey owners, inventory publication/retirement, captured replies,
wrong witness identity, restored old client databases and external writer fencing.
Every one of the initial path's 12 communication positions is interrupted before
delivery and after witness processing. Pending ciphertext is compared byte-for-byte
after recovery. The four sync points in an intent/state pair are interrupted before
and after synchronization. A loopback TCP endpoint exercises actual signed replies,
oversized frames, truncation and a total-deadline trickle.

The witness must retain its own monotonic state independently of client backups.
The existing whole-witness rollback counterexample remains valid. This is not a
hardware anti-rollback guarantee, a Byzantine consistency proof or evidence of a
separate-host deployment. Durable authority renewal/revocation, full cancellation,
delivery acknowledgements, ratchets and multi-device coordination remain part of
the full 0.2.0 work; this checkpoint does not complete that lifecycle.
