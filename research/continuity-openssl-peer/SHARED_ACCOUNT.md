# Independent common-account credential renewal

An original registered session whose two devices share an account keeps one
authenticated roster. Local-only renewal uses
`stage_account(local_grant, companion_grants, target_checkpoint, now)`;
required-witness renewal uses `prepare_account` with the same arguments.
These are methods on the original registration owner's borrowed credential
coordinator. Close the normal session before borrowing the coordinator.
Neither method returns a traffic owner or changes the original device key.

The original root must authorize every same-generation credential change in the
target roster. The request contains one local grant and up to 31 companion
grants, all with the same predecessor, target and policy. Local verification
still requires the exact original installation credential. Verifying a companion
does not transfer that device's local ownership. Both established roles project
their current authority from the same account record.

Request identity includes the local and companion signed statements and operation
IDs, sorted by device identity. Reordering or re-signing an identical decision
retains the first saved bytes and exact sealed target. Replacing any companion
decision is refused, including after completion or witness ACK cleanup.
The collection hash is local coordination identity, not a substitute for a root
signature or a witness statement.

## Storage and recovery

`QPREFS09` wraps a canonical version-five business payload, a common account
record and an `AccountRecord` in three u32-length-prefixed fields. The unchanged
business payload retains its two-MiB bound and control reservation. The common
account is bounded by two MiB and 256 retained device histories; the coordination
allocation is bounded by one complete 32-grant request plus 400 bytes. Additional
metadata capacity cannot fund business sends. The 64-MiB directory quota and
128-file bound remain. Formats one through eight retain their own encoding and
size checks; a new envelope cannot be admitted under an older tag.

Local-only stage preflights both Pending and completed representations. The
common account and outcome commit in one exact-target journal transaction.
Pending and ExpiredUncommitted deny ordinary session admission. Expiry uses the
earliest target credential or roster in the complete collection, and records the
actual retained predecessor and journal revision/digest. An existing Committed
result stays historical Committed after expiry and grants no current permission.
A different request after abandonment must name the retained predecessor and
respect the durable time floor.

Required-witness preparation seals a completed account image and returns the
original local grant's `QPCRNP01` proposal. Its exact target digest binds the
complete account image. The independent authority still approves the genuine
local root grant and exact proposal. A local collection hash never replaces that
authorization. Missing replies leave the result unknown until the original
transaction is queried and reconciled.

Conditional `QPRFLC02` extends the authenticated control with two 32-byte fields:
the selected request's collection binding and the currently active collection
binding. Closing a second request retains its identity while preserving the
first request's active authorization. Applied adopts the selected binding.
Both bindings survive intent removal and ACK cleanup. Version-one control
records remain readable with their original byte representation.

Reopen the same registration, key, session and original operation after a
failure. Recovery publishes the first sealed target; it does not reseal or
invent a new operation. Historical Applied/Closed cleanup does not authorize a
new Commit or ordinary output under expired authority.

## Evidence and remaining scope

`shared_account_checks.py` exercises actual registered owners with three and 32
members, two complete renewals, exact sealed-target recovery, changed companion
refusal, reserved sends, old ciphertext, rekey and real process kills.
`witness_account_checks.py` exercises the same group sizes with Applied and
Closed outcomes, independent native witness approval, a dropped Commit reply,
terminal-write interruption, witness-store reopening and post-ACK retries.
The model controls in `account_state_checks.py` separately cover root-signed
resurrection, generation rollback and incomplete collections.
`account_boundary_checks.py` observes the first companion's expiry at 275 while
the local credential remains valid until 300, rejects a successor that assumes
the abandoned target committed, and resumes the original installation using a
fresh grant from the retained predecessor. A second profile fills all 2,031,616
business bytes with 123 actual outbox rows. Two 32-device renewals preserve the
encoded epoch records and ciphertexts; the second Pending image is 4,030,189
bytes. Further business sends still fail. Callback cancellation, malformed
envelopes and completion bindings have separate refusal controls.

These fixtures use explicit validity-test times in the independent consumer;
the native traffic peer and witness use time 170. They do not establish
simultaneous real-time expiry and renewal of both native enrollments. Peer-only
common-account roster transitions remain refused until they have a proper
common authority and witness transition. Ordinary pending-write recovery uses
the [single common public-history projection](PENDING_WRITE_RECOVERY.md), with
independent exact approval and fresh Query confirmation before publication.
Compatibility with an actual archived version-five common-account
writer still needs its own migration run; the unchanged separate-account
version-seven migration is covered by its existing regression.
Policy/root/witness replacement,
account fanout and complete product admission remain separate requirements.
The reference Python/provider memory limitations still apply.
