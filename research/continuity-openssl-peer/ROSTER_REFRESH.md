# Independent common-account roster maintenance

Borrow `registration.roster_refresh(operation, now, transport=...)` after closing
the ordinary session. The original registration retains its signer, key, session
path and lease. Local-only owners call `refresh(roster, checkpoint, now)`.
Required-witness owners call `prepare`, obtain independent approval for the exact
returned proposal, then call `commit(now)`. After an unknown required-witness
result, reopen the same operation and call `status()` or `recover()`; never create
another journal. Local-only reopening reconciles its ordinary exact intent before
`status()` reports the retained result.
`close_proposal()` explicitly closes a prepared required-witness target.

This owner changes membership under the original independently verified policy.
It cannot issue a credential, change a same-generation credential without its
grant, revive a removed generation, replace the root, or adopt a new policy or
witness. Credential changes still use the complete-account G coordinator.
Normal traffic continues to enforce the current policy, credential and roster.
Historical cleanup after expiry returns an outcome, not a traffic owner.

## Exact transaction and storage

The native-compatible `QPRWNP01` proposal is 417 bytes. It binds the original
witness/subject, operation, previous and target roster checkpoints, original policy,
and exact expected/target journal heads. Device-signed commands 16–19 perform
Commit, Status, Close and ACK. A device proposal never grants its own approval.

`QPREFS10` keeps the unchanged version-five business image and common account.
`QPRFAT02` adds one 185-byte original R scope and framing to the existing account
renewal record: 193 bytes beyond version nine's coordination limit. This allowance
cannot fund additional business messages. Formats five and nine retain their own
limits and tags; readers cannot reinterpret the new scope under an older tag.

Required-witness R uses a distinct `QPRFRI01` authenticated intent. Its first
sealed target is retained across preparation retries, lost replies and process
interruption. `QPRFLC03` wraps the existing G control with a 475-byte `QPRFRC01`
R control, preserving the active G collection and its signed statements. G and R
cannot share a pending slot. Either coordinator's retired target version prevents
reuse by a later coordinator. A Closed R advances the retirement floor while
leaving the installed roster and business image unchanged.

The latest coordinator and the one active R receipt are bounded separate facts.
After a later R is Pending or Closed, the original active operation remains
observable as Applied. Reading or recovering that old result cannot commit,
close, ACK or remove the later operation. This is not an unbounded history ledger.

The terminal sequence is shared with G: install the exact Applied image (or
retain the Closed predecessor), confirm the witness head, persist the terminal,
ACK, remove the original intent, and mark completion. Interruption returns an
error and retains recoverable state. No cleanup step creates a fresh target.

## Validation boundaries

`roster_refresh_checks.py` exercises three- and 32-member original registered
accounts in local and required-witness modes. Both endpoints advance explicit
trusted test time through G/G/R/G. The Rust counterpart starts with a public
`DeviceEnrollment`, retains its original archive, renews through public APIs,
and reopens the original session using the independently retained live policy
and original bootstrap bundle. It does not reconstruct live permission from a
historical policy alone. The independent endpoint preserves its original outbox
and unfinished PQ contribution across R interruption and expired cleanup.

`roster_boundary_checks.py` exercises R before G, exact retry, unknown approval,
overlapping work, changed/stale inputs, Closed retirement and control corruption.
Each driver writes source/provider/binary identities before execution, checks
them again at completion and retains failed private installations separately
from public artifacts. A launched driver without its terminal result is not a
qualification result.

These are bounded independent-reference checks using explicit validity times.
They do not establish wall-clock device expiry, power-loss durability, physical
erasure, a deployed authority, construction-wide PCS, foreign-language parity,
or full release admission. Independent policy and witness replacement, device
replacement, fanout and the remaining migration work stay separate requirements.
