# Independent local credential renewal

`peer.local_renewal.LocalRenewal` coordinates one original session's same-key
credential extension under its original required-witness policy. It does not
return an active traffic owner. The host supplies the genuine original root's
renewal grant, its original operation ID, an independently trusted target roster
checkpoint, the original private store/scope/key and the original device signer.
The grant must bind the exact previous credential/roster, full key, identity,
policy and successor. No replacement identity or policy is inferred from it.

Close the normal session before opening this coordinator; the directory lease
allows one owner. `prepare(grant, checkpoint, now)` persists one exact sealed
target and returns its public `QPCRNP01` proposal. The independent authority must
approve that proposal against its independently verified grant and current
policy. The native fixture's command 34 exercises the real `AnchorStore`
preparation method; that test command is not a deployed enrollment service.

`status()` distinguishes Prepared, Applied, Closed and Unavailable.
`commit(now)` may issue a new Commit only while the target credential, roster
and policy are current. `recover()` reconciles Applied or Closed without issuing
a new Commit. `close_proposal()` closes an actually prepared original proposal;
Unavailable alone cannot authorize local cancellation or target deletion. The
independent authority can explicitly close an unprepared proposal using the
original historical grant. Neither an exception nor a missing response means
that the remote transaction did not commit.

After a missing Commit/Close/ACK reply or process termination, reopen the same
directory with the same scope, protection key and original operation. Query and
recover that operation. Do not generate a replacement operation or delete the
state. A semantic re-signing of the same grant preserves the first target bytes.
Historical cleanup may finish after policy expiry; it grants no traffic output.
After Applied cleanup, close the coordinator and open `WitnessSession` with the
original bootstrap inputs. Its derived current local authority comes from the
authenticated image, and the witness must authorize that current authority.

## Durable ordering

The original `QPREFW01` subject, signing key, wrapping-key domain, bootstrap
transcript, session keys and outbox identities remain fixed. Only a genuinely
renewed local identity selects inner format `QPREFS06`; ordinary new sessions and
explicit generic upgrades remain version five. Versions one through five keep
their previous encoding. Version six adds the same canonical identity-state
encoding used for peer metadata, directly after the optional peer metadata. It
requires an established session and a retained original-root renewal grant.
Older encoders refuse the local authority rather than omitting it. Both local and
peer metadata count against the business allowance, preserving control headroom;
maximum combined metadata adoption still needs its own capacity qualification.

The authenticated `authority` file binds the original scope, current statement,
retired successor floor, and at most one retained proposal/checkpoint. Its six
phases are initial, pending, terminal Applied, terminal Closed, completed Applied
and completed Closed. `QPRFLI01` binds the exact proposal and original sealed
target. Normal session recovery refuses this typed intent; only its coordinator
can reconcile it. Missing or inconsistent control for version-six state is an
error, not a request to reconstruct authority from caller inputs.

Applied installs the exact target before recording a terminal. Closed preserves
the original image. Both verify the actual witness head, then durably write and
read back the terminal before sending ACK. Only after ACK does cleanup remove
the matching intent and mark the control completed. An authenticated local
terminal remains usable when remote Status has been pruned to Unavailable.
The actual witness retains the exact ACK disposition at its permanent floor,
so ACK retries in the observed profile return Acknowledged. Fixed staging slots
for each control phase and the target head allow repeated interrupted recovery
without allocating another staging file each time. Conflicting staged bytes are
refused and retained. A coordinator rejects reentrant transactions; reentrant
close cancels result release while preserving committed state.

## Limits and qualification

`local_renewal_checks.py` runs the genuine required-witness provider, fresh
independent owner processes, lost replies, repeated staging cuts, two grants,
same-session traffic/rekey, explicit closes and policy-expired cleanup. Signed
test times are 210/310/401; the native traffic counterpart retains time 170. This
qualifies independent adoption, not the native peer's local enrollment renewal.
The ordinary pending-write profile preserves a preexisting undispatched write
after its original authority expires. Renewal refuses to overwrite that work;
this documented availability gap is not solved by the joint renewal interface.

Only the latest coordinator receipt is retained after completion; starting a
later renewal does not provide an unbounded historical operation ledger. This
increment does not provide local-only renewal, same-account joint coordination,
policy/witness replacement, device replacement, a separately deployed authority,
installed-package qualification, whole-witness rollback protection, physical
erasure, hardware power-loss qualification or construction-wide PCS analysis.
The Python/provider memory limitations in `README.md` still apply.

The journal's internal opening factory transfers its already recovered,
authenticated snapshot directly into session construction. The constructor
still validates the local control record and closes on failure. It neither
retains that snapshot as a cache nor treats it as permission to release output;
each operation keeps its own fresh reads and current-authority/release checks.
The real opening probe now performs one signed Query instead of three, removing
two duplicate exchanges and 14,682 framed protocol bytes. This is request/byte
accounting, not a latency or energy measurement. Plain journal `create/open`
continue returning only a journal; the snapshot transfer is an internal factory
contract, not an import or reopening input accepted from a caller.
