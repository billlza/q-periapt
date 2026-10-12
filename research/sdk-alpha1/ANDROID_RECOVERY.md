# Android recovery and host accounting

The unpublished Android Continuity adapter uses `ContinuityRecovery` to finish
accounting for an original installation after operational access is unavailable.
It cannot send messages, export keys, create an installation or become an
operational device. Close existing owners before opening recovery. All I/O calls
are synchronous and belong on a worker thread.

Open with `ContinuityRecovery.prepare(originalPath, originalWitness)`, call
`finishOpen`, then select the original `Ids.AccountOperation` or `Ids.Session`.
Use an explicit `RecoveryWitness.local()`, `signedTcp(endpoint, timeoutMs)` or
`mutualTls(endpoint, timeoutMs)` consistent with the installation's protection.
The endpoint only supplies transport: the engine loads the original protected
witness pin and credentials. Local mode cannot bypass a required witness. A
failed native selection requires closing and reopening the original owner.

## Reserved account operations

Call `beginAccountCleanupReport()` after selecting the original account operation.
It freezes the entire reserved batch and returns one immutable `CleanupReports.Account`
containing every original member, reservation, epoch, unconfirmed message,
pending delivery and skipped position. A failure can follow a durable freeze;
the method never returns a partial report or acknowledges it automatically.
Retain the same operation and retry against the same installation.

Commit the complete report, original operation and report IDs, and any host
accounting decisions in a durable, deduplicated application transaction. Only
after that transaction succeeds, call `acknowledgeAccount(report.header().report())`.
Finally, `retireAccount()` removes the aggregate's retained history according to
the native contract. A crash or missing reply at either step requires observing
the same original operation; it does not authorize a replacement operation.

The SDK deliberately does not supply a pretend database transaction for the
application's business state. A report ID alone is not complete loss accounting.
Skipped positions do not prove that a peer sent messages, and local accounting
does not prove remote business effects were consumed.

## Committed account operations

Use `reconcileAccount()` to read all original member results. The member states
distinguish acknowledged consumption, still committed work, pending resolution,
unknown delivery, retired history and abandoned reservations. A committed batch
cannot be converted to reserved abandonment with `beginAccountCleanupReport()`.

Retain and handle every original member result before retirement. A member with
an unknown result must stay unknown in host accounting; it cannot be relabelled
acknowledged to permit retirement. The engine enforces settlement of all original
members and keeps original session/bootstrap records and counters intact.

## Session closure and catalogue recovery

For an original session, `beginSessionCleanupReport()` freezes it and returns the
complete immutable report. Persist all fields and its `Ids.ClosureReport` before
`acknowledgeSession`. Both complete-report methods remain readable from their
cached native reports after cancellation, but cancellation does not grant
permission to perform acknowledgement or retirement.

Retain `archive()` before `retireSession(reportId)` if the application needs
future catalogue restoration. The 362-byte authenticated archive can be passed
to `selectArchive` on a fresh recovery owner, then `restoreSessionIndex()`.
This restores catalogue metadata; it restores neither keys nor permission to
send. Retirement and logical deletion do not establish physical or cryptographic
erasure of backups, retained pages or wrapping keys.

`sessionCount()` and `sessionAt()` are discovery hints. Selection authenticates
the actual original state. Never rebuild a missing installation or replace trust
material merely because discovery, networking or a status call failed.

## Validation scope

The [recovery checkpoint](evidence/20261012-android-recovery/README.md) records
Debug/Release host Java/JNI process validation, native report comparisons and
rejection controls. The first-use lane starts with a Java-created installation;
the required-witness lane uses C registration and operational traffic with Java
recovery. These share the native protocol engine and do not constitute independent
implementations. Physical Android acceptance retains its previously recorded
single-phone scope; this checkpoint does not claim a new ART/AAR run.
