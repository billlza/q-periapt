# Retained account authority and root cutover

This optional reference host connects authenticated account decisions to the
existing native `AccountAuthorityStore` and witness root protocol. The SDK does
not require this host, Passkeys or HTTP. Root selection is separate from live
device/session admission and from post-compromise confidentiality.

## Upgrade and original trust

Stop the original server, back up its retained state, and run
`enable-account-authorities <absolute-database-path> <original-origin>` after
the schema-9 root-successor upgrade. This explicitly upgrades schema 9 to 10.
Opening an old store never upgrades or recreates it implicitly. The new tables
retain original authority associations, root-cutover intents and retired issuer
history. Existing accounts, enrollment records and signing files are preserved.

Authenticate as the original account and submit `AssociationRequest`: a nonzero
caller-retained request ID, an original host-issued enrollment, the exact current
root revision/account and roster checkpoint, and an independently selected
signed required-witness policy. The host verifies the policy under its configured
family and verifies the historical credential under that original issuer.
Replacement inputs cannot choose this witness. Historical credential or policy
expiry does not invalidate the association's root-identification purpose.
Neither historical input grants traffic permission. This initial association
currently requires an issued device and roster; empty/unissued-root recovery is
not implemented by this path.

Each account retains its own native authority registry identity and wrapping
file. Initialization persists first-use phases before provisioning and can resume
the same original files after interruption. Once admitted, missing registry or
wrapping files produce `AuthorityUnavailable`; they are never recreated. The
host root stores its registry identity, so a missing association cannot silently
fall back to an unassociated issuer. Fresh enrollment, replacement, same-key
extension, G grants and P approvals retain the original registry owner and check
the current root admission. Historical exact results remain readable.

## Approve and commit one target

1. Prepare a separate [candidate root and enrollment](ROOT_PREPARATION.md).
   The device accepts its issued credential and prepares its original installation
   journal. Keep its signing and wrapping files and the exact prepared genesis.
2. Independently approve the original root, witness, successor certificate/roster,
   signed policy, journal identity and prepared head. Use the local witness
   `root-plan` command to obtain the original plan before freezing.
3. Submit `CutoverRequest`: candidate preparation/enrollment IDs, exact candidate
   roster checkpoint, journal/head, signed policy, original plan and device
   preparation. The host reconstructs issuer/certificate trust from its own
   retained candidate. It verifies the complete plan and the original witness
   requirement, and rejects policy rollback below the associated policy floor.
4. Approval atomically locks that candidate, suspends the previous issuer and
   retains the original host intent. It then prepares the same native registry
   operation. The candidate cannot be extended, manually closed or redirected
   while this operation is unresolved. An error may follow durable intent.
5. Use [witness freeze, bind and commit](WITNESS_ROOT_REPLACEMENT.md) for these
   exact inputs. Submit the retained decision and signed retirement to
   `commit_account_root`. Invalid signatures, scope or target do not replace
   the retained intent.
6. The host retains the authenticated terminal intent, commits the native registry
   transition, then atomically selects the new issuer, archives the suspended old
   issuer, marks the candidate selected and records the terminal result. Only
   then is success returned. Fresh issuance uses the selected root; old issuance
   remains exact history and cannot be extended under the replacement issuer.

The native registry's revisions start at 1 when associated. They are translated
to the host's retained revision sequence; neither sequence is renumbered.
Two stores do not share an atomic transaction: the retained intent and suspended
host issuer make the ordered commits recoverable. If the process dies after the
native commit, the old host mapping remains suspended until the same operation
reconciles. Do not create another candidate or replace either store to recover.

## Unknown outcomes and permanent non-commit

Retain the exact operation and inputs before sending a request. After server
restart, log in to the same account and call `resume_account_root`. A retained
retirement/closure resumes without reauthorizing a different target. Signed
historical retirement can be reconciled after target policy or credential expiry;
fresh admission must still check current policy, membership and actual time.

`AwaitingOutcome` means approval exists; the witness may already have an unknown
outcome. `Reconciling` means a terminal proof is retained but host reconciliation
may remain. `Committed` and `Closed` are historical outcomes, not current traffic
capabilities. Reading status does not advance or recreate storage. A committed
result remains historical even after another root or roster is selected.

To abandon an unresolved attempt, obtain its exact signed permanent **plan**
closure with `root-plan-close` and submit that receipt. Absence, timeout, or an
unsigned claim is insufficient. Closure retains the old issuer's suspension and
the old keys/history. If a witness freeze exists, a separately approved new
target may use `root-replan` with that original signed freeze and closed plan;
no command unfreezes the old root. A new target has a distinct operation ID.

Use `root-plan-close` for this host coordinator. `root-close` belongs to the
separate exact-proposal controller: its narrower closure proof cannot be
converted to an original-plan closure. A refusal here is preserved, not treated
as permission to manufacture the other proof or reopen the closed operation.

## HTTP adapter

The existing exact Host/Origin, JSON body bound and authenticated-session rules
apply. All paths below start with `/api/enrollment`.

| Method and path | Input |
| --- | --- |
| POST `/authority/associate` | Original `AssociationRequest` |
| GET `/authority` | Original association history |
| POST `/root-cutover/approve` | Original `CutoverRequest` |
| POST `/root-cutover/commit` | `operation`, `proof` containing `decision` and base64url `receipt` |
| POST `/root-cutover/close` | `operation`, base64url plan-closure `receipt` |
| POST `/root-cutover/resume` | Original `operation` |
| POST `/root-cutover/status` | Original `operation` |
| POST `/root/retired` | Historical host root `revision` |

The cutover and retired-root tables each retain at most 512 operations/records.
Native registry bounds also apply. There is no automatic history deletion to
recover capacity. Issued history survives missing old signing files; new signing
still requires the selected original private owner.

## Validation scope

Tests use real software Passkey authentication, host-issued credentials, native
installation stores and signed witness proofs. They cover root/target isolation,
historical results, real policy expiry, old-key loss, re-enrollment refusal,
same-key extension under the selected root, and original key/journal retention.
Seven actual process-kill cuts cover schema/association initialization; ten
cover host/native approval, commitment and closure. Loopback HTTP loses association,
approval and commitment response bodies and reauthenticates after each restart.

These are reference-host and native-engine observations. Browser root controls,
the installed independent-client root controller, original client session-owner
fencing, device lifecycle integration, empty-root recovery and full
post-compromise analysis remain separate work. This path must not be described
as a completed multi-platform root-recovery product.
