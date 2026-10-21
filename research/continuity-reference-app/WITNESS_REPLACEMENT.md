# Witness device replacement

The trusted local witness operator can atomically admit one fresh device
generation and retire its complete predecessor set. It uses the candidate SDK's
existing device-replacement transaction. Ordinary signed TCP requests cannot
approve this operation. Account authentication and approval remain host duties;
using Q-Periapt does not itself require a Passkey account.

The successor needs its own enrollment, signing keys and prepared journal.
Reusing an old key, retaining the same generation, resetting an old journal, or
silently omitting a live predecessor is rejected. Retired device records and
unresolved G/P/R metadata stay in the witness. Old device files are not deleted,
and retirement is not a claim that an attacker erased an old key or plaintext.

## Prepare an exact decision

An authenticated operator independently supplies a private JSON file with schema
`qperiapt-witness-device-replacement-trust/1`:

* `successor` is the existing `qperiapt-witness-enrollment-trust/1` structure:
  current `RootInfo`, approved device/generation, journal and exact genesis head,
  certificate, and independently pinned policy inputs.
* `predecessors` lists each original subject, its retained current roster
  checkpoint, and independently pinned historical policy inputs. `subject` uses
  unpadded base64url. Historical policy verification permits expired inputs but
  supplies no current authority. The list is bounded to 256 entries, matching the
  candidate witness capacity; ordinary enrollment already forbids duplicate
  journals under one credential.

The new device separately exports its existing `RequiresWitnessEnrollment`
preparation. Do not derive the trusted root, predecessor set or approval from
that untrusted export. The operator approves the exact prepared journal through
its authenticated host workflow.

```sh
q-periapt-continuity-witness replacement-prepare "$WITNESS_DB" "$WITNESS_ID" \
  "$APPROVED_TRUST_JSON" "$NEW_DEVICE_PREPARATION_JSON" "$EMPTY_PRIVATE_DIRECTORY"
```

This writes `device-replacement-decision.json`, containing a canonical native
`QPDRPL01` proposal and its binding. It reserves nothing and changes no witness
entry. Retain the file before commit. Concurrent predecessor changes make this
decision conflict; they never cause an implicit rebase.

## Commit and recover

```sh
q-periapt-continuity-witness replacement-commit "$WITNESS_DB" "$WITNESS_ID" \
  "$APPROVED_TRUST_JSON" "$NEW_DEVICE_PREPARATION_JSON" "$RETAINED_DECISION_JSON"

q-periapt-continuity-witness replacement-status "$WITNESS_DB" "$WITNESS_ID" \
  "$RETAINED_DECISION_JSON"
```

Commit rechecks live successor credentials, roster, policy and the exact old
state. A durable commit precedes the returned result. If output is lost or the
process fails, reopen the same witness and query the same decision. Never create
a new witness, decision or device key just because the result is unknown.

`Committed` observes the retained original replacement; it is not a traffic
lease. `Unavailable` means this exact decision is not retained and does not prove
that some different operation did not commit. A malformed or conflicting
decision fails explicitly. Current commit inputs must remain live; after their
expiry use `replacement-status` for historical observation. The successor must
still activate through its original pinned witness and pass current admission.

## Validation and limits

The host tests use actual SDK journals, check stale predecessor conflicts,
duplicate enrollment, generation/key separation, expiry and a process kill after
the witness commit. The CLI integration creates two actual native enrollments
under one test account, loses commit stdout, observes the original result, and
checks TCP activation before and after restarting the witness: the fresh device
activates and the retired device fails. Signing and journal identities remain
unchanged across recovery.

These checks cover witness admission and original recovery. They do not establish
new-device message exchange, independent-Python replacement, browser account
approval, root/witness replacement, device transfer of old message history, or
full release qualification. Those lifecycle paths retain their own requirements.
