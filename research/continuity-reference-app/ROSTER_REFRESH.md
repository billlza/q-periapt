# Surviving-device roster refresh

When another device in an account is added or replaced, the surviving device
keeps its signing keys, credential, installation and sessions. Its own roster
and the witness's authorized journal head must advance together. The `R`
transaction provides this coordination. `admit-peer-roster` updates a remote
account; it does not perform this operation. Credential renewal uses `G`.

Use the original private device directory, wrapping key and invitation for all
commands. Never reconstruct them after an uncertain result. These commands use
the OS clock and require the original pinned witness. They do not log in to the
account, sign rosters, approve themselves or activate a runtime.

## Select and retain inputs

`qperiapt-roster-refresh-inputs/1` contains `target` (the independently obtained
current `RootInfo` with its exact signed roster), `original` (the original
`PolicyInput`) and `policy` (the currently admitted `PolicyInput`). A `PolicyInput`
contains `pins` and `materials`, as exported by the policy publisher. Original
history and current policy remain distinct; the SDK checks any retained
credential/policy continuation rather than reverting to the original policy.

Keep one random, nonzero, 32-byte operation ID encoded as base64url without
padding. Retrying must preserve that ID and the exact target. In the commands
below, `DEVICE` denotes the three separate arguments: device directory, wrapping
key file and original invitation JSON. Paths must identify the original files.

```text
q-periapt-native-device roster-prepare DEVICE OP INPUTS WITNESS NEW_REQUEST
q-periapt-native-device roster-status DEVICE
```

Preparation seals the exact proposed journal image and pauses normal activation
until the transaction is resolved. `NEW_REQUEST` must not exist. If export or its
response fails, keep the original state and recover to another fresh path:

```text
q-periapt-native-device roster-recover-preparation DEVICE OP ORIGINAL_POLICY NEW_REQUEST
```

The public request includes the proposal, its binding and signed predecessor
evidence. A local `Staged` result without a recovered proposal does not prove
anything about a remote commit. `roster-abandon-unprepared DEVICE OP
ORIGINAL_POLICY` succeeds only when the SDK can prove no proposal was released
and no sealed target remains. It cannot cancel an exported proposal.

## Independent approval and commit

The trusted witness operator selects `qperiapt-witness-roster-refresh-trust/1`:

- `account`: exact independently selected target `RootInfo`;
- `device`, `generation`: the surviving identity;
- `subject`: base64url original 96-byte witness enrollment subject, retained
  independently from first enrollment (not recalculated from a renewed credential);
- `proposal_binding`: the explicitly approved 32-byte binding;
- `policy`: the independently selected current `PolicyInput`.

The device request supplies signed predecessor evidence, not its own trust root
or approval. The witness checks the actual predecessor head, unchanged credential
and signing owner, policy, target and original subject before preparing.

```text
q-periapt-continuity-witness roster-prepare HOST_DB IDENTITY TRUST REQUEST
q-periapt-native-device roster-commit DEVICE REQUEST INPUTS WITNESS
```

`Unavailable` means the exact witness result is unavailable, including when the
operator has not prepared it. It is not non-commit, cancellation or permission
to create another operation. Keep the proposal and reconcile it. A successful
transaction installs the original sealed image, records its local terminal
result, acknowledges the witness and retires pending state in that order.

## Recover or close the original transaction

```text
q-periapt-native-device roster-observe DEVICE REQUEST ORIGINAL_POLICY WITNESS
q-periapt-native-device roster-close DEVICE REQUEST ORIGINAL_POLICY WITNESS
q-periapt-continuity-witness roster-close HOST_DB IDENTITY TRUST REQUEST
```

Observation and closure verify historical signatures and can finish after the
target expires. Witness closure uses the retained exact target and policy,
including their historical signatures; it does not issue fresh authority. A
committed result remains `Applied` when closure is requested. A prepared target
closed before commit leaves the previous admission intact. Activation still
requires independently current inputs and a fresh witness admission.

`roster-status` reports local progress: `Absent`, `Staged`,
`AbandonedBeforePreparation`, `Reserved`, or terminal `Applied`/`Closed` with
`retired`. Terminal history is not a current-permission or witness-liveness test.
After a lost commit response, observe the same request; do not reset stores or
infer failure from the missing stdout. After `Applied`, normal `activate` uses
the new root snapshot and the original device files.

The CLI regressions exercise failed export, exact recovery, unapproved targets,
retarget refusal, lost output, rollback refusal and real-time target expiry.
`tests/host_roster.py` exercises real software-Passkey HTTP account addition and
replacement, two R transitions around an independently approved
[witnessed policy renewal](WITNESSED_POLICY_RENEWAL.md), retained pending delivery
and original session traffic/rekey. After P adoption, select continued activation
and retain original P0 alongside the current target. Software authentication,
local TCP and historical outcomes are
not human-Passkey, physical-device or continuous-PQ-recovery claims.
