# Original-session policy renewal with a witness

This flow implements the [original-device P relation](POLICY_RENEWAL.md) through
the original enrollment owner. It preserves the profile, policy signer, SDK
binding, witness, send budget and validity start, and advances version and expiry.
It retains device keys, journal, pending messages and established sessions.
Account and policy issuers approve the same request independently. A trusted
witness operator separately approves its exact sealed target. Historical progress
does not grant current session permission.

`DEVICE` below expands to the original absolute device directory, wrapping-key
path and invitation JSON. `ORIGINAL` is a retained `PolicyInput` JSON with
independently selected `pins` and `materials` for P0. `WITNESS` is the numeric
signed-TCP endpoint belonging to that pinned witness.

## Request and stage

```text
q-periapt-native-device policy-witness-request DEVICE OP ORIGINAL WITNESS NEW_REQUEST
```

Retain the operation ID and exported `qperiapt-retained-policy-request/1`. The
original journal and fresh witness head supply its scope. It does not reserve an
update. Obtain the account approval through authenticated
`/api/enrollment/policy-approval` and the policy approval through independently
authorized publisher `renewal-approve`. Keep both original responses and matching
statement commitments. `policy-witness-stage` takes the same explicit inputs as
`policy-stage` in the linked guide, with witnessed policies. It verifies both
approvals, identities, journal predecessor and live target before retaining the
first approval bytes. `policy-status` reports approval progress;
`policy-witness-status` reports coordination. Coordination can be Absent while
an approval is staged.

## Prepare and approve the original target

Publisher `renewal-policies` exports the exact original/previous/target
`qperiapt-policy-approval-inputs/1` selection used below as `POLICIES`.

```text
q-periapt-native-device policy-witness-prepare DEVICE OP STATEMENT POLICIES WITNESS NEW_PREPARATION
q-periapt-native-device policy-witness-recover-preparation DEVICE OP STATEMENT ORIGINAL NEW_PREPARATION
```

Preparation seals one journal target and exports a complete public proposal,
binding and exact retained two-root approval in
`qperiapt-policy-witness-preparation/1`. Exports are exclusive. After failed
export/stdout, recover the same preparation into a new file. `NoLocalPreparation`
reports local absence only. Before a target has been sealed or released,
`policy-witness-abandon-unprepared DEVICE OP STATEMENT ORIGINAL` can retain the
distinct local `AbandonedBeforePreparation`, without signer, live target or network.
A sealed target always requires its original signed coordination.

The operator supplies `qperiapt-witness-policy-renewal-trust/1` with independently
selected account root/current roster, device/generation, immutable original
subject, proposal binding, retained issuer request and original/previous/target
policy inputs. The device export grants no authority to populate that selection.
Keep the first enrollment's subject after later credential renewal.

```text
q-periapt-continuity-witness policy-prepare HOST_DB IDENTITY TRUST PREPARATION
q-periapt-native-device policy-witness-commit DEVICE PREPARATION POLICIES WITNESS
```

Witness preparation rechecks both signatures, live identity/target and actual
predecessor. Commit is separate. Unavailable never establishes non-commit.

## Recover and continue

```text
q-periapt-native-device policy-witness-observe DEVICE PREPARATION ORIGINAL WITNESS
q-periapt-native-device policy-witness-close DEVICE PREPARATION ORIGINAL WITNESS
q-periapt-continuity-witness policy-close HOST_DB IDENTITY TRUST PREPARATION
q-periapt-native-device policy-witness-activate DEVICE CURRENT_ROOT ORIGINAL TARGET WITNESS
```

Observation and closure authenticate the same original operation after expiry,
retain its terminal before ACK/cleanup and preserve an already Applied result.
The complete proposal must match, including its heads. Lost operator/commit stdout
requires reopening the same stores and observing that operation. `TARGET` is a
separately selected current `PolicyInput`. Activation additionally checks current
membership, validity and fresh witness admission and returns the original journal.

Network-service and outgoing JSON select current policy through the existing
paths and add `original_policy` pointing to `ORIGINAL`. Established sessions use
their historical bundle and authenticated P completion. The renewed service
accepts existing-session messages/control; bootstrap cannot create authority
through the historical context. Omission selects original activation, which
refuses an adopted target.

CLI regressions cover failed exports, exact retry, substitution, lost stdout,
real expiry and offline abandonment. The account workload composes R/P/R using
software-Passkey HTTP authorization, separate publisher/witness processes, two
lost message confirmations, original rekey and bidirectional traffic against the
independent Python endpoint. That peer stays on live P0. Joint G/P/R with both
endpoints' policy expiry, mobile persistence, cross-host deployment, general
upgrades and PCS proof remain separate requirements. Source and installed-package
executions have separate receipts.
