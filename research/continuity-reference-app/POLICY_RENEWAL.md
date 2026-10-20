# Original-device policy renewal

The native consumer supports the SDK's separate policy-only P operation. It
extends validity under the same original policy root, SDK binding, algorithm
profile, prekey modes, witness requirement and sending budget. It does not change
the device credential or roster and authorizes only original established sessions.
Changing those other parameters requires its own migration contract; a P renewal
must not be used to bypass their original transcript or storage bindings.

The application retains the original device directory, wrapping key, selected
invitation and independently provisioned policy pins. It generates and retains one
policy-operation ID before exporting the original request:

```sh
q-periapt-native-device policy-request "$device_dir" "$wrapping_key" "$invitation" \
  "$original_operation" "$original_policy_pins" "$original_policy_materials" "$new_request_output"
```

The `qperiapt-retained-policy-request/1` JSON contains public original/current
certificate and roster bytes and the actual journal's policy predecessor. The
application/enrollment/revision fields are host correlation. Scope binds the
policy operation, original journal/owner/credential, unchanged current credential
and roster, P0, actual previous policy and its previous authorization digest.
Export does not reserve a transition, authenticate an account, sign or adopt a
policy. Pending maintenance must be reconciled first. Export works after expiry
without the private device signer; retain all original storage and wrapping keys.
Output paths are exclusive. Retry the original operation to a new filename.

The account authority and original policy authority independently authenticate and
approve the same canonical `PolicyRenewalStatement`. Both approvals are required.
`Request::verify_identities` checks signed identities under separately selected
current account trust; it does not authenticate the reported journal or approve a
request. Construct the SDK statement using independently verified historical P0,
exact previous policy, and a live target policy. The SDK's statement checks bind
all identity and policy fields. The authorities must serialize/deduplicate their
own decisions and retain exact signature bytes across unknown responses.
The protected policy-side issuer now provides this transaction and operator CLI;
see [original-device renewal approvals](POLICY_PUBLISHER.md#original-device-renewal-approvals).
The account-side reference host also provides the authenticated transaction
described below. A policy signature cannot substitute for account authorization.

The consumer takes those two original bounded binary approval files separately
from the retained request and trust configuration:

```sh
q-periapt-native-device policy-stage "$device_dir" "$wrapping_key" "$invitation" \
  "$original_request" "$account_approval" "$policy_approval" "$current_root" \
  "$original_policy_pins" "$original_policy_materials" \
  "$previous_policy_pins" "$previous_policy_materials" \
  "$target_policy_pins" "$target_policy_materials"
q-periapt-native-device policy-status "$device_dir" "$wrapping_key" "$invitation"
```

Staging verifies both signatures and compares the complete scope with original
SDK state before retaining Pending. The supplied current signed roster must
exactly match the request. A different journal, root, prior policy, credential or
roster is not silently substituted. `policy-adopt` takes the same arguments as
`policy-stage`; it stages the exact operation and coordinates the original journal
adoption. Repeated calls preserve the original operation and authorization.
Successful stdout follows owner closure. An output error can occur after commit;
query the original status, then reconcile that same operation.

`Committed` is historical adoption metadata. These commands release no live
session owner, grant no fresh-bootstrap or publication permission, and do not
replace current traffic admission. The old generic activation path remains
fenced after adoption. Restoring an established session under P requires the
matching SDK continued-session path and fresh peer/current-policy checks.

After expiry or a lost result, use historical recovery with the exact operation
and statement already retained by the caller:

```sh
q-periapt-native-device policy-recover "$device_dir" "$wrapping_key" "$invitation" \
  "$original_operation" "$original_statement" \
  "$original_policy_pins" "$original_policy_materials"
```

This can finish an already-committed original journal operation without a live
target policy or private device signer. It does not adopt an uncommitted Pending,
classify it as abandoned, or stage another request. A pending target with no exact
commit returns an error and remains Pending. `policy-status` alone is not proof
of non-commit.

To resolve an expired pending operation, supply its exact original ID, statement
and independently verified target history:

```sh
q-periapt-native-device policy-resolve "$device_dir" "$wrapping_key" "$invitation" \
  "$original_operation" "$original_statement" \
  "$original_policy_pins" "$original_policy_materials" \
  "$target_policy_pins" "$target_policy_materials"
```

The SDK inspects the original installation and journal. An exact committed
operation remains `Committed`. An unchanged policy predecessor proves non-commit;
only then can signed credential, roster or target expiry, or an actual advanced
roster, permit `AbandonedUncommitted`. A still-live unchanged request, mismatched
statement/target, unreadable state or unresolved conflict returns an error.
Neither an expired file nor a failed command alone proves non-commit.

Resolution uses actual host time, preserves the SDK's retained time floor and
returns only outcome metadata. It needs no device signer or live target runtime.
Retain the exact result, including reason, observed roster and observation time.
Exact retry returns the retained outcome; the SDK retains only the last abandoned
record until a later abandonment or policy completion. Applications needing a
longer history must retain their own receipts. After proven abandonment, export a
new operation from the same original installation and obtain two new approvals.
Previous signatures do not authorize the new request or extend its expiry.

The current commands require a local-only original installation. Required-witness
P authorization and coordination remain separate; there is no local fallback.
The browser's review and recovery interface for P still needs integration.
Tests use real protected account and policy issuers, a software test Passkey,
actual HTTP and the native SDK owner; separate CLI cohorts exercise consumer
subprocesses. These are not real-account approval or established-session traffic
acceptance. Changed-policy credential continuation,
required-witness P, and the native/independent session facade remain integration
work. Keep these boundaries distinct from the separately integrated G renewal.

## Account-side approval

Stop the reference host, preserve a backup of its original database and key files,
and explicitly upgrade schema 5 before using this optional host feature:

```text
q-periapt-continuity-reference-app enable-policy-approvals DB http://localhost:8087
```

Schema 6 atomically adds `policy_approvals`; it retains the original account,
Passkeys, root, device enrollment, credential extensions and G decisions.
Opening never upgrades or repairs missing tables. Older hosts reject schema 6.
Using this reference account remains optional; it is not an SDK login requirement.

The authenticated API accepts a `PolicyApprovalRequest`:

- `retained`: the exact original `policy-request` output.
- `original_extension` and `current_extension`: explicit host issuance IDs, or
  explicit `null` for the original enrollment certificate. Neither field may be
  omitted. The current choice must descend from the original choice.
- `original`, `previous`, `target`: each contains `pins` and `materials` in the
  existing publisher export formats. These are exact policy selections; their
  signing key must match the host's independently configured policy family.

The account root is read from the authenticated account's own protected store,
never from the request. The host verifies original enrollment ownership, selected
certificate bytes, current membership and the exact current signed roster. It
checks the SDK's same-profile renewal relation, persists Pending before signing,
and rechecks the serialized root/roster and actual host time before committing.
The original journal and previous adoption remain device-side facts; issuer
approval does not prove that the device has adopted either policy.

```text
POST /api/enrollment/policy-approval
POST /api/enrollment/policy-approval/status
POST /api/enrollment/policy-approval/cancel
```

All three routes require the original account's live login and exact same-origin
boundary. They take the same immutable request. Only these policy routes accept
up to 512 KiB, accommodating three signed policy/SDK bundles; other routes retain
their 64 KiB limit. The separate ledger retains at most 512 decisions and never
evicts history to admit a new operation.

Issuance returns the exact persisted `IssuedPolicyApproval` JSON. Its `approval`
field is the base64url account signature; the consumer takes its decoded bytes
alongside the independent policy signature. `status` returns Absent, Pending,
Issued with the original response bytes, or Closed and never signs. Cancellation
retains an exact Closed tombstone, including before delayed first issuance.
Already-issued signatures cannot be cancelled. Expired or changed pending
decisions remain unresolved until an explicit cancellation; no new identity,
roster, expiry or policy is silently substituted.

After a response is lost or the server restarts, authenticate as the original
account and query/retry the original request. Historical issued responses remain
available after root suspension, expiry or loss of signing files, and their
account signature is reverified on retrieval. This is historical data, not a new
permission. The device still requires both approvals, exact original state and
current admission. The browser P review/backup flow and real-user ceremony remain
open; the API's software-authenticator tests do not satisfy that gate.
