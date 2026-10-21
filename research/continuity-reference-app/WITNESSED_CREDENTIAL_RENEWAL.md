# Original credential renewal with a witness

The reference witness accepts independently approved G under either the original
policy or an already acknowledged [independent P](WITNESSED_POLICY_RENEWAL.md).
It does not authorize an account login, extend a certificate, adopt a policy or
replace a device. Those decisions remain separate.

First obtain a same-key certificate extension and an authenticated
[retained-state grant](RETAINED_GRANTS.md). Keep the original device directory,
wrapping key, invitation, P0, request and issuer response. The existing native
`renewal-stage` and `renewal-witness-prepare` commands retain the exact G and export
`qperiapt-credential-witness-proposal/1`. An export failure does not undo a sealed
target: repeat with the identical inputs and an unused output path while the
target remains live. Expired recovery uses `renewal-witness-observe` and retained
historical inputs; it never creates new authority.

The operator separately selects a trusted JSON object with schema
`qperiapt-witness-credential-renewal-trust/1`:

- `account`: the independently selected target `RootInfo`, including its signed
  roster and checkpoint; `enrollment`, `operation` and `statement`: exact approved
  identifiers, each represented as 32 bytes.
- `subject`: base64url of the immutable original enrollment subject;
  `proposal_binding`: the approved complete proposal commitment. Obtain these
  through the trusted operator channel. An incoming device export cannot choose
  its own approval.
- `original`: independently pinned P0 `PolicyInput`; `policy`: selected current
  `PolicyInput`, each containing `pins` and `materials`.
- `lineage`: explicitly `{"kind":"original"}` or
  `{"kind":"independent","statement":[...32 bytes...]}`. The latter selects
  the exact P already retained by this witness; it cannot introduce another P.

```text
q-periapt-continuity-witness credential-prepare HOST_DB IDENTITY TRUST PREPARATION ISSUED_GRANT
q-periapt-native-device renewal-activate DEVICE APPROVAL ISSUED_GRANT CURRENT_ROOT ORIGINAL_PINS ORIGINAL_MATERIALS CURRENT_PINS CURRENT_MATERIALS WITNESS
q-periapt-native-device renewal-witness-observe DEVICE OP STATEMENT ORIGINAL_PINS ORIGINAL_MATERIALS WITNESS
q-periapt-continuity-witness credential-close HOST_DB IDENTITY TRUST PREPARATION ISSUED_GRANT
```

`DEVICE` expands to the original directory, wrapping-key path and invitation.
Preparation checks live membership, policy and the exact signed grant against
the independently selected root and witness. Closing uses authenticated
historical inputs and preserves an already Applied result while retained.
After the device durably acknowledges the result, witness retirement rejects
re-preparation/closure with `Retired`; consult the original device journal's
`renewal-status` or authenticated observation, never infer non-commit from that
error. Lost operator or activation output requires the same original operation.

The source CLI regressions cover original-policy G, P followed by G, substituted
operator selections, export/output loss and real policy expiry. The authenticated
account workload `tests/host_roster.py --credential-renewal` adds G after R/P/R.
Supply `--credential-recovery-probe` with the path to the Cargo example of that
name. This test-only consumer uses the returned recovery owner directly to reopen
the established session and observe its next message ID; it does not reactivate
the device through another path. The workload then restarts the witness, recovers
the original pending message, rekeys and exchanges traffic with the independent
Python peer. That peer's original C/P remain live. This source workload runs in a
separate account CI step with its own schema-3 receipt; the existing schema-2
installed R/P/R collector does not qualify it.

Joint T adoption, both endpoints' credential/policy expiry, new installed-package
qualification of this operator, mobile composition and general upgrades remain
separate acceptance requirements.
