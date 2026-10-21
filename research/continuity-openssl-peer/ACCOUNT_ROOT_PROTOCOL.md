# Independent account-root statement verification

`account_root_protocol` reconstructs the original planned root transition from
independently selected account, witness, credential, roster, policy and prepared
journal expectations. It uses the Python/OpenSSL implementation's existing
signature and identity verifiers. It neither imports nor calls the Rust engine.

This is the public protocol-verification layer for the independent root
controller. Durable account selection, original parent/session-owner fencing,
closure recovery and target activation are not implemented by these objects.
They must not be used as a substitute for those owner transitions.

## Original expectations

A `Plan` contains the original witness pin, target and freeze operation IDs,
previous account public key, successor `DevicePin`, signed certificate and roster,
historical signed policy, journal ID and exact prepared genesis head. These
expectations must come from the independently approved host operation, not from
the incoming plan being checked. The witness must also match the signed policy's
required witness. The two operation IDs are distinct and retained on retry.

`wire()` rechecks signed metadata and constructs canonical `QPAFPL01` bytes.
`verify_plan()` requires exact equality with that construction; it does not
derive trust from a received root or witness key. Target membership, key
separation, policy family, credential/roster/policy validity intersection, storage
owner and genesis bindings are checked. Historical verification does not assert
that any of those validity windows is current.

## Signed observations

`bind(freeze_receipt)` verifies the original request and complete bounded frozen
snapshot under both ML-DSA-65 and P-256 signatures. Frozen subjects are strictly
ordered and their heads, last-command markers and state commitments are retained.
The resulting `Decision` reconstructs the exact `QPARPL02` descriptor using only
that snapshot and the previously selected target.

`verify_retirement()` verifies the account-retirement purpose and exact decision
commitment. `Decision.verify_closed()` verifies permanent non-commit of that
particular bound decision. `Plan.verify_closed()` instead verifies non-commit
of the original plan for every snapshot. The purposes and statements are
different; none can substitute for another, a freeze proof or a live witness
reply. Original statements remain verifiable after policy expiry.

These methods return immutable historical observations, with no traffic owner.
They do not establish message delivery, erase old secrets, reactivate a suspended
root, select a successor, prove that the caller's durable store was updated or
establish post-compromise security. A controller must retain and reconcile its
own original approvals and owner transitions before releasing new work.

## Installed interoperability check

`tests/account_root_protocol.py` runs against an explicitly selected installed
wheel and provider, reading only public outputs and original fixture trust from
the real native witness CLI. It independently reconstructs plan/decision bytes
and verifies signed freezes, retirement and both closure types across commit,
exact-close, plan-close and replan profiles. It checks altered expectations,
canonical bounds, truncation, both signature components and proof-purpose
substitution. The same check runs after the local operator in reference-account
CI and records imported module hashes and public-input hashes.

This qualifies public root-statement interoperability. It does not qualify an
independent root controller, a root-replaced live session, a physical device root
transition or full release readiness.
