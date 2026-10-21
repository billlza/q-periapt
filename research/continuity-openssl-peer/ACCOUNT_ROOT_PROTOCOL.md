# Independent account-root statements and registry

`account_root_protocol` reconstructs the original planned root transition from
independently selected account, witness, credential, roster, policy and prepared
journal expectations. It uses the Python/OpenSSL implementation's existing
signature and identity verifiers. It neither imports nor calls the Rust engine.

These statement objects provide public protocol verification. The separate
`AccountAuthority` owner below retains original approvals and current root
selection. EnrollmentClient and original session-owner fencing and target
activation are not yet connected to it. Neither layer is a complete device
root-replacement controller.

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
independent live root-replacement controller, a root-replaced session, a physical
device root transition or full release readiness.

## Original application registry

`AccountAuthority.provision` explicitly creates a private original registry. The
host retains its wrapping key, identity, policy family, witness pin and absolute
directory. These are bound into the authenticated journal scope. `open` requires
existing state; it never creates a replacement for a missing registry.
`open(initial=True)` is only recovery of an original revision-zero creation
intent. It cannot create an empty registry or admit a later revision as first use.

`associate` verifies the independently selected signed original device and
roster under the configured family. It creates revision one for an application
ID. This identifies the original root; fresh device/policy permission remains a
separate check. Root reuse across applications or retained transitions is
refused. At most 64 applications and 256 root operations are retained.

`current` returns only an active mapping. `admit` requires that exact mapping
and returns a revocable lease; check it again before releasing work after I/O.
Preparation revokes the affected application's cached leases before attempting
persistence. An unrelated application's lease survives. Parent close, lost
parent ownership, a failed write or reentrant cancellation revokes permission.
Invalid proofs are rejected before mutation and leave the owner usable.

`begin_preparation` accepts a fresh independently approved `Plan`, not a decoded
incoming plan. It retains exact bytes before returning. `bind_freeze` checks and
retains the original signed snapshot. `commit_retirement` verifies the exact
signed retirement and advances the mapping once, including when the authenticated
retirement reconciles an originally unbound preparation. Retries retain the
original operation, target and selected revision.

`close_plan` and `close_decision` require their distinct signed non-commit proofs;
exact-decision closure requires an already bound preparation. Both preserve the
old-root suspension, including after reopening. `operation` exposes historical
checkpoint and plan/decision bytes for recovery without granting work. A later
approved target must preserve any authenticated original freeze request and
snapshot binding. An unbound closure cannot assert that a freeze was observed;
it preserves any prior authenticated retry scope. The host should keep the
original request to reconcile an in-flight unknown freeze. Closed operations
cannot reopen, and committed operations cannot close.

This registry uses the existing encrypted exact-target journal and publication
barriers. Its history has a dedicated bounded allocation within the unchanged
64-MiB directory quota; ordinary session business payloads remain limited to
2 MiB. Stored descriptors are reconstructed from the authenticated original
journal only. They cannot supply new host approval or transferable proof.
The registry is intended to live outside replaceable session backups; it does
not detect rollback of all host-retained authority state by itself.

`tests/account_authority.py` uses real native host/enrollment/witness outputs in
one policy family. It checks active versus historical selection, per-application
lease revocation, invalid proofs, exact versus plan closure, replan, path and
configuration binding, storage errors and actual SIGKILL at all eight publication
boundaries for creation, preparation, freeze, closure and retirement. It records
whether the implementation is source development or an installed wheel. CI runs
the installed scope with that run's generated signed inputs.

Still separate: EnrollmentClient configuration association and original child
journal fencing, unknown-delivery retention through root replacement, live
successor admission, independently approved adoption of another committed winner,
device qualification and post-compromise recovery analysis. Do not use this
registry as evidence that those composed paths are complete.
