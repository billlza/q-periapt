# Integrated Android roster qualification

The complete Debug and Release host JNI qualification passed without changing its
source, readers or packaged class inputs while running. Each profile executes
1,720 lifecycle Java processes plus one JNI boundary process: 3,442 in total.
The added roster workloads account for 1,960 calls across 44 exported routes.

Coverage includes local original-policy and selected-policy refresh, independently
approved remote roster admission, member retention versus revocation, required-witness
Applied/Closed recovery, real original-policy expiry and independently authorized
policy adoption before roster renewal. Recovery retains original identity, journal,
session and pending message. Historical reconciliation emits no fresh Commit/Close;
fresh activation still requires current authority. The complete preceding registration,
credential, expiry, policy, cancellation and traffic workloads remain included.

`CAPTURE.zip` retains 12,903 members plus a hash manifest: source, reader inputs,
public exports and command output. All member hashes and all four roster export
families in both profiles were reread. `CHECKS.json` separates lifecycle and boundary
counts; the initial capture assertion omitted that distinction and its failed
attempt remains locally retained. Private keys, journals and process environment
values are not archived.

The accepted physical phone's routes are recorded separately; no additional phone
is required. Retirement/replacement extensions are separately qualified candidates.
This host result does not itself establish remote CI or release readiness.
