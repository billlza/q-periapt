# Browser dependency audit admission

Hosted audit job `115181633663` at `1ce396c4` rejected the newly reachable private
Continuity engine as an unexpected local package. The real workspace-lock test
reproduced the rejection before any network audit. The browser dependency is
already explicitly pinned and path/private-package checked by the SDK package
classifier; this fix updates the separate lock-audit inventory.

Workspace scope now requires the original local set plus exactly
`q-periapt-continuity-identity-candidate` version `0.0.0`. It is still rejected as
a registry package, in the normalized publication closure and in the fuzz scope.
The publication cohort is unchanged. The 17 additional registry identities all
already exist in the isolated candidate lock; no existing lock identity changed
or disappeared (`LOCK_DELTA.json`).

The reviewed workspace closure grew from 242 to 259 registry entries. Its parser,
sparse worker and parent receipt now consistently apply a fixed 259-entry bound;
normalized/fuzz scope retains 256. Exact real-lock counts remain 259 and 46, and
regressions reject one entry beyond each scope's bound. Intermediate local runs
also exposed the old 256 parser/receipt limits; their failures are retained.

All 80 `test_rust_publish_contract` tests pass. The actual fixed-path command
`sh artifact/python-run.sh artifact/rust_publish_contract.py verify-workspace-dependency-audit`
then passed both current locks using cargo-audit 0.22.2 and fresh RustSec commit
`d5f46becf4d442d460e1fce5e12f2c0f00924868`. Its terminal marker records exact sparse
checksums, no yanked packages, denied warnings, stable locks and no ambient Cargo
home data. The task-local audit executable was copied from the existing verified
installation; no global installation changed.

This is a local reproduction and repair. Hosted confirmation at the repair commit
is still required; it is not a release or whole-protocol security claim.
