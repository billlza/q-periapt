# Canonical Apple package on physical iPad

The exact canonical `QPeriaptContinuity-Apple-candidate.zip` with SHA-256
`61fa752f429c599220a90d0f70b6fcdeeb09dd4634ded08ae14fee146afdc75a`
was extracted into a separate consumer workspace and used by a warning-clean
Release iPad application through its local Swift package. The app has no custom
SDK header/library search paths or Rust build step. Its link map and copied
static library bind the executable to the packaged iOS arm64 slice
`74e70bcf72e79a3fb2f6396ddf04f0023d1c2f39d4e3da45eace0c79a1186108`.
Package contents and app/driver/fixture identities are checked again after execution.

The offered iPad Pro 11-inch (M4), iPadOS 27.0.1, completed all five account-root
routes with both fixed and recoverable SDK trust: original target, transition,
bound transition, adoption, and signed noncommit. The cohort contains 362 Swift
application calls and matching startup admissions, 62 application exits with
code 77, 20 separate receiver exits, and 28 identities generated on the iPad.
Each route verifies original proposals, retained reports, rejection of altered
inputs, reopening after unknown outcomes, new-root traffic and controller-close
revocation. The public records include 50 peer TLS exchanges, 3,340 opaque witness
streams, and 140 expected refused reconnections after receiver exits. Original
session/message identities and the two business effects per case survive retry.
These effects are a test of the stated application commit contract, not an
arbitrary external exactly-once guarantee.

All 362 application launches require the exact run-bound startup acknowledgement
before SDK work. The capture verifier checks receipts, exit codes, console
markers, public-result hashes, transport sequence bounds and each startup
admission. Ten altered public/execution records are refused. The archive manifest
is reread in full, and all ten route/profile records are verified after extraction.
The run-owned application was uninstalled and its absence queried. No private
on-device keys or journals were exported. The initial device-discovery refusal
occurred before installation; it is not counted as an executed test.

[CHECKS.json](CHECKS.json) records artifact and capture hashes. [CAPTURE.zip](CAPTURE.zip)
retains public execution, app/driver source, verification source, package inventory,
build logs and link map. The archive bytes and canonical producer evidence remain
in [the package checkpoint](../20261012-apple-package-producer/README.md).
The real commands were the repository Python entrypoint running `build_app.py`,
`run_device.py` and `capture_root.py` in `target/continuity-canonical-ipad-root/`.

This closes physical account-root lifecycle acceptance for this exact canonical
Apple package. Earlier iPhone/iPad enrollment, policy, renewal and Data Protection
records retain their original artifact scope. This cohort does not claim physical
power-loss durability, physical key erasure, independent protocol implementation,
live-owner background recovery or post-compromise confidentiality recovery.
Hosted package CI and the rest of the 0.2.0 release goal remain separate. The
accepted single Android phone remains sufficient for its recorded acceptance.
No Intel Mac slice, release or registry publication is introduced.
