# Hosted SDK policy authority

[Run 39237096750](https://github.com/billlza/q-periapt/actions/runs/39237096750)
passed on Apple Silicon/macOS and Linux x86_64 at source
`e13efcaf23d38fb88ea52fd9aefa79724b6967e2`.

For each platform, terminal artifact readback verified the upstream archive
digest, all 137 members, 134 source inputs and the installed 50-module Python
wheel. Rust Debug and Release each passed 42 entries; native signing checks passed
16 entries; the browser model passed 17 tests. Strict Clippy and release builds
passed. Installed adapter and client suites passed eight and 16 tests respectively.
The operator CLIs exercised 24 commands, including seven expected refusals.

The reader independently reverified two SDK policy signatures and three hybrid
protocol policy publications using cryptography 48.0.1 / OpenSSL 4.0.1, including
exact original operation and export consistency. The SDK authority uses its own
protected native signing owner. Witness pins remain test inputs. Both installed
wheels match the independently built local wheel digest. Native binary hashes
are producer observations, not reproducible build claims.

`RECEIPT.json` identifies both original CI artifacts and the 150-member capture.
Its `PUBLIC_MANIFEST.json` inventories the public archives, source snapshots,
readers and readback outputs. No private database or signing/wrapping key is
included. Historical signature verification did not backdate policy activation.

This receipt covers the reference workflow only. Separate generic CI jobs at the
same source failed their artifact or packaging checks. A strict JSON tooling
violation in those paths was reproduced locally; its fix and subsequent results
must be assessed separately. A successful reference workflow does not clear those
failures.

Local operator trust is assumed. Consumer activation, independently authorized
authority replacement, real user/device authorization, full lifecycle acceptance,
power-loss behavior, secure erasure, PCS and release admission remain outside this
receipt. Intel Mac is outside the support scope.
