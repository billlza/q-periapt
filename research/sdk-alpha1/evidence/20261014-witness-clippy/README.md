# Witness policy guards on minimum and canonical Rust

CI [job 115649009293](https://github.com/billlza/q-periapt/actions/runs/38501419094/job/115649009293)
failed the Rust 1.90 candidate lane on `3fd559d6`. Clippy rejected two
`nonminimal_bool` expressions in `enrollment/policy_renewal/witness.rs` under
`-D warnings`; runtime tests had not begun. The complete 63,484-byte job log is
retained, with its SHA-256 in `CHECKS.json`.

Both guards now express `!A && !(B && ...)` as `!(A || (B && ...))`.
Short-circuit order and accepted states are unchanged. The image validator still
requires its original completed-policy condition, while witness scope keeps its
own original predicate. No lint allowance, warning suppression, fallback or
authorization relaxation was added.

On macOS arm64, Rust 1.90.0 and 1.98.1 each passed strict all-targets Clippy with
all features and separately with control-tls and connection-tls. Each compiler's
actual library test catalog then selected all **281 enrollment tests**, and all
281 passed, with no ignored tests. The selection explicitly includes lost Commit
and ACK recovery, P1/G1 to P2/G2, and the second joint update's exact receipt
recovery. Test receipts, catalogs, selection lists, source before/after and the
original CI failure are in `CAPTURE.zip`.

Two setup limitations remain visible in the capture. The first local 1.90
toolchain lacked cargo-clippy; the run then used an already installed complete
1.90 toolchain. The initial `witness_policy` filter selected only one basic
handshake test, which did not establish enrollment coverage. The later
catalog-derived run supplies the complete 281-test evidence above.

These local compiler and runtime checks do not substitute for the next exact-head
Linux CI run, packaged-device qualification or complete release readiness.
