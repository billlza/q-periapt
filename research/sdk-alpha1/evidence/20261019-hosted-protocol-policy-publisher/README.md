# Hosted protocol-policy publication

Run `39231378819` passed on Apple Silicon/macOS and Linux x86_64 at source
`85a18e75d7605d217e3bb0dcffcdb922b032b6e8`.

For each platform, terminal artifact readback verified all 89 members, the upstream
archive digest, 112 source inputs, the installed 50-module Python wheel, Rust
Debug/Release 34 entries, 17 browser model tests, strict Clippy and the release
build. The installed adapter/client suites passed eight and 16 tests. The native
publisher CLI passed 13 commands, including four expected refusals. Both wheels
match the independently built local wheel digest.

The reader additionally reverified the public SDK signature and hybrid protocol
signature for each of three policy versions, exact intent metadata, witness
binding and byte-identical original exports. This is historical verification;
it does not choose a past clock to activate an expired policy. Native binary
hashes are producer observations, not a claim of reproducible binary builds.

The capture contains the original public CI artifacts, exact source inputs,
readers and their outputs. `RECEIPT.json` and `PUBLIC_MANIFEST.json` identify the
bytes. Private databases and signing/wrapping keys are excluded from CI upload.
The local pre-fix/post-fix counterexample and retained-state checks are recorded
separately in `20261019-protocol-policy-publisher-local`.

The SDK authority and witness pins in these checks remain explicit test inputs.
Operational SDK root issuance, authenticated trust provisioning, consumer policy
activation, real host-authorized enrollment and full session lifecycle acceptance
remain open. No power-loss, secure-erasure, PCS or 0.2.0 release claim follows from
these CI results. Intel Mac is outside the support scope.
