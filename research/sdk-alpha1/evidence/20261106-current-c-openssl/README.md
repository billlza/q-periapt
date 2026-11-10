# Current installed C/OpenSSL Debug and Release public replay

The completed C components of the current host-JNI runs now have an independent
P0 readback at `5678d1019861fa1b04f3a219ba3fde7e0ddaaba8`. Both profiles use
matching installed SDK/candidate archives, including the later roster change.
This extends the [original P0 regression](../20261104-openssl-witness-census/README.md)
to the current cohort without rewriting the earlier evidence identity.

| Actual installed component | Debug | Release |
| --- | --- | --- |
| Independent OpenSSL server / C owners | 146 exchanges | 146 exchanges |
| Independent OpenSSL client / native Witness | 2 one-exchange connections | 2 one-exchange connections |
| Wrong subject, trailing data, missing end, wrong protocol | 4 refusals; 0 store calls | 4 refusals; 0 store calls |
| Native mutual-TLS counterpart | 146 exchanges | 146 exchanges |
| Altered public evidence controls | 14 refused | 14 refused |

Original readers check the actual ordered TLS 1.3 / X25519MLKEM768 /
`q-periapt-anchor/1` negotiation records, successful command transcripts, durable
business effect and revoked-cleanup reports. Client framing and command/attempt
binding retain their separate checks. Each exact public data inventory and
`PUBLIC_FILES.json` are compared. Copies of each real server record reject counts
142, 145 and 147 in the report, trace and both together, plus changes to role,
TLS version, group, ALPN and sequence. These are reader controls, not additional
hostile network runs. The original P0 checkpoint retains the old-reader red result.

The SDK report has SHA-256
`1e40fc2ae0c7c113509ae2a5c5a858cbd73a8a6fd7f63e66203316c4c61e228d`;
the candidate archive has
`0730aa20794527b3947dc4734bf82d48516294c42018dc8dfd23ebc5f42fc2a6`.
All 1,401 package inputs match the original source snapshots. Each profile's
candidate and nine SDK trees outside the checkout match the actual archives.
OpenSSL 3.5.9 peer, CLI, header and linked-library fingerprints are rechecked.

Each one-profile `C_CONSUMER.json` has `partition_completed=true` and
`completed=false`: the latter requires both profiles within that invocation.
Both completed C partitions are available here. This does not assert completion
of the enclosing JNI runs or independently replay every other C scenario.

[CAPTURE.zip](CAPTURE.zip) contains 584 members, is 28,498,958 bytes and has SHA-256
`6a0ac44c8a7713a9b9b7a8dd30b94c6829e76861824658d79f37b3d046d3cfb5`.
It retains each C client/library, OpenSSL peer and Rust Witness helper, ten
consumed archives, original command/component reports, relevant source/readers
and diagnostic history. It excludes private protocol stores and keys. External
tool dependency fingerprints do not imply a self-contained Xcode/OpenSSL runtime.

[FILES.json](FILES.json) pins every member. [READBACK.json](READBACK.json) records
the installation checks, eight component rereads and 28 altered-evidence refusals.
[ARCHIVE_READBACK.json](ARCHIVE_READBACK.json) then verifies every captured byte
and replays all eight public transcripts without reading private runtime state.
That replay does not rerun native workloads or altered-input controls. The
[replay script](replay.py) takes `CAPTURE.zip`, `FILES.json` and a fresh output
JSON. Run it through the matching checkout's isolated `artifact/python-run.sh`;
it compares local reader bytes with the captured source closure first.

Three unsuccessful diagnostic attempts remain captured: an inventory expectation
omitted the generated `PUBLIC_FILES.json`; a native-TLS log lookup omitted its
original `-trace-` label; SDK archive selection omitted the producer's `crates/`
directory after both profiles had replayed. The final driver checks the manifest's
exact schema, original command labels and actual archive locations. Producer
data, protocol checks, timeouts, installed sources and native runs are unchanged.

This closes the selected current same-host P0 Debug/Release evidence. OpenSSL
supplies independent TLS; Witness state/signature logic remains shared. Full JNI,
cross-host/platform qualification, final CI, Continuity ABI 2 admission, protocol
proof, external review and release remain separate.
