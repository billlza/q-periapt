# Foreign successor TLS and durable message consumption

The generation-replacement workload now uses the existing C, Swift and Kotlin
enrollment-parent connection APIs for the successor's actual traffic. A separate
client process opens the admitted generation-2 device and serves its fresh TLS
bootstrap. Another process reopens that exact session and durably consumes the
application message. The native sender checks both returned identities and the
complete host effect record. Callback counts must show one invocation and one
new effect; the existing reentrant-close and application-confirmation checks stay
active. No product API or foreign client implementation changed.

The workload uses the shared payload already strictly accepted by all three
qualification clients. The public reader checks its complete bytes together with
the original session/message identities. It also requires two distinct traffic
process IDs, separate from the ten enrollment and eight retirement processes.
Native-only, missing, reordered or reused process evidence is rejected. Empty
logs are valid during startup or for successful stderr; authenticated input
records retain their nonempty rule, and logs have a separate 8192-byte bound.

All eight profiles passed on macOS arm64: C and Swift Debug/Release, plus Kotlin
Debug/Release under Serial/G1. Each executed twenty foreign processes. The full
native connection/replacement regression, Rust 1.90 compile check, Rust 1.98.1
strict Clippy and 25 affected artifact tests also passed. GC configuration alone
does not establish that collection occurred in every individual trace.

`QUALIFICATION.json` and `CAPTURES.zip` bind source hashes, commands, actual
consumer/library/harness hashes, public records and client outputs. The harness
is a development build using previously qualified installed C/Swift consumers
and a private Maven Kotlin consumer. It is not complete qualification of new
distribution archives. Private databases, wrapping/signing keys and TLS private
keys are excluded.

The prior commit `67e1a5b0` passed its clean-source gate, 44 CodeQL quality tests
and all 2661 artifact tests, then was pushed to CI. That CI run excludes this
newer traffic change. Its Rust CodeQL analysis is preserved until analysis,
quality, upload and diagnostic retention complete.

Account issuance, witness replacement commit and successor prekey preparation
remain native Rust. The endpoint processes share the same protocol engine and
physical host. Complete developer-facing prekey publication, new archive
qualification, independent implementations, physical/minimum-OS coverage and
overall 0.2.0 admission remain open.
