# Installed macOS-to-Linux SDK connection

The complete Swift SDK ZIP consumer on macOS arm64 and a Rust peer built from
nine exact SDK crate archives on native Linux aarch64 passed all twelve unchanged
connection cases. The macOS installed baseline also passed twelve cases, strict
Rust/Clippy checks, Swift release/concurrency checks and static-library provenance.

Source identities are explicit: the host driver is `b20cafd7`, Linux harness
source is `33ca8c5c`, crate cohort is `de2c49e9`, and fresh Apple producer is
`33ca8c5c`. The installed producer verified compatible current product input
hashes; equal version strings alone did not admit these packages.

Linux ran as UID 1000 in a Debian 12/glibc 2.36 container inside a native aarch64
VZ VM (Ubuntu kernel 6.8) on the same physical Mac. A private pinned SSH TCP
forward transports encrypted SDK bytes without processing TLS. The isolated
adapter rewrites only the listener announcement. Linux and macOS maintain
separate persistent policy databases. The adapter copies the closed Linux DB
back solely for hash-checked evidence; its fixture transfer whitelist never
sends that DB back to the runtime.

Cases: roundtrip, concurrent, timeout, cancel, request-timeout, request-cancel,
runtime-revoke, mismatch, hostname, persist-revocation, reject-restart-rollback,
and persist-re-enable-and-reconnect. Original predicates and deadlines remain.
Ten owned SSH forwarders were checked closed; the idle task VM/container was
then stopped with disks preserved.

Three failed harness attempts remain in CAPTURES.zip: inherited SSH multiplexing
prevented readiness; a daemon-thread supervisor failed at interpreter shutdown;
and the final collector initially expected a local server DB. They are failures,
even where application observations passed. The fourth fresh attempt passed the
whole pipeline. The selected scripts, raw logs, package/linker identities,
transfer hashes and source records are retained with a closed MEMBERS.json hash
inventory. Private TLS keys, policy DB bytes, SSH private keys and binaries are
excluded; original local run directories remain available.

This qualifies the observed macOS-to-native-Linux OS boundary using the same SDK.
It does not establish independent physical hosts, an independent protocol
implementation, physical/minimum-OS devices, controlled performance or energy,
Continuity recovery security, signing/publication, or overall 0.2.0 readiness.
