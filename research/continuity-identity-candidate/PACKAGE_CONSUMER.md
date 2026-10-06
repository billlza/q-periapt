# Installed Rust candidate connection

The crate remains `0.0.0`, `publish = false`, outside the SDK workspace and its
publication topology. This gate establishes a Cargo archive and Rust installation
boundary for the existing engine. It does not freeze Continuity, add foreign
bindings, publish a registry package or close the 0.2.0 release requirements.

`artifact/continuity_package.py` accepts a digest-pinned `RUST_SDK_PACKAGE.json`
and its twelve-crate cohort. Before compiling, it checks the current SDK source
identity and the nine consumed archives against their actual source members.
Candidate dependencies have exact `=0.2.0` requirements. Cargo packages and verifies
the candidate with these archive-derived SDK dependencies; no source path is left
in the normalized candidate dependency declarations. The original candidate
manifest, all packaged source members and the complete Cargo inventory are checked.

An independent Cargo consumer lives outside the checkout. It installs the nine SDK
archives plus the candidate archive using exact local registry patches and compiles
the public connection workload shipped in that archive. Cargo metadata must identify
those ten origins, both TLS features, and the candidate's unchanged unpublished
status. Every resolved external dependency must retain a registry source and the
version/checksum from the candidate's committed lockfile. Fetch is bounded and
locked; packaging, compilation and execution are offline with a fresh Cargo home.

Both Debug and Release execute the complete public service trace: independent
processes, original public enrollment and retained enrollment/service owners, confirmed bootstrap, application fsync
followed by process exit before receipt, exact retransmission after restart,
identity-signed network rekey, reverse traffic, lease contention, pre-cancellation,
durable SDK revocation, and cleanup-only restart after revocation. A test exit code
alone is insufficient: the gate checks the complete test set, reads both endpoint
application files independently and compares the retained cleanup identity across
the three cleanup processes. Strict Clippy and final package/source/lock/compiler
identity checks follow execution. Failure leaves a report with `completed: false`.

Run in a clean standalone checkout (the standard source gate applies), with a
previously qualified SDK cohort whose native sources match:

```sh
report=/absolute/path/to/sdk-rust-package/RUST_SDK_PACKAGE.json
report_sha256=$(shasum -a 256 "$report" | cut -d' ' -f1)
sh artifact/python-run.sh artifact/continuity_package.py \
  --report "$report" --report-sha256 "$report_sha256" \
  --toolchain-root "$(rustc +1.98.1 --print sysroot)" \
  --output target/continuity-installed-rust
```

The consumer's mode-0700 temporary directory retains private test keys and databases
for local diagnosis. CI uploads only the crate, public reports and command logs,
never this private directory. These are same-host Rust peers using one protocol
implementation. Cross-host operation, independent implementations, required-witness
network lifecycle, minimum/compiler/device execution and all foreign adapters keep
their separate acceptance requirements. The `continuity-installed-rust` CI job
uses the same run's SDK producer artifact; Linux results must actually finish
before being claimed.

`--with-c-consumer` adds the unpublished
[C owner consumer](../../bindings/c/ContinuityPackageConsumer/README.md), which
retains its own precise installation and verification scope. Its local traces
cover both application directions, complete revoked-session accounting and real
journal-sync process interruptions. Its explicit required-witness trace uses
the same native engine and an independently owned witness socket/store for actual
C bootstrap, application delivery, rekey and post-revocation cleanup. Lost committed
witness replies retain the original command with fresh challenge attempts.
The send case cancels a live C call after witness commit and a partial reply;
Busy close retains the owner, connected I/O releases promptly, and reopening
reconciles the exact command. Polling retains the original absolute deadline.
The archive-shipped fixture provisions/enrolls test state through public APIs;
it does not expose provisioning through the C owner API. The witness carrier is
signed TCP, so this does not qualify encrypted metadata, an independent witness
implementation, external service operation or cross-host deployment.

## Enrollment through the shipped connection

The ordinary bidirectional TLS trace now creates device identities through
`DeviceEnrollment::provision/request`, verifies each request against the account
authority's independently approved root and exact device metadata, signs the
credential with `issue_enrollment`, and admits the current roster through `accept`.
The same transaction prepares and activates the original installation. No private
signing key is exported. Every traffic restart opens the original enrollment and
retains `EnrolledDevice` while borrowing its existing service and signer.

`owner-mode` is explicit trusted fixture configuration. An enrolled path never
selects preconfigured installation recovery just because an enrollment file is
missing. Both devices' original signed requests, public keys, signing identities,
accepted/active/reopened journal IDs and real application effects are independently
read back. Two child processes probe the actual enrollment databases for Busy;
the ordinary connection now checks ten live database leases. Cleanup remains the
separate three-store, traffic-disabled recovery path after SDK revocation.

`artifact/continuity_enrollment.py` requires and exports exactly 46 public files
per build profile. Missing registration evidence or evidence naming a different
connection fails the package gate even if the old connection log reports success.
Native public APIs verify signatures; the Python reader checks framing, commitments
and cross-file identities and is not an independent protocol implementation.

The C/Swift/Kotlin setup fixture continues to use the explicit preconfigured-input
mode and leaves installation children absent before foreign setup. The separate signed-TCP roster-recovery trace retains its explicit installation
profile. Expired-bootstrap restoration now uses two enrolled devices in the same
account: after an application effect commits and its receipt is lost, the injected
protocol clock expires both the initial roster and prekey advertisement. Fresh
bootstrap and unrefreshed enrollment reopening fail. Both original registrations
then retain independently pinned current rosters and restore the exact original
session through their borrowed services, with unchanged context and outbox.

The package reader additionally requires and exports 44 public files for this
restoration, binding original requests/keys/credentials, expired and current roster
checkpoints, journal identities and the original session. It compares the actual
application effect and original ciphertext separately. Native APIs verify signatures;
the reader is a structural readback, not an independent cryptographic implementation.

These traces do not add foreign enrollment, remote account authentication,
credential/root/policy replacement or a complete identity lifecycle. Required-witness
registration activation now has a separate signed current-authority check; the
ordinary TLS restoration profile is local-only and does not stand in for a deployed
operator service or an independent witness implementation.

## Replacing an enrolled device generation

The complete Rust trace also exercises replacement under the local-only witness
profile. After the old receiver commits an application effect and exits before
returning its receipt, the independently retained account authority enrolls a new
generation of that device. The replacement creates its own signing owner, journal,
prekeys and TLS identity; it receives no private state from the old device. Closing
and reopening enrollment retains the exact original new-generation request and
accepted journal.

The sender explicitly admits the authority's newer peer roster. Its cached old
context then refuses release of the old message. Cleanup freezes that session and
exits before completion; independent recovery processes retain the same closure
identity, original message and ciphertext commitment, with zero acknowledgments
and one unconfirmed delivery. The original sender subsequently establishes a fresh
TLS session with the replacement and confirms a new application effect. The old
effect remains unchanged. A later signed roster that reintroduces the retired
generation is rejected after the sender has reopened its durable state.

`artifact/continuity_device_replacement.py` requires 49 public files per Debug or
Release execution and exports them as `<profile>-device-replacement-public`.
It checks original account/device lineage, distinct signing components and journals,
generation and roster advancement, effects and durable loss-accounting identities.
Native APIs validate signatures and private state; the reader is a structural
cross-check. Missing or inconsistent replacement evidence fails the package gate.

This reference relies on an available account authority and explicit trusted roster
delivery to the peer. It does not establish atomic replacement under a required
witness, global revocation of the lost device, account-root replacement, secret
migration, foreign-language replacement or physical-device qualification. Those
remain separate 0.2.0 requirements.
