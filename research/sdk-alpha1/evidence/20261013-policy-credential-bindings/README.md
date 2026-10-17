# Credential issuer inputs and G after independent P

This checkpoint exposes the existing core credential-renewal issuer request through
C, Swift and Android. The request includes the immutable original identity/P0,
acknowledged predecessor credentials/roster and current policy authorization. It
is neither a reservation nor an approval; the issuer separately authenticates,
authorizes and deduplicates the retained original operation.

Android also exposes extended G coordination metadata with distinct joint-T and
independent-P fields. It rejects malformed lengths, domains, modes, counters and
nonzero unused tails. JNI encodes explicit fields rather than native padding;
large request buffers are allocated before owner admission. Shared metadata and
codec helpers avoid copying the protocol into separate language state machines.

## Executed scope

- Six host Java/JNI routes: local, signed witness and mutual-TLS witness, each with
  fixed/recoverable trust. All 332 fresh foreign processes completed.
- Independent root issuance uses the actual exported request, checked against
  registered identity and independently approved P. The original P0 really
  expires before P and then G. The next issuer request retains P0/original C/R
  while advancing its actual predecessor to the renewed C/R.
- Required-witness routes lose the actual committed reply and reconcile its
  original operation; later history sends no fresh G Commit/Close. The native
  counterparty independently admits G. Original session/message identity and
  one business effect survive the complete P/G sequence.
- Swift: 74 source-linked tests, including typed request layout, owned public
  records, unsigned boundaries and unchanged request output on C failure.
- 58 artifact/inventory/adversarial readback tests and native Clippy with warnings
  denied. This is not an independent protocol implementation or a release verdict.

`HOST_REQUIRED_CAPTURE.zip` preserves the two originally successful required
routes and their reader failure. `HOST_REMAINING_CAPTURE.zip` contains the other
four successful routes. Public exports contain no device/issuer private keys.
`COMPILED_SOURCE_LINKAGE.json` compares the actual compiled C/Java/JNI product
inputs with the current product sources. `CHECKS.json` retains the test-harness
failures and their causes.

The first local test incorrectly used the joint G/T reconciliation API after an
independent P; the core correctly refused it. Local G under P completes via the
existing consuming `activatePolicyRenewal` path, followed by a fresh enrollment
for status. The test was corrected; core admission was not weakened. A later
fixture misuse read status after ownership transfer and was similarly corrected.
The signed fault injector needed its explicit partial-reply marker. The public
reader's 03 flag precedes its retained-P digest; fixing those offsets revalidated
already completed native runs without reopening their private state.

## Accepted Android physical execution

`ANDROID_CAPTURE.zip` records signed/fixed, mutual-TLS/recoverable and
local/recoverable routes on the accepted API 37 arm64-v8a phone: 166 independent
ART processes through the R8 release APK. Every operation records the installed
APK digest and public result digest, with process absence after force-stop.
All three routes passed the same native issuer/witness and original-message
checks. Each fresh application installation was uninstalled and all owned ADB
reverse mappings were removed. No previously accepted device cohort was reopened.

The AAR Java JAR is byte-identical to the host-tested JAR. Both packaged native
libraries have at least 16-KiB ELF segment alignment. The physical phone's observed
kernel page size was 4096 bytes. Package boundaries, executable identity, process
outcomes, public readback and cleanup are recorded separately in the capture.
This workload uses ADB reverse transport to the host peer/witness.

## Remaining goal work

This binding checkpoint does not close the full 0.2.0 goal. Complete installed
Swift/Apple P/G issuer and session workflows, current CI (including Rust CodeQL),
broader repeated lifecycle/package admission, independent implementation/host
coverage, protocol/PCS review and complete product-path performance remain separate
obligations. The new Android local joint-T reconciliation/historical wrappers have
input and FFI boundary checks; these independent-P workloads do not qualify a full
joint-T execution through those wrappers. One accepted API 37 physical Android device is the agreed Android
hardware acceptance target; an API 36 device is not an additional requirement.
