# Kotlin registered-device publication component

The private Maven consumer exercises the new typed device publication API through
the shared native C/Rust engine. The Kotlin module and consumer were compiled from
the exact inputs in `QUALIFICATION.json`; the native component is source-identical
to commit `a71195ec72e83a270a6af096e38d50f92ca3f08c`. The final source commit can
contain this receipt without treating its own future hash as a build input.

Observed on macOS arm64, private JDK 25.0.4.1+1, Gradle 9.8.0 and Kotlin 2.4.20:

- All 58 named JVM tests passed with each Debug/Release native library, strict
  dependency verification and compiler warnings as errors.
- A separate consumer outside the checkout resolved the exact Maven JAR and two
  pinned runtime dependencies. Installed bytes matched recorded resolution bytes;
  no project dependency or checkout dependency path was accepted.
- Debug/Release × Serial/G1 each completed original registration, publication
  preparation, exact artifact retry after process reopen, cancellation, status and
  public-history retirement, then normal TLS/application consumption. Each run
  retained 85 public readbacks. The native harness verified signatures and every
  membership proof; the Python reader independently checked public structure and
  identity. These are separate checks, not an independent protocol implementation.
- Eleven artifact-reader tests passed. Their explicit report inventory includes
  every new JVM test report and the existing CI upload patterns retain them.
- The unchanged native source also completed all 816 library tests, including the
  final-member-expiry regression. Its full input hashes and logs are retained here.

`CAPTURES.zip` has 428 members, 340,545 bytes, SHA-256
`e0819d05a2db9283f0c233fab59a625963cb49d25dbc46af135ba56a8ca915fc`.
The archive retains commands, results, test reports, public readbacks, Maven
metadata, runtime closure and initial refusals. Private journals, wrapping keys
and signer state are not included. Initial failures and their specific corrections
are listed in `QUALIFICATION.json`; no admission or verification gate was relaxed.

These are private Maven/component runs, not completed distribution-archive or
release qualification. The library copies retain the previously qualified local
`@rpath` layout. The C-specific short-buffer probe is covered by the separate C
component and was not executed by the Kotlin CLI. This workload's subsequent
traffic still uses the remote fixture advertisement, so it does not close the
successor-owned advertisement requirement. GC configurations are recorded; this
does not prove collection occurred in every call or qualify every JVM collector.
No public package registry publication, merge or release occurred.

The separate `NATIVE_PREFLIGHT.json`/ZIP records clean standalone source
`6a1f1f0b6cba3b92a86b8ff3a92547ab0b40cf5f`: source gate, 44 CodeQL-quality
reader tests and 2,665 full artifact tests passed. That source predates the
Swift/Kotlin publication wrappers; current-head preflight is a separate gate.
