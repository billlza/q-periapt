# Kotlin restricted enrolled-device retirement

`ContinuityRetiredEnrollment` delegates the original inventory/report, host ACK
and journal/signer erasure to the same native engine. It reuses the existing
Cleaner, explicit close and call reachability fence. Authority inputs and report
outputs own their bytes; no raw handle, operational device or signer is exposed.
The private owner constructor is rejected by an actual Java 25 compilation and
produces no executable class.

A private local Maven publication is verified and consumed outside the checkout,
with strict dependency verification and an exact runtime JAR closure. Its JAR
SHA-256 is `696b3708c266badebb92649068db48961e011a79c1e23bf4a87d428f876890d6`.
The native engines are exact copies from the completed `ce70bf83` installed C
producer. Each Debug/Release × Serial/G1 combination passes eight actual JVM
cleanup processes, including pending-owner cancellation, wrong-purpose valid
signature refusal, exact reopen and three exits without completion. Original
registration also passes with Debug/Serial and Release/G1. All selected JARs,
launchers, engines and native harnesses retain their recorded hashes.

Both exact native profiles pass all 54 named JVM tests; the four new retirement
cases check layout/padding, immutable input ownership, malformed proposal/report
refusal and distinct erasure states. The 23 related artifact tests pass, and the
installed collector requires both GC configurations and retains all 54 test
reports. Running with Serial/G1 does not prove every trace triggered collection
or qualify every JVM's GC behavior.

Two integration failures are retained. The first consumer compiled successfully
but the runtime verifier refused dependency paths inside the source checkout;
a fresh outside-checkout consumer/cache/Maven directory passed the unchanged
rule. Three verifier-fixture expectations still counted 50 tests or omitted the
new XML; they now require all 54 tests and every report, without weakening gates.

`QUALIFICATION.json` and `CAPTURES.zip` bind code-copy hashes, actual commands,
XML, Maven files and explicitly exported synthetic public records. Private
databases, signer/wrapping files and TLS private keys are excluded. This is a
private Maven consumer over a qualified engine, not the complete distributed
Kotlin ZIP producer or an Android/WASM result. Replacement authorization,
independent full-report reconstruction and fresh-generation TLS here remain
native Rust. Full foreign replacement, independent implementation, physical
erasure/power-loss and broader release admission remain open.
