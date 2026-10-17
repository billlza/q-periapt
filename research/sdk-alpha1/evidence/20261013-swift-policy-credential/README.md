# C and Swift: original session through independent P, then G

This checkpoint adds first-use C and Swift consumers of the existing credential
issuer-request and extended policy-continuation APIs. It uses a verified original
registration, a real P0 expiry, an independently authorized policy renewal P,
and then same-key credential renewal G under P. It does not add another protocol
implementation or change the production engine.

## Completed host execution

`HOST_CAPTURE.zip` preserves eight fresh source-linked executions: C and Swift,
with signed or mutual-TLS witnesses, each under fixed or recoverable SDK trust.
Every route exports the actual public issuer request, verifies its original
identity/P0 and current policy authority, rejects a bad grant signature, loses
the actual G committed reply, and recovers the same operation from history.
The counterparty independently admits G; the original session and message are
acknowledged with one business effect. A subsequent issuer request retains the
original credentials and advances the acknowledged predecessor.

The C and Swift tests use the shared native issuer/connection state machine and
small language-specific operation dispatchers. P and joint-T proposal fields
remain distinct. They do not copy the renewal protocol into each binding.
The new request buffer is heap allocated in the C consumer. This checkpoint
makes no latency, allocation or energy improvement claim.

The initial two host executions reached the final public export but failed
because its new child directory was created with mode 0755. The private-file
publisher correctly refused that directory. The fixture now explicitly creates
it with mode 0700. The failed executable and logs were retained; all eight
accepted routes use a fresh directory and the corrected executable.

`HOST_CAPTURE.json` records the archive identity and route results. The archive
SHA-256 is `10163960793c8d1520647769c83fa0235e40a6cdf0573ec376a8da9ab159c35a`.
It contains public protocol records and command results, not private device
journals or issuer keys. Artifact-reader controls validate all eight routes and
reject altered issuer/P/predecessor bindings, malformed proposal domains,
incorrect history, missing process results and unexpected private output.
Historical seven-test captures remain readable; current producers require the
expanded eleven-test catalog. CI uploads the added public P/G readbacks.

## Actual Apple package preparation

The production inputs are the nine SDK Cargo archives and the candidate Cargo
archive from `eeba648417bdcec469cccbd6a332f813e12c6df9`, with locked/offline
package verification and installed-path dependency resolution. The new
qualification consumers exercise that unchanged production code. A fresh Apple
archive was built with Rust 1.98.1 and Xcode 27.0 (27A266a), containing only
ARM64 macOS, iOS and iOS-simulator slices. It passed the exact C export inventory,
archive extraction, macOS public-owner probe and Apple consumer build checks.

The Apple candidate archive SHA-256 is
`5ce4baf49e64f77d29117503fd62dca193962bf5a4565c08df1c15854f055eae`.
The physical application links the extracted XCFramework through its Swift
package, without source-library/header search-path substitutions. Package
construction and physical execution are recorded separately.

## Installed macOS execution

All four Swift routes also completed using the extracted Apple package on
macOS ARM64: signed and mutual-TLS witnesses, each with fixed/recoverable trust.
The executable was compiled against the package's supplied Swift wrapper and
XCFramework. Its dependencies contain no workspace engine dylib. These are fresh
cohorts with their own original registrations, sessions and messages; the earlier
source-linked cohorts were not reopened.

## Accepted installed iPad execution

All four witness/trust combinations completed on the offered iPad Pro 11-inch
(M4), iPadOS 27.0.1: signed/fixed, signed/recoverable, TLS/fixed and
TLS/recoverable. The accepted paths contain 186 independent app invocations
(47 per signed route and 46 per TLS route). Each retains its own original
registration, session and message through P0 expiry, P, G, lost committed reply,
exact historical recovery, counterparty admission and one business effect.
The actual installed application and the installed Mac consumer use the same
Apple archive identified above. Transport is an opaque USB relay to the host's
peer/witness; these are not Wi-Fi performance measurements or an independent
protocol implementation.

`INSTALLED_APPLE_CAPTURE.zip` contains four installed Mac and four physical iPad
public readbacks, signed-app and package identities, terminal operation receipts,
source/harness adaptations, startup controls, and failed attempts. Its SHA-256
is `8280057c8a59718e40cd88f44ee008bc40ab1e78e020d71398e3759543181088`.
`INSTALLED_APPLE_CAPTURE.json` records its route identities. All owned test apps
were uninstalled after collection; no accepted private cohort was reopened.

The physical adapter moves the same private-directory assertions into the app,
creates the account registry on the actual device, and keeps the native host
receiver's policy-target creation on the host. The 120-second external-process
budget accommodates CoreDevice overhead; the SDK's own protocol timeouts are
unchanged. Later app fixtures additionally verify the device's own clock has
reached signed expiry before the unchanged native 104-refusal assertion.

Failed attempts remain failed. One first attempt and one later attempt ended at
startup with exit 1 and no application diagnostic; their causes remain
unclassified. Another launch returned CoreDevice 1010 (unexpected EOF while
reading the socket identifier). A copied controller initially lacked its
executable bit and failed before any device launch; its owned file mode was
corrected. The test app then gained a run-bound USB startup acknowledgement
before SDK access, with actual correct-token/wrong-token controls, rather than
relying only on a fixed startup delay. This improves the observation boundary;
it does not retrospectively diagnose the earlier exits.

A subsequent attempt acknowledged startup but returned a durable Foundation
file-save error (NSCocoa 512, underlying POSIX EIO). After the user explicitly
unlocked the iPad and kept its screen on, both remaining fresh routes completed.
This supports an unlocked-device acceptance result, not a claim that the exact
file-protection or CoreDevice cause was proved or that locked-background
operation passed this checkpoint. No SDK authentication, expiry, storage or
reconciliation guard was relaxed, and no automatic operation retry was added.

Validation also includes 22 artifact reader/integration controls, strict Rust
format and diff checks, warnings-as-errors consumer builds, Android harness
compilation with its explicitly big-endian shared request decoder, and installed
executable linkage checks. The CoreDevice and public-fixture failures are not
silently counted as successful SDK executions.

## Scope still open

This checkpoint does not close the complete 0.2.0 goal. Current CI, repeated
whole-lifecycle/package admission, independent implementation and host coverage,
protocol/PCS review and product-path performance remain separate obligations.
Android's independent-P/G device results are retained in the preceding binding
checkpoint; its joint-T wrappers require their own full lifecycle execution.
No additional API 36 phone or Intel Mac is required.
