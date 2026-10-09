# First configuration with required witness and actual traffic

The original first-use configuration now proceeds through real peer communication
and original-message recovery under all three protection/carrier selections:
local, required signed TCP witness and required mutual-TLS witness. Both fixed and
recoverable SDK trust profiles still begin with an absent target directory. The
sender creates its own wrapping key, device signer, enrollment and installation;
the independent host supplies signed policy, TLS identity and approved account
inputs. No private installation is copied into the sender.

Every case establishes a session, observes receiver exit 77 after durable
application effect, retains the sender's uncertain-but-committed original message,
then reopens the original configured registration/session and retries that exact
message. Acknowledgement, registration bytes, effect bytes and exactly one effect
file must agree. The C receiver also checks that retry invoked its idempotent
application callback once without creating another effect. This preserves the
host's deduplication responsibility; it does not promise arbitrary exactly-once
external effects.

Eight actual profile executions passed: C and Swift Debug/Release, and Kotlin
Debug/Release with G1 and Serial. Each executes all six configuration scenarios,
for 48 communication/recovery flows. Witness genesis is independently enrolled;
missing witness, bad receipt and wrong scope remain explicit failures. Responder
prekeys are prepared before the measured mTLS interval. During mTLS activation
and traffic, the signed-TCP witness capture must remain unchanged, preventing a
carrier fallback from satisfying the test. Both independently approved endpoint
subjects are provisioned to the TLS witness.

One common connection case is used by local and witnessed scenarios. Witnessed
receivers reuse the existing bounded C process helper from the account traffic
workload. The first-use examples now use the same fixed qualification plaintext
as that receiver; this changes test data only. Existing legacy/configured
registration and witnessed policy/roster traffic with rekey passed in both native
profiles after the helper extraction: three selected tests per profile. Strict
all-target Clippy and Rust 1.90 checks passed. Swift client builds deny warnings;
Kotlin clients build outside the checkout against the previously qualified Maven
SDK with strict dependency verification and warnings denied. SDK/core behavior,
product ABI 2 and the 132-export unpublished candidate interface are unchanged.

The required collector now explicitly selects and pins the C receiver as well as
the configuration sender and Rust harness. Foreign execution requires that same
receiver identity from the native baseline. An inherited receiver selection is
overridden; before/after binary snapshots reject substitutions. Four actual
collector profiles passed (C Debug/Release, Swift Debug, Kotlin Release/Serial),
including two real short-header guards, on top of the eight profile executions.

The reader requires twelve scope markers and exactly 64 public records across
six scenarios. For every carrier it checks original request/session/message,
uncertain outcome, acknowledgement and effect linkage. Eight validator tests
cover altered or truncated records, missing/duplicate markers, unlisted/private
files, a mismatched native receiver and receiver replacement before/during
execution. Signature verification belongs to the shared native engine; this
structural reader is not a second cryptographic implementation.

`CHECKS.json` retains commands, binary identities and source/readback hashes.
`PUBLIC_CAPTURE.zip` contains only selected public records, logs and qualified
consumer sources. Generated private runtime keys and databases are excluded.
The two shared Rust helpers are required members of the 444-file source census.
This is component evidence. A fresh complete installed distribution, final-commit
CI, continued-policy composition, independent protocol implementation, physical
and minimum-OS acceptance and the broader 0.2.0 release gates remain separate.
