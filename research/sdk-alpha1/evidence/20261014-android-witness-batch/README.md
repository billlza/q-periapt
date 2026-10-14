# Concurrent host qualification of witnessed joint updates

Eight fresh signed-TCP/mutual-TLS, fixed/recoverable, Applied/Closed routes ran
with four native test threads. All 364 foreign Java/JNI process invocations and
all eight native tests passed. The native test receipt records 730.15 seconds;
the controller, including public export and readback, records 732.26 seconds.
Both fit the unchanged 900-second command bound. This is an observed host
qualification duration, not an application latency or energy benchmark.

The previous qualifier invoked all eight routes serially. Each route requires
two real 180-second policy validity windows. The new batch runs two waves of
four without changing either window, any security assertion or any scenario.
Every route now owns a named child directory. The complete eight-test receipt
is required before reading any outcome; missing, duplicate or failed tests are
rejected. Original journal, witness and credential-operation identities must be
distinct across all eight routes. Public export is independently reread.

The run used a newly built native test executable and entirely new installation,
journal and witness state. The Java/JNI/C engine inputs remain the retained
package cohort; their hashes were checked before and after execution. No accepted
or protected old cohort was reopened. `CAPTURE.zip` retains public records, exact
producer hashes, build/execution receipts, the three changed source files and
the related Python checks. The full private fixture and executable remain local.

The change affects test scheduling, directory isolation and result admission.
It does not change the Android public API, JNI dispatch or protocol engine.
Physical ART acceptance is the previously retained single-phone evidence; this
run adds no new device claim. The standalone batch was Debug; complete installed
Debug/Release CI, all release gates and second-generation foreign G/T execution
remain separate requirements. No overall release-readiness claim is made.
