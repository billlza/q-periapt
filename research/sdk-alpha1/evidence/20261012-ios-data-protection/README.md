# iPad Complete-protection and original-state recovery checkpoint

The installed Swift binary candidate passed one real lock/unlock cycle on the
explicitly offered iPad Pro 11-inch (M4), iPadOS 27.0.1. This is a bounded
closed-owner storage result: fixed and recoverable SDK trust, two fresh
on-device identities, five app launches, and independently verified original
registration requests. No product SDK code changed for this checkpoint.

The app uses the same extracted Swift/XCFramework candidate as the
[installed-package checkpoint](../20261012-ios-binary-package/README.md), SHA-256
`f205d19d560584d1f80a85bc8631f76787db96eb35580b94ee6d5b37659b15bc`.
It builds in Release with Swift 6 strict concurrency and warnings as errors,
without custom SDK header/library search paths. The native host issues signed
inputs after verifying requests created by the device; it never supplies a
prebuilt SDK database, wrapping key, signing key, enrollment or journal.

## Observed behavior

1. Each profile creates its identity, accepts an independently issued grant,
   prepares local storage and activates. Original public request, signing ID,
   journal ID and next publication ID are retained for exact comparison.
2. All SDK owners close successfully. The host app sets `FileProtectionType.complete`
   on the private directory tree and checks all 40 entries. A further unlocked
   reopen succeeds before the lock baseline is recorded.
3. A user locks the iPad. The Scene-based app obtains a bounded UIKit background
   task and actually observes `isProtectedDataAvailable == false`. A public
   sentinel under Complete protection fails `open` with `EPERM` (1). Both SDK
   `prepareOpen` / `finishOpen` attempts refuse with **702**, the host-store
   private-file error. Neither a mere background transition nor a timeout counts
   as a protection pass.
4. After the user unlocks the iPad, the original namespace, file type, size, inode,
   modification time and protection classes match the pre-lock baseline. Both
   installations reopen and activate with byte-identical original public requests,
   signing IDs, journal IDs and next publication IDs. The native host independently
   verifies both original request signatures again.
5. Every launch has an exact run-bound host startup admission, terminal exit 0 and
   matching container receipt. The run-owned app is uninstalled and its absence
   is observed. Device-generated private state is never copied into the capture.

`702` follows `OpenConfiguration::open` → `PolicyStore::open_inner` →
`open_private_file` → `StoreError::PrivateFile`. This is the existing failure
mapping, not a newly introduced universal “device locked” status. Applications
must not interpret every 702 as transient lock state or retry indefinitely.

## Evidence and reproduction

[CHECKS.json](CHECKS.json) records binary/package identities and the result.
[CAPTURE.zip](CAPTURE.zip) contains 178 checked members plus its manifest:
public records, device startup/exit/receipt logs, native verifier output, app and
qualification-driver sources, build logs and package provenance. The archive is
extracted and its verification repeated. Its SHA-256 is
`64cd934c891329f92f9a69f739ed47401cae55af6453aca355863480ad7fbb24`.
The native fixture extends the installed fixture sources retained by the
[iPad root checkpoint](../20261012-ipad-root/README.md).
[FIXTURE_SOURCE.json](FIXTURE_SOURCE.json) verifies all 867 reused files
byte-for-byte against that checkpoint; only the archived protection test is added.
[COUNTERCHECKS.json](COUNTERCHECKS.json) records six altered captures refused by
the same reader: changed original/restored identity, wrong locked refusal, missing
locked proof, missing startup admission and missing receipt.

The successful commands were:

```sh
QPERIAPT_PYTHON=/opt/homebrew/opt/python@3.14/bin/python3.14 PYTHONPATH=artifact \
  sh artifact/python-run.sh target/continuity-ios-data-protection/build_app.py
QPERIAPT_PYTHON=/opt/homebrew/opt/python@3.14/bin/python3.14 PYTHONPATH=artifact \
  sh artifact/python-run.sh target/continuity-ios-data-protection/run_device.py
QPERIAPT_PYTHON=/opt/homebrew/opt/python@3.14/bin/python3.14 PYTHONPATH=artifact \
  sh artifact/python-run.sh target/continuity-ios-data-protection/capture.py
```

The native verifier test is
`ios_complete_protection_preserves_original_identity`: one passed, zero failed,
zero ignored, three unrelated fixture tests filtered out. A prior trial called
`status()` on an enrollment after `activate()` transferred its owner; it correctly
failed with code 2. Its source and failed logs are retained separately, and it is
not counted as a successful launch. The corrected harness reads enrollment
metadata before transfer and uses the successor for operational checks.

## Integration boundary

Complete protection is chosen and applied by the host app; the SDK does not
silently set a protection class or create background tasks. Apple documents
[protected-data availability](https://developer.apple.com/documentation/uikit/uiapplication/isprotecteddataavailable)
and the
[pre-unavailability notification](https://developer.apple.com/documentation/uikit/uiapplication/protecteddatawillbecomeunavailablenotification)
for coordinating file release. This checkpoint exercises a planned, successfully
closed installation before locking. In-flight callers still need the existing
cancel → join → throwing close contract; a Busy close does not release the owner.

This result does not establish erasure of live owner memory, behavior of still-open
file descriptors, interrupted writes, witness availability while locked, reboot,
physical power loss or an automatic application lifecycle manager. Canonical
release-pipeline integration and simulator execution remain separate work. It
also does not qualify a new protocol implementation or close the full 0.2.0 goal.
