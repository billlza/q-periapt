# Android 16-KiB full-profile post-install failure

Push job 113805908369 at `a671719e` installed the full consumer APK successfully,
then failed installed-package ownership admission before Instrumentation. The
two APK reads produced 261632 and 0 bytes instead of 13723600. The owned ADB
server recorded connection termination at 11:58:08.623 and 11:58:21.024 UTC.
The existing single transport recovery did not restore sustained communication;
the admission deadline expired and application cleanup remained unresolved.

This differs from the prior `b1006eb3` failure, which passed the full SDK tests
and failed during minimal-profile admission. Neither failed admission executed
the affected profile's SDK Instrumentation. The newer guest log records low
memory kills of unrelated applications before the disconnect. This is an
observation, not proof that memory pressure killed adbd or caused the transfer
failure. No timeout, retry, memory setting, identity check or SDK code was changed.

The parallel PR job 113806720320 passed both profiles and Linux replay job
113812088286 completed successfully. Its actual checkout `ff88b033` and push
checkout `a671719e` have the same Git tree. The successful 73252400-byte runtime
artifact was downloaded and matched GitHub's SHA-256. The retained full/minimal
Instrumentation outputs and build receipts were read back from the artifact
and checked against their recorded sizes and hashes: three full SDK tests and
one minimal runtime-version test passed. The AAR digest recorded by both
successful profiles is `8a31d195c7a9cf612a782519f8430cdec4f4201984138af6e254f6695d560a48`.
The complete replay was not rerun locally.

`CAPTURE.zip` retains the original failure diagnostic archive, extracted logs,
job/run/artifact metadata, actual checkout identities and selected successful
proofs. The large successful artifact remains at the path in `MANIFEST.json`.
Passing parallel evidence does not resolve the failing job or establish stable
device communication. The root cause remains open.
