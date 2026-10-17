# Clean macOS ARM64 C SDK archive

Source `814721fafbdffdc0a6cd4ee2cce7fb90289413c2` was built from a clean,
standalone checkout using Rust 1.98.1 without the dirty-source override. The
producer executed four external pkg-config consumers, one frozen-header consumer
and four CMake tests through shared/static linkage. The same archive then passed
the public archive verification entrypoint with separately supplied expected
archive, manifest, contract, target and version values; all consumers ran again.

The 6,107,734-byte archive SHA-256 is
`adeb1fff4412a6e7691aafa0dbdc3d7f3c411b90e59ad3f7cfc192e789875445`.
Its manifest SHA-256 is
`09b9265be84936ebe34a258d4de700481a5aa17225e605d6f0c0a7be9dd0168a`.
The library/header preserve the 43-export ABI. The legacy consumer includes the
new invalid-span boundary cases. This closes this source's local clean C package
and revalidation checks, not the full SDK/Continuity connection, independent
endpoint, platform/device, current later CI, signing or release requirements.

The exact producer and public revalidation commands, raw logs (JSON-encoded),
package manifest and consumer receipts are retained here. The archive remains
at the local path in `qualification.json`; it has not been published.
