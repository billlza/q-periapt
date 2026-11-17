# SDK 0.2.0 Apple signing execution and independent readback

Producer source: `b327970189259ac3a5dd2353db4a90b178a72431`.
This is actual qualification of the new signing path, before the coordinated
Continuity product freeze. It is not a public release or a final frozen cohort.

The existing `swift-xcframework-release.sh --profile sdk-020` entry point
completed from a clean standalone source clone. Its detached build source was
rechecked and removed only after the distribution and completion record were
retained. The four native targets, 51 SDK exports per architecture, closed
archive layout, build-path hygiene, licenses and BOMs passed their existing
checks. Developer ID signing used team `YKUPL7Z869`; the exact leaf certificate
and secure timestamp are retained in `APPLE_DISTRIBUTION.json`.

Both the native ZIP and complete Swift SDK ZIP were verified after extraction.
The original host consumer ran six tests with zero failures. A fresh complete
package installed outside the checkout ran another six public API tests,
verified its signature before and after testing, and proved SwiftPM selected
the packaged macOS archive. macOS arm64, iOS arm64 and both simulator
architectures passed their linkage checks without warning/error diagnostics.
These linkage checks do not claim a new physical-device execution.

| Actual artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `CQPeriapt.xcframework.zip` | 14,207,346 | `a64889174ff3490ad0da72a3cdad8c311a3e7a28b61ca921769861a695bc0f06` |
| `QPeriapt-Swift-SDK-0.2.0.zip` | 15,754,663 | `8278a687e0c6253f7254f864748a56d005257ede4a17ab758678a524d8d2bb2a` |

The separately executed `readback.py` consumed the producer's clean source,
with independent expected commit and artifact/certificate digests. It checked
562 selected source inputs and the Rust workspace digest, replayed the signed
distribution projection, extracted and verified all 607 SDK package files,
checked the 14 native files, and ran strict `codesign` verification on that
fresh extraction. The five installed-consumer log hashes and original host
consumer log also matched. `READBACK.json` distinguishes its new verification
from the producer's previously executed tests.

The two ZIPs and original logs remain under the local task's
`target/release020-finalization/apple-build-attempt02/target/` tree. This
directory retains portable manifest, distribution, completion and readback
records; `SHA256SUMS` names the original distribution files, not files copied
into this evidence directory. Raw logs and linked probes are retained locally,
including private temporary paths, and are not claimed as public release assets.

The preceding attempt stopped before compilation because its explicitly
selected isolated Cargo home had not yet been created. Its source and raw log
remain retained. After creating that directory, a separate clean source clone
completed the execution above. Neither failure state nor previously produced
distribution bytes were replaced.

The implementation's 168 Apple distribution, SDK, legacy publication and
readback controls passed with Python warnings treated as errors. The added
`CodeResources` tamper control fails on the preceding implementation and passes
after the fix. The post-execution retention adjustment copies the 15 selected
consumer logs/probes (20,065,784 bytes) instead of Xcode's derived-data caches;
all 15 selected original files were independently checked to exist as regular
files. The signed artifacts above retain their original producer identity.

Final source qualification, internal finding reconciliation, normative freeze,
final artifact selection, registry/GitHub publication and public installation
readback remain separate release work. No `v0.2.0` tag or public release was
created by this signing execution.
