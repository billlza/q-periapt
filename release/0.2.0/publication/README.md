# Q-Periapt 0.2.0 publication verification

Both stable release tags remain at the admitted evidence commit
`7c154548d03354a03e91f086b000197026884c0f`. This later metadata-only commit retains
the actual public verification results; it does not replace source qualification.

The GitHub receipt records verified immutable-release signatures for both tags
and freshly downloaded, byte-exact matches for all 67 admitted assets. Its two
raw release-verification responses are retained alongside it. The asset files
remain in the two public releases; this commit does not duplicate them.

The registry receipt is a later read-only observation of all twelve non-yanked
0.2.0 versions through both the official API and sparse index. The separate
archive-download receipt records twelve unauthenticated static.crates.io
downloads matching the admitted archive bytes. No consumer runtime is inferred
from these public-download checks.

The first final registry readback stopped at the local source-integrity guard:
syntax checking the task's closure scripts had generated two Python bytecode
caches. Those exact temporary files were preserved outside the source checkout.
The unchanged owning verifier was then run again. The failure, diagnosis, repair
and actual successful receipt binding are retained under registry/readback-attempt01/.
The guard was not relaxed and no registry upload was repeated.

The selected product source is `af4618c8065d7133adfb86e1d116577089161ff0`.
Its required 72-job CI, independent checks, CodeQL and other admission decisions
are preserved in the parent release evidence. Extra workflows triggered by
publishing metadata tags retain their own source identities and outcomes; the
attached snapshot is not a claim that every additional workflow has completed.

The extra reference-account run also retained a cancelled Linux checkout that
spent its full 60-minute job bound in a shallow tag fetch, before product
execution. Its absent-output retention error remains in the original log. That
job alone was retried once; the actual terminal outcome and both observations
are retained under reference-checkout/. The stalled-fetch cause is not promoted
to a proved network diagnosis, and this is not a replacement qualification run.

The post-tag SDK-free Android platform diagnostic failed one of three trials.
With the API 35 / 16 KiB image at its observed default 2560 MiB, system_server's
HeapTaskDaemon crashed in ART MarkCompact::ScanObject. No SDK installation was
attempted. All three original captures are retained, including both passes.
The SDK's passed API 35 profile uses an explicit 4096 MiB configuration. The ART
root cause and the causal effect of memory size remain unestablished; the
default-memory platform failure is not marked fixed. DISPOSITION.json's original
local reference prefixes identify the source capture; the identical files are
retained here under android-platform/ and indexed in VERIFIED_COHORT.json.

The previously captured Windows OS997 failure also remains an unresolved cause,
as documented in the parent evidence. The selected Windows matrix passed.
No new physical-device, Intel macOS or cryptographic theorem claim is added.

Public releases:
- https://github.com/billlza/q-periapt/releases/tag/v0.2.0
- https://github.com/billlza/q-periapt/releases/tag/abi2-platforms-v0.2.0
- https://crates.io/crates/q-periapt-sdk/0.2.0

VERIFIED_COHORT.json hashes the retained files. Its own bytes are identified by
the later annotated verified-cohort Git tag, avoiding a self-referential hash.
