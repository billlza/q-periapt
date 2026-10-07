# Options-prefix boundary and durable policy exhaustion

Source: `6e520a99210e1be254fb95ae2a4b4ce546ab8d14`, macOS Apple Silicon.
The five C constructors now inspect size, then revision, before reading complete
pointer-bearing options. Unsupported headers return `ERR_LIMITS` without changing
output. Supported headers still require the full initialized structure and valid
buffers. This rejects short/unknown layouts; it does not accept older layouts or
validate arbitrary pointers. No export, declaration, layout or status value changed.

`guard.c` puts the aligned two-word prefix immediately before a PROT_NONE page.
All ten size/revision cases terminated with SIGBUS against the retained old release
library (`ddb0c6c...`). All ten passed against the new release library. These inputs
violated the old documented complete-structure contract: the observation supports
a defensive boundary extension, not a demonstrated remote exploit. The ordinary
portable C SDK smoke also includes exact four/eight-byte allocation cases for the
shared platform consumers; execution in this checkpoint is macOS ARM64 only.

FFI Debug and Release each passed 43 tests. Host-store passed 37 tests, including
real commits, process cuts and the new exhaustion case. Strict Clippy passed for
SDK/host-store/FFI; all three ABI mutation tests passed; regenerated C/Swift headers
have identical declarations and the actual dynamic library retains exactly 43
expected exports. Rustfmt and git diff whitespace checks passed.

A clean standalone checkout produced and installed the C archive without a dirty
source override. Four pkg-config consumers, the frozen legacy-header consumer and
four CMake tests passed outside the checkout. Public revalidation with independently
pinned archive/manifest/contract identities repeated those checks. Twenty further
protected-page calls passed against those installed shared/static libraries.
The archive is 6,108,020 bytes, SHA-256
`3401b6c3c79a504c5fc79bbb8d2734fbcd77c9f9fb919c74324fc1f0a96f82db`;
manifest SHA-256 `bb4362e08160177f7974e8732275088a4f0afaa940f66e671be3cfbee07e8857`.

The policy test is characterization, not a root-recovery fix: an enabled policy at
u32::MAX still cannot accept a same-version/lower-version emergency disable, even
after reopening. A separately valid root is rejected by the existing store.
The first attempted test did not compile because a core signing error did not
implement std::error::Error; the explicit conversion fixed that test-only issue.
Both attempts are retained, and no compile failure is presented as a security red.
The authority RFC now distinguishes fixed-root enforcement from missing dynamic
succession/recovery and corrects its obsolete nine-export-only ABI claim.

`raw-records.json` losslessly preserves local runner commands, complete source
fingerprints and stdout/stderr as gzip+base64. Decode each entry, check its byte
length and SHA-256, then inspect it as ordinary diagnostic data. `manifest.json`
hashes every retained file. This is local component/package qualification; root
recovery, Continuity authority migration, current remote CI, other platforms and
full release admission remain open. No package was published.
