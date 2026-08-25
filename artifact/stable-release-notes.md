# Q-Periapt 0.1.3 — ABI 2 stable release

Before this stable transaction, the published prerelease was `0.1.0-alpha.2`;
`0.1.0-alpha.3` was the working source line, not a published release. That working
line was first tagged as `0.1.0` but never published, then re-tagged as `0.1.1` and
again never published, then re-tagged as `0.1.2` and again never published (see the
0.1.0, 0.1.1, and 0.1.2 history below). This release carries the same source line,
plus the first-real-publish path corrections, forward as `0.1.3`,
while keeping the public C ABI at major version 2 and the exact nine-symbol export
surface. It is not an ABI 2.1 change and requires no ABI migration.

0.1.0 history: on 2026-08-21 the Apple distribution tag `v0.1.0` and the platform tag
`abi2-platforms-v0.1.0` were pushed, pointing at the results successor
`c4907760cc8320642c19cf177770f02a93f49c93`, under the no-bypass tag ruleset; they
are therefore permanent. The tag-triggered `ABI2 stable platform release` workflow
run `32477530879` built a sound six-subject candidate with valid build-provenance
attestations. The candidate verifier frozen in that source line
(`artifact/platform_candidate_attestation.py`) pinned two fields of the Sigstore
certificate summary to the wrong values: it expected
`certificateIssuer = https://token.actions.githubusercontent.com` and
`issuer = https://fulcio.sigstore.dev`, while the GitHub CLI reports
`certificateIssuer` as the X.509 issuer DN `CN=sigstore-intermediate,O=sigstore.dev`
and `issuer` as the OIDC issuer `https://token.actions.githubusercontent.com`. The
0.1.0 platform, Apple, and source publications were therefore never finalized: no
GitHub release, no crates.io publication, and no signed Apple distribution exist
for 0.1.0. Because stable tags are immutable and publication commits may change
only `artifact/results.json`, the correction ships as `0.1.1` (the same source line
plus the verifier fix) and 0.1.0 remains tagged, unpublished history.

0.1.1 history: on 2026-08-22 the Apple distribution tag `v0.1.1` and the platform tag
`abi2-platforms-v0.1.1` were pushed, pointing at the results successor
`dc3fa3037f620a987172eb798dcfaa814eb7e3bb`, under the no-bypass tag ruleset; they are
therefore permanent. The tag-triggered `ABI2 stable platform release` workflow run
`32572800739` built a candidate that verified successfully; platform assembly and both
the platform and Apple pending receipts were produced, and the Apple XCFramework was
Developer ID-signed. The coordinated GitHub-release publication could not finalize,
however, because a latent argument bug in the publication receipt IO staging helper
aborted the prepare step; that defect is now fixed on this source line. The 0.1.1
platform, Apple, and source publications were therefore never finalized: no GitHub
release, no crates.io publication, and no signed Apple distribution exist for 0.1.1.
Because stable tags are immutable and publication commits may change only
`artifact/results.json`, the correction ships as `0.1.2` (the same source line plus
the publication receipt IO fix) and 0.1.1 remains tagged, unpublished history
alongside 0.1.0.

0.1.2 history: on 2026-08-23 the Apple distribution tag `v0.1.2` and the platform tag
`abi2-platforms-v0.1.2` were pushed, pointing at the results successor
`533a6d63d8cca81d1757a84038cd046743f94539`, under the no-bypass tag ruleset; they are
therefore permanent. The tag-triggered `ABI2 stable platform release` workflow built a
candidate that verified successfully; platform assembly and both the platform and Apple
pending receipts were produced, and the Apple XCFramework was Developer ID-signed. This
was the first end-to-end coordinated GitHub-release publication run against real GitHub,
and it could not finalize because several code paths that only execute during a real
first publish carried latent bugs: a draft release is keyed under GitHub's synthetic
`untagged-<hex>` slug rather than the tag form; the publish transition validator
required `target_commitish` to be byte-identical although GitHub normalizes it from the
tag commit SHA to the default branch on tag materialization; three `OutcomeUnknown`
escalations persisted no reconciliation authority and wedged the transaction in
permanent manual review; the remote-consumer receipt over-constrained the XCTest
three-test-pass summary; and crates.io eventual consistency between its API and sparse
index was not tolerated on a first publish. Those defects are now fixed on this source
line. The 0.1.2 platform, Apple, and source publications were therefore never
finalized: no GitHub release, no crates.io publication, and no signed Apple
distribution exist for 0.1.2. Because stable tags are immutable and publication commits
may change only `artifact/results.json`, the correction ships as `0.1.3` (the same
source line plus the first-real-publish path fixes) and 0.1.2 remains tagged,
unpublished history alongside 0.1.0 and 0.1.1. The repository therefore carries eight
stable-named tags: `v0.1.0` and `abi2-platforms-v0.1.0` and `v0.1.1` and
`abi2-platforms-v0.1.1` and `v0.1.2` and `abi2-platforms-v0.1.2` (historical,
unpublished) and `v0.1.3` and `abi2-platforms-v0.1.3` (current); the tag ruleset must
protect all eight.

Here “stable” means a non-prerelease distribution channel plus the frozen C ABI 2
and exact dependency cohort. SemVer `0.1.3` remains a Rust `0.x` API line, not a
Rust API 1.0 compatibility promise; the ten internal crate edges remain pinned to
exact `=0.1.3` versions.

The release plan uses two independently verifiable GitHub transactions for the
same product SemVer. Each becomes public/current only after its verified receipt
records the immutable release:

- Apple: `v0.1.3`
- Android and GNU/Linux: `abi2-platforms-v0.1.3`

The earlier alpha.2 tags and receipts remain immutable historical evidence. They
are not rewritten or promoted as 0.1.3 evidence. The unpublished 0.1.0, 0.1.1, and 0.1.2 tags
likewise remain historical and are not promoted as 0.1.3 evidence.

Before the final source PR can be merged as `S`, repository administration must
replace the obsolete required contexts `constant-time (ubuntu-latest)` and
`constant-time (ubuntu-24.04-arm)` with the current exact checks
`Binary CT [x86_64-portable]` and `Binary CT [aarch64-native]`, while retaining
strict branch protection, administrator enforcement, and every unrelated required
check. This is an external administrative action; a locally green workflow or an
unprotected merge cannot substitute for a fresh read-only branch-protection
observation and a mergeable final PR.

Before either stable tag is created or pushed, an authorized operator must first
ensure that an active repository tag ruleset explicitly includes both exact 0.1.3
refs alongside the historical `v0.1.0`, `abi2-platforms-v0.1.0`, `v0.1.1`,
`abi2-platforms-v0.1.1`, `v0.1.2`, and `abi2-platforms-v0.1.2` refs, restricts
updates and deletions, and has no bypass actor. Creating or changing the
ruleset is an external administrative action and is not performed by this
repository. Immediately before tag creation, run the read-only authority below
with exactly one `GH_TOKEN` or `GITHUB_TOKEN` whose access is sufficient for the
GET response to include `bypass_actors`:

```sh
/bin/sh artifact/python-run.sh artifact/github_release_observation.py \
  verify-stable-tag-protection
```

Proceed only from a fresh `STABLE_TAG_PROTECTION_PASS`. The command samples the
complete bounded tag-ruleset inventory twice through the source-pinned GitHub CLI,
requires the current API version, rejects proxy/CA/Git/GitHub overrides and user
CLI configuration, and accepts only explicit active `update` plus `deletion`
coverage, with an empty bypass list, for every one of the eight stable-named refs —
the current `refs/tags/v0.1.3` and `refs/tags/abi2-platforms-v0.1.3` together with
the historical `refs/tags/v0.1.0`, `refs/tags/abi2-platforms-v0.1.0`,
`refs/tags/v0.1.1`, `refs/tags/abi2-platforms-v0.1.1`, `refs/tags/v0.1.2`, and
`refs/tags/abi2-platforms-v0.1.2`. Protection is verified
for the whole set, so a historical release tag can never silently lose its
update/deletion rule. A missing or hidden bypass list, target/ref mismatch,
disabled/evaluate ruleset, incomplete first page, tool drift, or changed second
sample is a refusal. Tag-triggered CI is too late to replace this pre-tag check.
State observation of the absent/apple-only/exact transition still concerns only
the current `v0.1.3` refs.

Both stable tags point to the coordinated results-only commit `R`, whose sole
parent is the source-changing commit `S`. Stable receipts record `S` as
`source_parent_commit`, `R` as `tag_commit`, and bind the tag tree plus the
canonical source-tree digest declared by `R`'s results manifest. Signed Apple
candidate bytes retain `distribution.source_commit = S`; `R` is never relabeled
as the artifact source.

Before any release-scoped package handoff, physical-device run, or performance
collection begins, every source change must already be merged into the final,
non-rewritten `main`. A clean `HEAD == refs/remotes/origin/main` defines `S`.
Evidence captured on a feature SHA, a pull-request synthetic merge commit, or a
predecessor that is later merged or rebased is stale and must be recollected; it
cannot be selected into `R`.

The stable package-publication transition from `S` to `R` selects the Rust package
handoff, Android AAR, canonical arm64-v8a/API-35/16-KiB release AVD proof, and the
cross-linked local release index/consumer receipt. Apple physical-matrix, Android
physical-device, and controlled-performance evidence remain separate
product-readiness selectors. The core transition preserves their historical bytes
only as explicit `stale_requires_rerun` or absent state; it neither treats omission
as success nor converts a failed optional verifier into a passing result.

## Reliability and security hardening

The 0.1.3 source line makes a deliberate fail-closed Rust/WASM behavior change:
`CompatXWing` calls must use canonical absent suite/version/context metadata
(`[]`, `0`, `[]`). Calls that previously succeeded while those values were ignored
now return the existing policy error before XOF construction, backend execution, or
output mutation. The three historical X-Wing draft-10 KAT vectors remain unchanged;
the source line additionally pins the CFRG
`draft-irtf-cfrg-concrete-hybrid-kems-04` Appendix B.2 vector, stored as the repository
vector-0 fixture. That document remains a
non-RFC Internet-Draft. The official vector covers valid keygen, encapsulation, and
decapsulation; a separate locally derived same-length ciphertext mutation checks
implicit rejection; the draft supplies no expected secret for that rejected case. Private
rustls group wire encoding and the ContextBound-only exact-nine C ABI 2 surface are
unchanged.

Two ownership changes likewise leave ABI 2 and wire bytes unchanged. The Compat
rustls client retains the stable 32-byte seed representation, expands it exactly once
per in-flight handshake into a non-Clone zeroizing 2,400-byte prepared owner, and
reuses that owner at completion. There is no global/shared secret-key cache or C-ABI
prepared-key surface. Separately, the native FFI's first dynamically allocated
Rust-owned policy-bound-context copy reserves before writing sensitive bytes and is
wiped by one RAII owner on normal return, error, or unwind. Valid-length allocation
failure remains opaque internal/backend failure, while oversized input remains an
explicit length error. Caller/marshalling copies, registers, paging, and process abort
remain outside this local erasure boundary.

This source line also strengthens the Android release transaction without weakening
package ownership checks:

- installed-package state and installed-APK ownership are observed through fixed,
  typed, bounded operations;
- an APK is accepted only after consecutive exact path-and-byte observations and
  exact signer verification;
- cleanup alternates package-state and ownership observations under one total
  deadline, retains the single-uninstall invariant, and fails closed when state
  cannot be established;
- a script-owned emulator can perform at most one receipt-, process-, listener-,
  console-, and private-ADB-bound transport registration recovery before starting
  package convergence again;
- failure diagnostics publish only bounded sanitized state tokens and path hashes,
  not raw ADB output, device identifiers, host paths, credentials, or signing data.

These source notes cannot by themselves assert a performance improvement. The final
release earns that claim only if `R` selects the mandatory raw-schema-v5 /
proof-schema-v8 / budget-schema-v10 proof for `S`, and the coordinated verified
receipt `V` preserves and revalidates that exact selection. The proof requires both
the preserved ContextBound/CompatXWing profile non-regression estimand with strict
ContextBound fixed suite/version/application-context inputs and CompatXWing canonical
`[]`/`0`/`[]` inputs, and a
same-process native/portable ContextBound `hybrid_core` implementation estimand for
encapsulation and decapsulation over `expanded_fips203_2400`. The harness generates
one expanded keypair, supplies the same key bytes/coins/corpus to both implementations,
and requires per-case output equality; portable key generation is not invoked. Both C
paths use the same O3/PIC/Armv8-A/macOS-11/section-codegen contract, and the O3 Rust
harness uses thin LTO and one codegen unit under the stable Rust/Cargo 1.96.1 producer.
Each estimand/operation is warmed independently immediately before collection. The
implementation estimand excludes FFI and OS RNG and is not complete ABI, rustls,
device, or competitor performance. The latter preregisters one-sided 95% upper
native/portable limits of 0.95 for primary p50/p95 and 1.0 for p99. Performance
remains pending until one fresh clean-source, controlled-host, exact-sample proof
for this tree is selected; no historical or small diagnostic run is promoted by
these notes.

## Assets and tested scope

- Apple: a Developer ID-signed, static-only XCFramework for macOS, iOS devices,
  and iOS simulators, plus its exact distribution evidence, manifest, and checksum
  file. Notarization is not applicable to this SDK payload; final applications
  retain their own signing, provisioning, and notarization responsibilities.
- Android: one AAR with `arm64-v8a`, `armeabi-v7a`, `x86`, and `x86_64` JNI
  libraries, exact ABI 2 exports, ELF hardening, and 16 KiB load alignment. The
  platform target includes a source- and AAR-bound API 35 arm64 16 KiB emulator runtime
  evidence bundle.
- GNU/Linux: x86_64 and aarch64 C SDK archives with shared/static libraries,
  headers, ABI contract, pkg-config/CMake metadata, SBOM/CBOM, licenses, GLIBC
  ceiling checks, and native consumers.
- Windows: the x64 MSVC C SDK ZIP remains an unsigned, unsupported CI diagnostic.
  It is excluded from the stable candidate subjects, formal distribution manifest,
  release assets, attestation, and receipt. It can enter a later supported release
  only after an Authenticode producer/verifier plus certificate and timestamp-authority
  gates exist; no signing success is inferred here.

Each platform candidate package is produced by the tag-bound workflow and covered
by GitHub build provenance. Final manifests and checksum sets bind the selected
assets; post-publication consumers re-download and verify the immutable releases.

While `S` still carries the frozen 190-key pre-migration manifest, main CI uses
only the exact source-transition readiness authority described in `ARTIFACT.md`;
it is not a generic proof skip. Once `R` installs the exact 237-key map, CI
dispatches only to the full proof-to-byte gate. Mixed states and failed readiness
never fall through to the other mode.

## Verification

### Create the two immutable tags at R

Do not create either tag until `R` is the clean final `origin/main` commit and
the latest exact-`R`, `main`/`push` CI and CodeQL run attempts are both
completed and successful. The operator token must also have read access to Code
Scanning analyses and alerts; a permission error is a hard failure, never an empty
result. Record those run and attempt IDs. A newer failed, cancelled, or in-progress
exact run blocks an older success. Re-run the tag-ruleset
authority immediately before this block. Neither `S`, a feature or pull-request
SHA, nor the later `P` or `V` results commits may be tagged.
From the first pre-tag security sample through the final remote tag-state sample,
the authorized release operator must freeze workflow rerun/dispatch actions and
exclude concurrent tag or branch operators; otherwise the authority must be sampled
again before any mutation.

The fixed local Git wrapper below discards caller Git configuration/environment for
all observations and tag construction. First prove that both *exact* stable refs
are absent locally and through the neutral, double-sampled read-only GitHub API;
similarly prefixed prerelease refs and the historical `v0.1.0` /
`abi2-platforms-v0.1.0` / `v0.1.1` / `abi2-platforms-v0.1.1` / `v0.1.2` /
`abi2-platforms-v0.1.2` refs do not affect this
exact-absence decision.
Execute the fenced command once as written. Do not source it or paste its body into
the operator shell: the fixed non-shell launcher first removes all documented
`xcrun` selectors, validates the credential and public tagger fields, and passes
only those fields plus a fixed locale and `PATH` to
`execve("/bin/sh")`, and never places the token in an argument. The quoted
here-document then disables tracing before any credential expansion and only then
enables the fail-closed shell options. Startup variables, exported shell functions,
and caller trace state cannot cross this boundary.
Inject `GH_TOKEN` only from a fresh trusted parent shell with tracing disabled. If a
token has already been present while parent-shell xtrace or an untrusted `PS4` was
active, discard that shell and credential and restart clean; no child process can
undo a disclosure already made by its parent.

```sh
/usr/bin/env -u DEVELOPER_DIR -u SDKROOT -u TOOLCHAINS \
  -u xcrun_log -u xcrun_verbose -u xcrun_nocache \
  /usr/bin/python3 -I -S -B -c '
import os
import re

def required(name, maximum, pattern=None):
    value = os.environ.get(name)
    if value is None or not value or len(value) > maximum:
        raise SystemExit("error: invalid " + name)
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise SystemExit("error: invalid " + name)
    if pattern is not None and re.fullmatch(pattern, value) is None:
        raise SystemExit("error: invalid " + name)
    return value

if "GITHUB_TOKEN" in os.environ:
    raise SystemExit("error: GITHUB_TOKEN must be absent")
token = required("GH_TOKEN", 4096)
tagger_name = required("RELEASE_TAGGER_NAME", 128, r"[A-Za-z0-9._ -]+")
tagger_email = required("RELEASE_TAGGER_EMAIL", 254, r"[A-Za-z0-9._%+@-]+")
if tagger_email.count("@") != 1 or tagger_email.startswith("@") or tagger_email.endswith("@"):
    raise SystemExit("error: invalid RELEASE_TAGGER_EMAIL")
os.execve(
    "/bin/sh",
    ["/bin/sh"],
    {
        "GH_TOKEN": token,
        "RELEASE_TAGGER_NAME": tagger_name,
        "RELEASE_TAGGER_EMAIL": tagger_email,
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
    },
)
' <<'QPERIAPT_STABLE_TAG_TRANSACTION'
set +x
set -euf
release_root=$(/bin/pwd -P)
test "$PWD" = "$release_root"
release_git() {
  /usr/bin/env -i LANG=C LC_ALL=C PATH=/usr/bin:/bin \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
    GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 \
    GIT_TERMINAL_PROMPT=0 GCM_INTERACTIVE=never \
    /usr/bin/git -C "$release_root" \
      -c core.fsmonitor=false -c core.hooksPath=/dev/null \
      -c core.attributesFile=/dev/null -c core.excludesFile=/dev/null \
      -c tag.gpgSign=false "$@"
}
release_tag() {
  /usr/bin/env -i LANG=C LC_ALL=C PATH=/usr/bin:/bin \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
    GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 \
    GIT_COMMITTER_NAME="$RELEASE_TAGGER_NAME" \
    GIT_COMMITTER_EMAIL="$RELEASE_TAGGER_EMAIL" \
    /usr/bin/git -C "$release_root" \
      -c core.fsmonitor=false -c core.hooksPath=/dev/null \
      -c core.attributesFile=/dev/null -c core.excludesFile=/dev/null \
      -c tag.gpgSign=false tag "$@"
}

apple_tag=v0.1.3
platform_tag=abi2-platforms-v0.1.3
/bin/sh artifact/python-run.sh artifact/github_release_observation.py \
  verify-stable-tag-protection
if release_git show-ref --verify --quiet "refs/tags/$apple_tag"; then exit 1; fi
if release_git show-ref --verify --quiet "refs/tags/$platform_tag"; then exit 1; fi
/bin/sh artifact/python-run.sh artifact/github_release_observation.py \
  stable-tag-state absent

push_parent=/private/tmp
test -d "$push_parent" && test ! -L "$push_parent"
test "$(/usr/bin/stat -f '%u' "$push_parent")" = 0
test "$(/usr/bin/stat -f '%p' "$push_parent")" = 41777
test "$(CDPATH='' cd -P -- "$push_parent" && /bin/pwd -P)" = "$push_parent"
push_bare=$(umask 077 && /usr/bin/mktemp -d \
  "$push_parent/qperiapt-stable-tag-push.XXXXXXXX")
/bin/chmod 0700 "$push_bare"
test -d "$push_bare" && test ! -L "$push_bare"
test "$(/usr/bin/stat -f '%u' "$push_bare")" = "$(/usr/bin/id -u)"
test "$(/usr/bin/stat -f '%Lp' "$push_bare")" = 700
test "$(/usr/bin/dirname -- "$push_bare")" = "$push_parent"
test "$(CDPATH='' cd -P -- "$push_bare" && /bin/pwd -P)" = "$push_bare"
push_bare_device=$(/usr/bin/stat -f '%d' "$push_bare")
push_bare_inode=$(/usr/bin/stat -f '%i' "$push_bare")
/usr/bin/env -i LANG=C LC_ALL=C PATH=/usr/bin:/bin \
  GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
  GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 \
  /usr/bin/git init --bare "$push_bare"
bare_git() {
  /usr/bin/env -i LANG=C LC_ALL=C PATH=/usr/bin:/bin \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
    GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 \
    GIT_TERMINAL_PROMPT=0 GCM_INTERACTIVE=never \
    /usr/bin/git --git-dir="$push_bare" "$@"
}
bare_git fetch --no-tags https://github.com/billlza/q-periapt.git \
  '+refs/heads/main:refs/remotes/origin/main'
R=$(release_git rev-parse --verify 'HEAD^{commit}')
test "$R" = "$(bare_git rev-parse --verify \
  'refs/remotes/origin/main^{commit}')"
test -z "$(release_git status --porcelain=v1 --untracked-files=all)"
S=$(/usr/bin/jq -er '.provenance.snapshot_commit' artifact/results.json)
test "${#S}" -eq 40
case "$S" in ''|*[!0-9a-f]*) exit 1 ;; esac
test "$(release_git rev-list --parents -n 1 "$R")" = "$R $S"
test "$(release_git diff --name-only "$S" "$R" --)" = artifact/results.json
TREE=$(release_git rev-parse --verify "$R^{tree}")

pretag_security=$(/bin/sh artifact/python-run.sh \
  artifact/platform_candidate_attestation.py \
  pretag-security-readiness "$R" "$S")
IFS=' ' read -r pretag_f1 pretag_f2 pretag_f3 pretag_f4 pretag_f5 \
  pretag_f6 pretag_f7 pretag_f8 pretag_extra <<EOF
$pretag_security
EOF
test -z "$pretag_extra"
test "$pretag_security" = \
  "$pretag_f1 $pretag_f2 $pretag_f3 $pretag_f4 $pretag_f5 $pretag_f6 $pretag_f7 $pretag_f8"
test "$pretag_f1" = PRETAG_SECURITY_READINESS_PASS
test "$pretag_f2" = "tag_commit=$R"
test "$pretag_f3" = "source_parent=$S"
ci_run=${pretag_f4#ci_run=}
ci_attempt=${pretag_f5#ci_attempt=}
codeql_run=${pretag_f6#codeql_run=}
codeql_attempt=${pretag_f7#codeql_attempt=}
github_cli_sha256=${pretag_f8#github_cli_sha256=}
test "ci_run=$ci_run" = "$pretag_f4"
test "ci_attempt=$ci_attempt" = "$pretag_f5"
test "codeql_run=$codeql_run" = "$pretag_f6"
test "codeql_attempt=$codeql_attempt" = "$pretag_f7"
test "github_cli_sha256=$github_cli_sha256" = "$pretag_f8"
for identifier in "$ci_run" "$ci_attempt" "$codeql_run" "$codeql_attempt"; do
  case "$identifier" in ''|0*|*[!0-9]*) exit 1 ;; esac
done
test "${#github_cli_sha256}" -eq 64
case "$github_cli_sha256" in ''|*[!0-9a-f]*) exit 1 ;; esac
printf '%s\n' "$pretag_security"

release_tag -a -m 'release: Q-Periapt 0.1.3 Apple distribution' \
  "$apple_tag" "$R"
release_tag -a -m 'release: Q-Periapt 0.1.3 ABI2 platform distribution' \
  "$platform_tag" "$R"
APPLE_TAG_OBJECT=$(release_git rev-parse --verify \
  "refs/tags/$apple_tag^{tag}")
PLATFORM_TAG_OBJECT=$(release_git rev-parse --verify \
  "refs/tags/$platform_tag^{tag}")
test "$APPLE_TAG_OBJECT" != "$PLATFORM_TAG_OBJECT"
test "$(release_git cat-file -t "$APPLE_TAG_OBJECT")" = tag
test "$(release_git cat-file -t "$PLATFORM_TAG_OBJECT")" = tag
test "$(release_git rev-parse --verify \
  "refs/tags/$apple_tag^{commit}")" = "$R"
test "$(release_git rev-parse --verify \
  "refs/tags/$platform_tag^{commit}")" = "$R"
test "$(release_git rev-parse --verify \
  "refs/tags/$apple_tag^{tree}")" = "$TREE"
test "$(release_git rev-parse --verify \
  "refs/tags/$platform_tag^{tree}")" = "$TREE"

# These are the only credential-bearing mutations in this block. Import the
# already validated tag objects into a new private bare repository, then push each
# exact ref to the literal repository URL. No source-repository remote, pushurl,
# insteadOf rule, credential helper, proxy, CA override, or ambient Git config is
# consulted.
bare_git fetch --no-tags "$release_root" \
  "refs/tags/$apple_tag:refs/tags/$apple_tag" \
  "refs/tags/$platform_tag:refs/tags/$platform_tag"
test "$(bare_git rev-parse "refs/tags/$apple_tag^{tag}")" = \
  "$APPLE_TAG_OBJECT"
test "$(bare_git rev-parse "refs/tags/$platform_tag^{tag}")" = \
  "$PLATFORM_TAG_OBJECT"
push_exact_tag() (
  set -eu
  trap 'unset QPERIAPT_GIT_AUTH' EXIT
  trap 'unset QPERIAPT_GIT_AUTH; exit 125' HUP INT TERM
  QPERIAPT_GIT_AUTH="Authorization: Basic $(/usr/bin/printf 'x-access-token:%s' \
    "$GH_TOKEN" | /usr/bin/base64 | /usr/bin/tr -d '\n')"
  /usr/bin/env -i LANG=C LC_ALL=C PATH=/usr/bin:/bin \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
    GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 \
    GIT_TERMINAL_PROMPT=0 GCM_INTERACTIVE=never \
    QPERIAPT_GIT_AUTH="$QPERIAPT_GIT_AUTH" \
    /usr/bin/git --git-dir="$push_bare" \
      -c http.followRedirects=false -c http.sslVerify=true \
      --config-env=http.https://github.com/.extraheader=QPERIAPT_GIT_AUTH \
      push --no-follow-tags https://github.com/billlza/q-periapt.git \
      "refs/tags/$1:refs/tags/$1"
)
require_remote_tag_state() {
  required_tag_state=$1
  observed_tag_state=$(/bin/sh artifact/python-run.sh \
    artifact/github_release_observation.py stable-tag-state recover \
    "$R" "$TREE" "$APPLE_TAG_OBJECT" "$PLATFORM_TAG_OBJECT")
  IFS=' ' read -r state_f1 state_f2 state_f3 state_f4 state_extra <<EOF
$observed_tag_state
EOF
  test -z "$state_extra"
  test "$observed_tag_state" = "$state_f1 $state_f2 $state_f3 $state_f4"
  test "$state_f1" = STABLE_TAG_STATE_PASS
  test "$state_f2" = repository=billlza/q-periapt
  remote_state=${state_f3#state=}
  observation_sha256=${state_f4#observation_sha256=}
  test "state=$remote_state" = "$state_f3"
  test "observation_sha256=$observation_sha256" = "$state_f4"
  case "$remote_state" in absent|apple_only|exact) ;; *) exit 1 ;; esac
  test "$remote_state" = "$required_tag_state"
  test "${#observation_sha256}" -eq 64
  case "$observation_sha256" in ''|*[!0-9a-f]*) exit 1 ;; esac
  printf '%s\n' "$observed_tag_state"
}

# A nonzero transport result is not itself a remote-state conclusion. The
# double-sampled reconcile authority decides whether the exact mutation landed.
if ! push_exact_tag "$apple_tag"; then
  printf '%s\n' 'Apple tag push returned nonzero; reconciling remote state.' >&2
fi
require_remote_tag_state apple_only
if ! push_exact_tag "$platform_tag"; then
  printf '%s\n' 'Platform tag push returned nonzero; reconciling remote state.' >&2
fi

/bin/sh artifact/python-run.sh artifact/github_release_observation.py \
  verify-stable-tag-protection
require_remote_tag_state exact
test -d "$push_bare" && test ! -L "$push_bare"
test "$(/usr/bin/stat -f '%u' "$push_bare")" = "$(/usr/bin/id -u)"
test "$(/usr/bin/stat -f '%Lp' "$push_bare")" = 700
test "$(/usr/bin/stat -f '%d' "$push_bare")" = "$push_bare_device"
test "$(/usr/bin/stat -f '%i' "$push_bare")" = "$push_bare_inode"
test "$(CDPATH='' cd -P -- "$push_bare" && /bin/pwd -P)" = "$push_bare"
QPERIAPT_STABLE_TAG_TRANSACTION
```

Preserve `R`, `TREE`, and both tag-object IDs out of band. If a push has an
unknown outcome or only the first exact ref becomes visible, do not delete, move,
or recreate it. Rebuild and revalidate the isolated private bare repository from
the retained local annotated objects, then invoke `stable-tag-state recover R TREE
APPLE_TAG_OBJECT PLATFORM_TAG_OBJECT`. Its strict marker permits only `absent`,
`apple_only`, or `exact`: `absent` authorizes only the Apple ref push,
`apple_only` authorizes only the platform ref push, and `exact` means no further
mutation. `platform_only`, lightweight or wrong tag objects, peeled-commit/tree
mismatches, pagination ambiguity, or a change across the two samples are hard
failures. After any authorized push, repeat the same authority and proceed only
when it returns the next exact state; finish by re-verifying tag protection and an
`exact` state. Never scan for or guess a missing ref.

Before assembling the non-Apple platform distribution, place the exact six-subject
CI candidate transaction below the fixed private candidate-input root and write its
sanitized projection below the separate fixed private projection root:

```sh
candidate_inputs=$PWD/target/abi2-platform-candidate-inputs
candidate_projections=$PWD/target/abi2-platform-candidate-projections
(umask 077 && mkdir -p "$candidate_inputs" "$candidate_projections")
chmod 0700 "$candidate_inputs" "$candidate_projections"
candidate_dir=$candidate_inputs/stable-platform-candidate
tag_commit=$(git rev-parse --verify \
  'refs/tags/abi2-platforms-v0.1.3^{commit}')
projection_parent=$(umask 077 && \
  mktemp -d "$candidate_projections/transaction.XXXXXXXX")
chmod 0700 "$projection_parent"
projection=$projection_parent/candidate-attestation-projection.json
sh artifact/verify-platform-candidate.sh \
  "$candidate_dir" "$tag_commit" "$projection"
```

The verifier records one private preflight snapshot, runs the six exact GitHub
attestation checks, then re-samples the candidate with the same parser. It publishes
the `0600` projection with exclusive creation only when every result contains the
same statement, verification record, run, and timestamp and the candidate bytes are
unchanged. The fixed input, projection, and raw-verification roots must be owned by
the current user with mode `0700`; the verifier fails before Git or GitHub when a
path escapes those roots. Raw GitHub responses remain in a script-owned `0700`
directory under `target/abi2-platform-candidate-verification/raw`; neither their
path nor their contents appear in the success marker.

The sixth subject, `ABI2_SOURCE_SECURITY_GATE.json`, is schema-2 transaction evidence rather
than a public product asset. For each of `.github/workflows/ci.yml` and
`.github/workflows/codeql.yml`, the tag workflow queries every matching
`main`/`push` run at exact `R`, selects the highest run ID, and then refuses
unless that latest exact run and its current attempt completed successfully. A later
failed, cancelled, or in-progress run therefore blocks an earlier success. It then
queries that exact attempt's complete job inventory. The receipt admits only the fixed
x86_64-portable and aarch64-native binary-CT jobs plus all six fixed CodeQL language
jobs. It separately binds `refs/heads/main` to R, selects the latest exact-R analysis
for each fixed `/language:*` category, requires CodeQL 2.26.2, positive
rule counts, and empty error/warning fields, records each analysis's actual
result count, and requires the main-ref open-alert response to be empty. A
CodeQL finding leaves that open-alert list only by being fixed or by being
dismissed with a reason recorded against the alert, so the empty list is the
operative requirement: zero unadjudicated findings. Requiring a zero result
count instead would demand that no finding ever existed, which dismissal cannot
achieve because the count is a property of the uploaded analysis and includes
already-dismissed findings. It records bounded numeric run/job/analysis IDs and binds R, S,
the relative workflow paths, workflow source digests, and the hosted GitHub CLI's
canonical path, version, and SHA-256. Each API call runs with an empty private CLI configuration,
minimal credential-only environment, and pre/post executable identity sampling. The
candidate verifier checks the complete structure and its attested subject digest;
both pending and verified platform receipts retain the same sanitized projection and
crosslink. The final public release tuple is the seven-file platform distribution
assembled below; neither `ABI2_SOURCE_SECURITY_GATE.json` nor
`CANDIDATE_SHA256SUMS` is uploaded as a public product asset.

Before creating the platform pending receipt or results commit `P`, assemble the
verified four product candidate assets together with the current-R Android runtime
bundle. Set the four Android tool variables to canonical absolute paths from the
fixed SDK/NDK used for this transaction. The candidate directory remains the exact
six-subject directory verified above; the assembler consumes only its four product
assets and separately deep-verifies the runtime bundle. Use one fresh bounded
transaction name with the required `transaction.` prefix:

```sh
platform_candidate_root=$PWD/target/abi2-platform-release-candidates
(umask 077 && mkdir -p "$platform_candidate_root")
chmod 0700 "$platform_candidate_root"
platform_assembly_transaction=transaction.stable-platform-UNIQUE
platform_runtime_bundle=$PWD/PATH_TO_CURRENT_R_RUNTIME_BUNDLE.zip
test -f "$platform_runtime_bundle" && test ! -L "$platform_runtime_bundle"
test ! -e "$platform_candidate_root/$platform_assembly_transaction"
sh artifact/python-run.sh artifact/platform_distribution.py assemble \
  --root "$PWD" \
  --candidate-dir "$candidate_dir" \
  --runtime-bundle "$platform_runtime_bundle" \
  --transaction-name "$platform_assembly_transaction" \
  --android-llvm-nm "$android_llvm_nm" \
  --android-llvm-readelf "$android_llvm_readelf" \
  --android-apksigner "$android_apksigner" \
  --android-zipalign "$android_zipalign"
platform_assembly_receipt=$platform_candidate_root/$platform_assembly_transaction/platform-release-candidate-receipt.json
platform_release_dir=$platform_candidate_root/$platform_assembly_transaction/release
test -f "$platform_assembly_receipt" && test ! -L "$platform_assembly_receipt"
test -d "$platform_release_dir" && test ! -L "$platform_release_dir"
```

Copy `receipt=` and `release_dir=` from the single
`ABI2_PLATFORM_DISTRIBUTION_ASSEMBLE_PASS` marker and prefix them with `$PWD/`.
Require those values to equal the two canonical absolute paths set above before
continuing.
The release directory must contain exactly the canonical seven public files. The
private sibling completion receipt is written last with no-replace publication,
file/directory durability, and a descriptor-pinned pre/post snapshot; it is not a
release asset. Missing receipt, an extra transaction entry, changed asset bytes,
wrong MIME policy, or a reused transaction name is a hard failure. Upload only the
seven files from that exact `release_dir`; do not rebuild, copy from a different
directory, or hand-compose either the receipt or `artifact/results.json`.
The stable platform publication receipt is unpublished schema 3. A schema-2
pending receipt has no final seven-asset binding and is invalid; do not edit or
migrate it. Preserve it only as failed local evidence, then create a fresh schema-3
assembly and pending transaction from the verified bytes.

Publication receipts advance through `pending` before `verified`; a domain receipt
never edits `artifact/results.json` directly. First bind the two pending receipts to
their private candidate/completion evidence. The platform verifier must be a clean
standalone checkout named `M` with its own non-symlink `.git` directory:

```sh
platform_tag=abi2-platforms-v0.1.3
platform_worktree_root=$PWD/target/abi2-platform-publication-worktrees
(umask 077 && mkdir -p "$platform_worktree_root")
chmod 0700 "$platform_worktree_root"
test ! -e "$platform_worktree_root/M"
(umask 077 && git clone --no-local "$PWD" "$platform_worktree_root/M")
git -C "$platform_worktree_root/M" checkout --detach "$platform_tag"
test -z "$(git -C "$platform_worktree_root/M" status --porcelain=v1 \
  --untracked-files=all)"
sh artifact/python-run.sh artifact/platform_stable_publication.py pending \
  --candidate-projection "$projection" \
  --assembly-receipt "$platform_assembly_receipt" \
  --verifier-checkout "$platform_worktree_root/M"

apple_tag=v0.1.3
results_sha256=$(shasum -a 256 artifact/results.json | awk '{print $1}')
source_parent_commit=$(jq -r '.provenance.snapshot_commit' artifact/results.json)
tag_commit=$(git rev-parse --verify "refs/tags/$apple_tag^{commit}")
test "$source_parent_commit" != "$tag_commit"
apple_worktrees=$PWD/target/qperiapt-apple-release-worktrees
completed=$apple_worktrees/$source_parent_commit/completed.json
sh artifact/python-run.sh artifact/apple_stable_publication.py pending \
  "$completed" "$results_sha256"
```

Set `platform_pending_receipt` and `apple_pending_receipt` to `$PWD/` plus the
repo-relative `receipt=`/`path=` values printed by those commands. Pin the current
results bytes and ask the neutral finalizer for a separate pending results
candidate. The candidate marker binds both the current parent commit and its results
SHA-256. Install the exact candidate bytes, commit only `artifact/results.json`, then
run the dedicated installed-transition verifier; neither receipt is itself a results
file:

```sh
pending_parent_commit=$(git rev-parse --verify HEAD)
pending_parent_results_sha256=$results_sha256
sh artifact/python-run.sh artifact/release_receipt_finalizer.py finalize \
  "$results_sha256" \
  --apple-receipt "$apple_pending_receipt" \
  --platform-receipt "$platform_pending_receipt"

# Copy all four values from the single RELEASE_PUBLICATION_RESULTS_CANDIDATE_PASS marker.
pending_candidate=target/release-publication-results/transaction.EMITTED_ID/results.json
pending_candidate_sha256=EMITTED_64_LOWERCASE_HEX_SHA256
emitted_parent_commit=EMITTED_40_LOWERCASE_HEX_COMMIT
emitted_parent_results_sha256=EMITTED_64_LOWERCASE_HEX_SHA256
test "$emitted_parent_commit" = "$pending_parent_commit"
test "$emitted_parent_results_sha256" = "$pending_parent_results_sha256"
test "$(shasum -a 256 "$pending_candidate" | awk '{print $1}')" = \
  "$pending_candidate_sha256"
install -m 0644 "$pending_candidate" artifact/results.json
test "$(shasum -a 256 artifact/results.json | awk '{print $1}')" = \
  "$pending_candidate_sha256"
cmp -s "$pending_candidate" artifact/results.json
test "$(git diff --name-only -- artifact/results.json)" = artifact/results.json
test -z "$(git diff --name-only -- . ':(exclude)artifact/results.json')"
# Re-sample the candidate and installation immediately before staging.
test "$(shasum -a 256 "$pending_candidate" | awk '{print $1}')" = \
  "$pending_candidate_sha256"
test "$(shasum -a 256 artifact/results.json | awk '{print $1}')" = \
  "$pending_candidate_sha256"
cmp -s "$pending_candidate" artifact/results.json
git -c core.fsmonitor=false -c core.hooksPath=/dev/null \
  -c core.attributesFile=/dev/null -c core.excludesFile=/dev/null \
  add -- artifact/results.json
test "$(git -c core.fsmonitor=false -c core.hooksPath=/dev/null \
  -c core.attributesFile=/dev/null -c core.excludesFile=/dev/null \
  diff --cached --name-only)" = artifact/results.json
test "$(shasum -a 256 "$pending_candidate" | awk '{print $1}')" = \
  "$pending_candidate_sha256"
test "$(shasum -a 256 artifact/results.json | awk '{print $1}')" = \
  "$pending_candidate_sha256"
cmp -s "$pending_candidate" artifact/results.json
test "$(git -c core.fsmonitor=false -c core.hooksPath=/dev/null \
  -c core.attributesFile=/dev/null -c core.excludesFile=/dev/null \
  show :artifact/results.json | shasum -a 256 | awk '{print $1}')" = \
  "$pending_candidate_sha256"
git -c core.fsmonitor=false -c core.hooksPath=/dev/null \
  -c core.attributesFile=/dev/null -c core.excludesFile=/dev/null commit \
  -m 'release: record stable publication pending cohort'
test "$(git -c core.fsmonitor=false -c core.hooksPath=/dev/null \
  -c core.attributesFile=/dev/null -c core.excludesFile=/dev/null \
  show HEAD:artifact/results.json | shasum -a 256 | awk '{print $1}')" = \
  "$pending_candidate_sha256"
pending_results_sha256=$pending_candidate_sha256
test "$(shasum -a 256 artifact/results.json | awk '{print $1}')" = \
  "$pending_results_sha256"
sh artifact/python-run.sh artifact/release_receipt_finalizer.py verify-installed \
  "$pending_results_sha256" \
  "$pending_parent_commit" \
  "$pending_parent_results_sha256"
```

### Publish the coordinated immutable GitHub releases from P

This is the sole GitHub Release API asset/publication mutation transaction. It
runs only after the pending results commit `P` above is installed and verified,
but before any remote consumer or publication verifier. The separately
authorized annotated-tag push above remains a prerequisite and is not part of
this Release API transaction. The coordinator handles Apple and platform in
one journal: Apple draft, platform draft, the four-asset Apple prefix, the
seven-asset platform prefix, Apple publication, then platform publication.
Apple remains the latest release. The fixed short release bodies live directly
in `artifact/stable_github_publication.py`; no mutable body file is an authority.

`prepare` descriptor-safely creates the fixed passwd-home mode-0700 state
hierarchy if it is absent. It accepts only the installed results digest, performs
no credentialed or network operation, copies the selected 4+7 bytes into its
private fixed staging root, and prints the exact plan digest:

```sh
/usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
  /bin/sh artifact/python-run.sh artifact/stable_github_publication.py prepare \
  "$pending_results_sha256"
# Copy plan_sha256 from the single STABLE_GITHUB_PREPARED marker.
stable_github_plan_sha256=EMITTED_64_LOWERCASE_HEX_SHA256
```

There is one deliberately manual pre-credential bootstrap residue. If the process is
killed after creating the final state directory but before durably creating its
persistent lock, every later command rejects that existing empty root; it never
recreates the lock because an older process could still hold the unlinked inode. Only
after an independent operator confirms that no `prepare`, `publish`, `status`, or
`verify` process is running, the credential is not in use elsewhere, the path is the
exact passwd-derived fixed root, its complete parent chain and the root are owned
mode-`0700` non-symlink directories, and the root inventory is strictly empty, may the
operator approve a non-recursive `rmdir` of that one empty final root and restart
`prepare`. `rmdir` must fail if any entry appears. Never construct a lock manually,
remove a non-empty root, or delete a lock, intent, reconciliation, outcome, or staging
residue.

Do not run the credentialed command through an ambient `python-run.sh` shell.
Start from a fresh trusted parent shell with tracing disabled. The fixed launcher
below rejects a second credential, control characters, malformed plan/results
pins, and all caller startup/trace/function variables by constructing the child
environment from an allowlist. `GH_TOKEN` remains only in that environment and
never enters argv. If the parent shell ever exposed the token under xtrace or an
untrusted `PS4`, discard both shell and credential before continuing.

```sh
# GH_TOKEN is already injected by the controlled credential provider.
STABLE_GITHUB_PLAN_SHA256="$stable_github_plan_sha256" \
STABLE_GITHUB_RESULTS_SHA256="$pending_results_sha256" \
/usr/bin/env -u DEVELOPER_DIR -u SDKROOT -u TOOLCHAINS \
  -u xcrun_log -u xcrun_verbose -u xcrun_nocache \
  /usr/bin/python3 -I -S -B -c '
import os
import re

def required(name, maximum, pattern=None):
    value = os.environ.get(name)
    if value is None or not value or len(value) > maximum:
        raise SystemExit("error: invalid " + name)
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise SystemExit("error: invalid " + name)
    if pattern is not None and re.fullmatch(pattern, value) is None:
        raise SystemExit("error: invalid " + name)
    return value

if "GITHUB_TOKEN" in os.environ:
    raise SystemExit("error: GITHUB_TOKEN must be absent")
token = required("GH_TOKEN", 4096)
plan = required("STABLE_GITHUB_PLAN_SHA256", 64, r"[0-9a-f]{64}")
results = required("STABLE_GITHUB_RESULTS_SHA256", 64, r"[0-9a-f]{64}")
os.execve(
    "/bin/sh",
    ["/bin/sh"],
    {
        "GH_TOKEN": token,
        "STABLE_GITHUB_PLAN_SHA256": plan,
        "STABLE_GITHUB_RESULTS_SHA256": results,
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
    },
)
' <<'QPERIAPT_STABLE_GITHUB_PUBLICATION'
set +x
set -euf
/bin/sh artifact/python-run.sh artifact/stable_github_publication.py publish \
  --execute-real-github-mutation \
  --expected-plan-sha256 "$STABLE_GITHUB_PLAN_SHA256" \
  --expected-results-sha256 "$STABLE_GITHUB_RESULTS_SHA256" \
  --ack-draft-barrier I_ACKNOWLEDGE_BOTH_DRAFTS_BEFORE_ASSET_UPLOAD \
  --ack-publication-order I_ACKNOWLEDGE_APPLE_THEN_PLATFORM_PUBLICATION
/bin/sh artifact/python-run.sh artifact/stable_github_publication.py verify
QPERIAPT_STABLE_GITHUB_PUBLICATION
```

A timeout or nonzero command is never retried. If every local boundary remains
intact, the coordinator takes a fresh complete observation: an exact successor is
journaled, while a predecessor or temporarily unavailable ordinary remote observation
receives a durable, intent-bound reconciliation authority and then stops. Non-exact
state, a signal, starter or unexpected asset, local identity drift, or any other
unresolved boundary stops with the trailing intent retained. Do not delete,
overwrite, or clobber a remote asset. A later invocation may observe and journal an
exact delayed successor only when the journal also contains that no-replace
reconciliation authority. A bare trailing intent is permanently
`manual_review_required`: later `publish` invocations may inspect it but never accept,
repeat, or advance that mutation. `status` distinguishes it from
`reconciliation_eligible`.
Do not issue a replacement mutation manually.
Starter deletion requires a separate future operator acknowledgement and is
intentionally not implemented here.

The persistent local lock coordinates only this OS account on this publication host.
Until every unresolved or manual-review intent has been explicitly disposed, do not
use the same GitHub credential from another UID, host, shell, or tool. The local
SHA-256 and descriptor checks detect accidental byte/identity drift; they do not claim
to resist hostile same-UID code, root/host compromise, credential theft, or a
compromised GitHub account or service.

After selecting that pending candidate, run the external consumer from its clean
verifier checkout with the seven existing `QPERIAPT_SWIFT_BINARY_*` pins. Map
`QPERIAPT_SWIFT_BINARY_CHECKSUM`, `QPERIAPT_SWIFT_BINARY_SHA256`,
`QPERIAPT_SWIFT_BINARY_APPLE_DISTRIBUTION_SHA256`,
`QPERIAPT_SWIFT_BINARY_MANIFEST_SHA256`,
`QPERIAPT_SWIFT_BINARY_SHA256SUMS_SHA256`, and
`QPERIAPT_SWIFT_BINARY_SOURCE_COMMIT` to the current pending distribution's
`swiftpm_checksum`, `artifact_sha256`, `apple_distribution_evidence_sha256`,
`manifest_sha256`, `checksums_sha256`, and `source_commit` respectively.
`QPERIAPT_SWIFT_BINARY_URL` is exactly
`https://github.com/billlza/q-periapt/releases/download/v0.1.3/CQPeriapt.xcframework.zip`.
These are cross-checked facts, not new caller claims:

```sh
/bin/sh artifact/swift-xcframework-remote-consumer.sh
```

The script accepts no arguments. It snapshots and pins the startup
`artifact/results.json` internally, performs the remote checks, and invokes the
receipt emitter only from that source-bound snapshot. Its
`APPLE_REMOTE_CONSUMER_RECEIPT_PASS` marker reports the fixed path under
`target/qperiapt-swift-remote-consumer-runs/transaction.<fresh>/`.
That marker and leaf are the atomic evidence commit. The terminal
`SWIFT_REMOTE_BINARY_CONSUMER_PASS` marker is emitted only after the source
snapshots are removed and the global lock is released. If the script exits 125
with `remote-consumer receipt committed with incomplete durability` or
`remote-consumer receipt committed but post-commit cleanup failed`, the atomic
no-replace visibility point completed for the intended receipt bytes. The
failure means the current named path identity, availability, or durability is
not established by that marker alone. Preserve the transaction and independently
verify its current leaf and bytes read-only; the reported receipt SHA-256 binds
the bytes at the visibility point, not the later pathname state. The run's
durability or hygiene failure still requires handling, and the nonzero script
run must not be recorded as a PASS. A distinct exit-125 `remote-consumer receipt
visibility indeterminate` diagnostic preserves the entire transaction and global
lock for read-only inspection and manual disposition. In that state,
`intended_receipt_sha256` records only the bytes that the emitter attempted to
publish; it does not confirm that the named leaf exists with those bytes. Do not
clean, retry, finalize, or record a PASS from either failed transaction until its
state has been resolved explicitly.

After the Apple release is immutable, collect its five-subject GitHub release
attestation into disjoint private raw and projection transactions:

```sh
apple_verification=$PWD/target/qperiapt-apple-release-verification
apple_raw_root=$apple_verification/raw
apple_projection_root=$apple_verification/projections
(umask 077 && mkdir -p "$apple_raw_root" "$apple_projection_root")
chmod 0700 "$apple_verification" "$apple_raw_root" "$apple_projection_root"
release_id=$(sh artifact/python-run.sh \
  artifact/apple_release_verification.py release-id "$completed")
tag_object=$(sh artifact/python-run.sh \
  artifact/apple_release_verification.py tag-object "$completed")
apple_transaction=release-$release_id-UNIQUE_OPERATOR_TRANSACTION
apple_raw=$apple_raw_root/$apple_transaction
test ! -e "$apple_raw"
apple_projection_parent=$(umask 077 && \
  mktemp -d "$apple_projection_root/transaction.XXXXXXXX")
chmod 0700 "$apple_projection_parent"
apple_projection=$apple_projection_parent/apple-github-release-verification.json
sh artifact/python-run.sh artifact/apple_release_verification.py collect \
  "$completed" "$release_id" "$tag_object" "$apple_raw" "$apple_projection"
```

Set `apple_remote_receipt` to `$PWD/` plus the emitted repo-relative path. Promote
Apple, then collect the platform release into fresh absent raw/download paths. Set
the four Android variables below to canonical absolute executable paths from the
fixed SDK/NDK installation selected for this transaction:

```sh
pending_results_sha256=$(shasum -a 256 artifact/results.json | awk '{print $1}')
sh artifact/python-run.sh artifact/apple_stable_publication.py promote \
  "$pending_results_sha256" "$apple_projection" "$apple_remote_receipt"

platform_transaction=release-UNIQUE_OPERATOR_TRANSACTION
platform_raw=$PWD/target/abi2-platform-publication-verification/raw/$platform_transaction
platform_downloads=$PWD/target/abi2-platform-publication-verification/downloads/$platform_transaction
test ! -e "$platform_raw" && test ! -e "$platform_downloads"
sh artifact/python-run.sh artifact/platform_stable_publication.py collect \
  --pending-receipt "$platform_pending_receipt" \
  --verifier-checkout "$platform_worktree_root/M" \
  --raw-directory "$platform_raw" \
  --download-directory "$platform_downloads" \
  --android-llvm-nm "$android_llvm_nm" \
  --android-llvm-readelf "$android_llvm_readelf" \
  --android-apksigner "$android_apksigner" \
  --android-zipalign "$android_zipalign"
```

Set `apple_verified_receipt` and `platform_verified_receipt` to `$PWD/` plus their
printed repo-relative paths. The coordinated stable cohort cannot activate until
the crates.io coordinator has reconciled all ten exact `0.1.3` archives as
`published_verified`. Its `source_identity` must be the four-field S/R/tree/digest
projection shared by the verified Apple and platform receipts. The registry lane
accepts no arbitrary transcript or package directory. On a clean S checkout,
`rust-publish-contract.sh` captures its canonical stdout into one bounded private
transcript, retains the exact ten verified `.crate` files before cleaning Cargo's
temporary package target, and commits `rust-package-handoff.json` last. It prints the
only admissible repository-relative handoff path and digest as a controlled
`RUST_PACKAGE_HANDOFF_PASS` line on stderr. A dirty diagnostic run never commits a
handoff. A nonzero exit, missing marker, or duplicate reserved marker is failure even
if a private transaction directory exists; do not scan for or select that orphan.
After proving S is still clean, start a new transaction. Never substitute an ad hoc
`cargo package` run.

Handoff production is an earlier source-phase step. Before creating the results-only
commit R, run the contract once in the clean S checkout that will later advance to R
and P. Retain the exact marker values out of band, and retain that checkout's
`target/qperiapt-rust-package-handoffs` directory. Do not create the handoff in a
disposable worktree because the registry consumer accepts only its own checkout's
fixed handoff root:

```sh
sh artifact/rust-publish-contract.sh
# Record the single repository-relative path and sha256 values verbatim as
# RECORDED_RUST_HANDOFF_MANIFEST and RECORDED_RUST_HANDOFF_SHA256. Pass those
# same values to source_results_assembler as documented in ARTIFACT.md.
```

After S has advanced to its direct results-only child R and then to the clean pending
results commit P, resume in that same checkout. Read the selectors installed in R and
require them to equal the two retained marker values; neither directory scanning nor
manual path substitution is an authority. The production verifier independently requires S-to-R to be direct/results-only,
`tree(R)` to match `tag_tree`, and the current checkout to be R or a clean, linear,
results-only descendant:

```sh
crates_inputs=$PWD/target/qperiapt-crates-io-publication-inputs
(umask 077 && mkdir -p "$crates_inputs")
chmod 0700 "$crates_inputs"
crates_source_identity=$crates_inputs/source-identity.json
test ! -e "$crates_source_identity"
(umask 077 && jq '.source | {canonical_source_tree_sha256,source_parent_commit,tag_commit,tag_tree}' \
  "$apple_verified_receipt" >"$crates_source_identity")
chmod 0600 "$crates_source_identity"

# Supply both RECORDED_* values from the earlier clean-S marker.
: "${RECORDED_RUST_HANDOFF_MANIFEST:?missing clean-S handoff path}"
: "${RECORDED_RUST_HANDOFF_SHA256:?missing clean-S handoff digest}"
selected_rust_handoff_manifest=$(jq -er '.rust_publish.handoff_manifest_path' artifact/results.json)
selected_rust_handoff_sha256=$(jq -er '.rust_publish.handoff_manifest_sha256' artifact/results.json)
test "$selected_rust_handoff_manifest" = "$RECORDED_RUST_HANDOFF_MANIFEST"
test "$selected_rust_handoff_sha256" = "$RECORDED_RUST_HANDOFF_SHA256"
rust_handoff_manifest=$PWD/$selected_rust_handoff_manifest
rust_handoff_sha256=$selected_rust_handoff_sha256
test "${#rust_handoff_sha256}" -eq 64
case "$rust_handoff_sha256" in *[!0-9a-f]*|'') exit 1 ;; esac
test "$(shasum -a 256 "$rust_handoff_manifest" | awk '{print $1}')" = \
  "$rust_handoff_sha256"

# The path and digest arguments below are explicit confirmations only. The
# coordinator reloads results commit R, validates its selected Rust handoff,
# reconstructs the fixed repository path, and uses only that R-derived value.
sh artifact/python-run.sh artifact/crates_io_publication.py verify \
  "$crates_source_identity" "$rust_handoff_manifest" "$rust_handoff_sha256"
```

This is a read-only registry reconciliation command and does not upload. If it
reports `partial`, preserve the exact `receipt_path` and `receipt_sha256` from its
controlled marker and verify those bytes before any later resume. A resume must
supply that receipt through `--previous-receipt`, remain bound to the same handoff
digest, and reconcile every prior unknown outcome before another upload can be
attempted. Real publication is irreversible and additionally requires both explicit
publish flags, the fixed external exact-byte uploader, `CARGO_REGISTRY_TOKEN`, and
the one fixed same-host/same-effective-account state authority derived from the OS
passwd record—not ambient `HOME`—at
`~/.q-periapt/publication-state/crates.io-v0.1.3`. All worktrees and resumes for this
version must use that exact root; an alternate safe-looking root is rejected so its
lock and unknown-outcome journal cannot fork. Pre-create each private directory with
mode `0700`; the publish CLI independently checks canonical ownership, modes, ancestry,
and every registered worktree before reading a credential:

```sh
publication_account_home=$(python3 -I -S -c \
  'import os,pwd; print(pwd.getpwuid(os.geteuid()).pw_dir)')
publication_state_parent=$publication_account_home/.q-periapt/publication-state
publication_state_root=$publication_state_parent/crates.io-v0.1.3
(umask 077 && mkdir -p "$publication_state_root")

# Install the separately reviewed exact-byte uploader as this fixed 0700 child.
uploader_command=$publication_state_root/qperiapt-crates-io-uploader
test -f "$uploader_command" && test ! -L "$uploader_command"

# Only an authorized operator on the isolated publication host may run this.
# Add --previous-receipt with the exact latest partial receipt when resuming.
# --state-root and --uploader-command confirm the displayed authority; the
# coordinator derives both paths independently from passwd data and a fixed leaf.
sh artifact/python-run.sh artifact/crates_io_publication.py publish \
  "$crates_source_identity" "$rust_handoff_manifest" "$rust_handoff_sha256" \
  --state-root "$publication_state_root" \
  --uploader-command "$uploader_command" \
  --execute-real-upload --acknowledge-irreversible-publish
```

Do not use the same registry credential from another UID or host while this fixed
transaction is unresolved; the local lock intentionally claims only same-host,
same-account cross-worktree exclusion. No such upload has been run or is implied
here. After an abrupt local crash, restart under that same authority: it deletes only
descriptor-proven empty or exact private precommit journal residue. A durable final
intent is never deleted or retried; it must first reconcile through the official API
and sparse index. Mixed, renamed, multiply linked, special-file, permission-mismatched,
or changing residue fails before credentials or an uploader are reached. Set
`crates_verified_receipt` and
`crates_verified_receipt_sha256` only from a fresh
`CRATES_IO_PUBLICATION_VERIFY_PASS` or `CRATES_IO_PUBLICATION_RUN_PASS` marker whose
status is `published_verified` for all ten crates, then require the receipt bytes to
match:

```sh
crates_verified_receipt=$PWD/target/qperiapt-crates-io-publication-receipts/transaction.EMITTED_ID/crates-io-v0.1.3-publication-receipt.json
crates_verified_receipt_sha256=EMITTED_64_LOWERCASE_HEX_SHA256
test "$(shasum -a 256 "$crates_verified_receipt" | awk '{print $1}')" = \
  "$crates_verified_receipt_sha256"
```

Finalize against the still-pinned pending results. Install V as the direct
results-only child of P and run `verify-installed` before the receipt-level
read-only `verify`; those commands prove different boundaries and neither replaces
the other:

```sh
verified_parent_commit=$(git rev-parse --verify HEAD)
verified_parent_results_sha256=$pending_results_sha256
sh artifact/python-run.sh artifact/release_receipt_finalizer.py finalize \
  "$pending_results_sha256" \
  --apple-receipt "$apple_verified_receipt" \
  --platform-receipt "$platform_verified_receipt" \
  --crates-receipt "$crates_verified_receipt"

# Copy all four values from the single RELEASE_PUBLICATION_RESULTS_CANDIDATE_PASS marker.
verified_candidate=target/release-publication-results/transaction.EMITTED_ID/results.json
verified_candidate_sha256=EMITTED_64_LOWERCASE_HEX_SHA256
emitted_parent_commit=EMITTED_40_LOWERCASE_HEX_COMMIT
emitted_parent_results_sha256=EMITTED_64_LOWERCASE_HEX_SHA256
test "$emitted_parent_commit" = "$verified_parent_commit"
test "$emitted_parent_results_sha256" = "$verified_parent_results_sha256"
test "$(shasum -a 256 "$verified_candidate" | awk '{print $1}')" = \
  "$verified_candidate_sha256"
install -m 0644 "$verified_candidate" artifact/results.json
test "$(shasum -a 256 artifact/results.json | awk '{print $1}')" = \
  "$verified_candidate_sha256"
cmp -s "$verified_candidate" artifact/results.json
test "$(git diff --name-only -- artifact/results.json)" = artifact/results.json
test -z "$(git diff --name-only -- . ':(exclude)artifact/results.json')"
# Re-sample the candidate and installation immediately before staging.
test "$(shasum -a 256 "$verified_candidate" | awk '{print $1}')" = \
  "$verified_candidate_sha256"
test "$(shasum -a 256 artifact/results.json | awk '{print $1}')" = \
  "$verified_candidate_sha256"
cmp -s "$verified_candidate" artifact/results.json
git -c core.fsmonitor=false -c core.hooksPath=/dev/null \
  -c core.attributesFile=/dev/null -c core.excludesFile=/dev/null \
  add -- artifact/results.json
test "$(git -c core.fsmonitor=false -c core.hooksPath=/dev/null \
  -c core.attributesFile=/dev/null -c core.excludesFile=/dev/null \
  diff --cached --name-only)" = artifact/results.json
test "$(shasum -a 256 "$verified_candidate" | awk '{print $1}')" = \
  "$verified_candidate_sha256"
test "$(shasum -a 256 artifact/results.json | awk '{print $1}')" = \
  "$verified_candidate_sha256"
cmp -s "$verified_candidate" artifact/results.json
test "$(git -c core.fsmonitor=false -c core.hooksPath=/dev/null \
  -c core.attributesFile=/dev/null -c core.excludesFile=/dev/null \
  show :artifact/results.json | shasum -a 256 | awk '{print $1}')" = \
  "$verified_candidate_sha256"
git -c core.fsmonitor=false -c core.hooksPath=/dev/null \
  -c core.attributesFile=/dev/null -c core.excludesFile=/dev/null commit \
  -m 'release: record stable publication verified cohort'
test "$(git -c core.fsmonitor=false -c core.hooksPath=/dev/null \
  -c core.attributesFile=/dev/null -c core.excludesFile=/dev/null \
  show HEAD:artifact/results.json | shasum -a 256 | awk '{print $1}')" = \
  "$verified_candidate_sha256"
verified_results_sha256=$verified_candidate_sha256
test "$(shasum -a 256 artifact/results.json | awk '{print $1}')" = \
  "$verified_results_sha256"
sh artifact/python-run.sh artifact/release_receipt_finalizer.py verify-installed \
  "$verified_results_sha256" \
  "$verified_parent_commit" \
  "$verified_parent_results_sha256"
sh artifact/python-run.sh artifact/release_receipt_finalizer.py verify \
  "$verified_results_sha256" \
  --apple-receipt "$apple_verified_receipt" \
  --platform-receipt "$platform_verified_receipt" \
  --crates-receipt "$crates_verified_receipt"
```

Both collectors use bounded pre/post `PUBLIC` repository and immutable stable-release
views around exact release attestation checks. Platform collection then streams all
seven assets into one new private directory, rechecks their size/hash inventory,
and runs the deep verifier from `M`. The source-pinned GitHub CLI receives exactly
one bounded credential in a minimal environment with empty private configuration,
so this remains an authenticated rather than anonymous-availability claim. All receipt, raw, download,
projection, remote-consumer, and results-candidate outputs stay below fixed roots.
A failed raw/download collection requires a new transaction leaf. Successful
outputs are no-replace; already-selected receipts are checked only with `verify`.

Do not substitute ambient `gh release verify`, `gh release verify-asset`, or
`gh release view` commands for these collectors. Such commands are at most
operator diagnostics: they do not use this transaction's fixed tool identity,
minimal environment, pre/post samples, private raw retention, or receipt
transition checks, and therefore are not publication authority.

## Explicit boundaries

No crates.io publication has been executed or claimed by these notes; stable cohort
activation remains blocked until the exact ten-crate `published_verified` receipt exists.
This stable ABI package release does not by itself claim Maven Central publication,
deb/rpm/MSIX publication, Windows Authenticode, current Android physical-device
coverage, current performance evidence, independent cryptographic certification,
FIPS validation, hostile-host attestation, or production readiness. Those remain
separate release, credential, hardware, benchmark, audit, or certification gates.
