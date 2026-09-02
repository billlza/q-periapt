# Artifact evaluation guide

This artifact backs the paper's claims in three layers, ordered by cost and dependency weight. A
reviewer with only Rust installed can run **Tier 1** in ~10 minutes; **Tier 2** reproduces the CI
gates in ~1 hour given a few extra toolchains; **Tier 3** reproduces the hardware-dependent
measurements (network shaping, binary constant-time) and needs specific hosts.

This artifact evaluates the implemented hybrid-KEM, policy, bindings, four-flight
demo handshake, and evidence chain. It does **not** evaluate a Q-Periapt Continuity
protocol: there is no account/device directory, prekey service, wire protocol,
persistent ratchet, multi-device manager, recovery adapter, or stateful protocol
implementation in this repository. A separate `publish = false` lifecycle model has
31 lifecycle integration tests, 12 canonical-context tests, eight strict canonical
prekey-selection tests, and one private receipt-atomicity regression. It retains trusted pairwise session/current-context
admission across reconstruction, exact version+digest state advances, and a candidate
structured `LifecycleContextV1` plus a strict non-production `PrekeySelectionV1`
record; operation and storage payloads remain opaque. The
model is not part of the paper artifact tiers and contains no real crypto or deployed
session bytes. Its trusted genesis is not credential authentication, and it has no
context-advance API.
Its provider completions, repository/anchor outcomes, receipts, and durability
boundary are abstract trusted-adapter contracts; it does not prove provider-policy
authorization, downgrade resistance, or host fsync-before-effect ordering. The research plan and
model boundary are in
[`docs/CONTINUITY_RESEARCH.md`](docs/CONTINUITY_RESEARCH.md); no existing pass marker
may be interpreted as a PQ3/Signal-parity claim.

All commands run from the repository root. `cargo` ≥ 1.85 is the only hard prerequisite for the
host smoke; proof/release Python gates additionally require CPython ≥ 3.11. The hardened launcher
uses fixed platform paths or an explicit absolute `QPERIAPT_PYTHON`, never a PATH fallback.

## Rust CodeQL analysis boundary

The Rust CodeQL lane uses the CodeQL 2.26.2 bundle linked to the exact pinned CodeQL Action
commit, rather than whichever newer bundle happens to be present in the hosted runner toolcache,
with a Rust 1.94.0 analysis sysroot
because the bundled Rust extractor cannot completely expand this repository with the canonical
Rust 1.96.1 sysroot. This is a compatibility analysis configuration, not native Rust 1.96.1
CodeQL analysis. Before CodeQL initialization, the same commit must pass
`cargo check --workspace --all-targets --locked` under both Rust 1.94.0 and Rust 1.96.1 with
warnings denied, repository-external target directories, and no repository-local `target` entry.

Before any Rust result is uploaded, a fail-closed database gate requires the exact path set of all
93 tracked `.rs` files to be successfully extracted; zero extraction warnings, extraction errors,
unextracted elements, unresolved source macros, AST/CFG/SSA/data-flow inconsistencies, or source
format arguments without an expression and data-flow node; and non-vacuous macro and format-argument
sentinels. Path-resolution and type-inference internal-consistency categories are checked for a
complete, self-reconciling classification and reported as telemetry rather than required to be
zero. In particular, duplicate configurations of `wasm_bindgen`-generated `Abi` type mentions can
produce type-inference telemetry; this is not a claim of complete extractor semantics for that
generated code. The canonical Rust 1.96.1 all-target compile and the separate WASM Node gate cover
those build/runtime surfaces. Each custom query receives a fixed four-thread, 14,000 MB evaluator
budget while retaining its 300-second process deadline and bounded diagnostic output; a resource or
deadline failure blocks publication. Rust analysis runs with SARIF upload disabled and raw database
upload disabled; only an explicit SARIF upload after the quality and unchanged-checkout gates may
publish results. The quality adapter accepts no environment-selected executable, database, or
temporary path: it uses the exact Linux CodeQL 2.26.2 toolcache path and workflow database layout,
rejects unsafe file types, requires the database paths to be current-user-owned and without
cross-account write permission, and revalidates their open path identities around every query and
decode.
The evaluator budget is scoped to the public-repository Rust `ubuntu-latest` lane, currently four
vCPUs and 16 GB. A runner-label, repository-visibility, or hosted-hardware change requires
revalidating the fixed budget rather than lowering the quality gate or extending its deadline.
The pinned action's fixed GitHub-hosted toolcache launcher may be foreign-owned,
group/other-writable, or multiply linked, so its owner, write mode, and link count are observed
runner-image properties rather than gate conditions. Its regular-file type, executable mode, exact
path/version, and open identity remain required.
These checks prevent accidental path drift and ordinary replacement from silently selecting a
different analysis, but they are trusted-runner integrity checks, not isolation from hostile code
already executing under the same runner account. The open descriptors retain path-identity
snapshots; the CLI, database contents, adjacent bundle files, and temporary workspace remain
trusted inputs used by pathname. In-place launcher modification through its original inode or an
alternate hard link is likewise outside this identity-only check. The inherited process environment
and OS runtime are trusted too. The fixed-path rule does not claim to hermetically isolate the
CodeQL process. Resisting same-UID
replace-and-restore or a hostile builder requires an isolated runner image that prevents hostile
local writers; a separate account alone is insufficient when the toolcache is cross-account
writable.

## Quick start — one command

```sh
sh artifact/smoke.sh
sh artifact/proof-to-byte.sh
QPERIAPT_SKIP_SMOKE=1 QPERIAPT_RUN_CONTINUITY_DIAGNOSTIC=1 sh artifact/proof-to-byte.sh
```

The third command is an explicitly scoped, non-release Continuity diagnostic. It
checks the test-only Rust model, independent Python Lifecycle and strict Prekey
encoders/decoders plus full-byte vectors, isolation rules, and both separate EasyCrypt
projection/omission developments. Its pass marker does not
enter the ABI 2 release-attestation state machine.

Runs the minimal closed loop (core tests, shared/reference vectors including the three retained
X-Wing draft-10 vectors and the CFRG `concrete-hybrid-kems-04` Appendix B.2 vector 0
MLKEM768-X25519 vector, the C-ABI face + a real C
link-and-run, the WASM face's shared vector on the host, a real loopback TLS 1.3 handshake over the
hybrid group, and the EasyCrypt no-`admit` gate) and prints `ALL PASS` (exit 0). Needs a Rust
toolchain and a C compiler — no Docker, wasm-pack, Node, or device hardware.
`proof-to-byte.sh` additionally validates the selected hashes in
[`artifact/results.json`](artifact/results.json), verifies the claim ledger and canonical
source-input digest, then runs the same host smoke unless `QPERIAPT_SKIP_SMOKE=1` is set. That
entrypoint intentionally ignores ambient `GITHUB_SHA`. CI and release callers can bind the
actual checkout explicitly with a 40-character lowercase hexadecimal
`QPERIAPT_EXPECTED_GIT_COMMIT`; CI passes the step-scoped `${{ github.sha }}`, which is the tested
synthetic merge commit for a pull request rather than `pull_request.head.sha`. The hardened
source freeze validates this commitment before emitting any proof marker, and malformed or
mismatched values fail with exit status 2.

The host tests also pin two process-local ownership boundaries. For Compat rustls,
the stable private-key representation remains a 32-byte seed; one in-flight client
exchange expands it once into a non-Clone, zeroizing 2,400-byte prepared owner and
reuses that owner at completion. No secret-key cache is global or shared between
handshakes, and the capability is not exported through ABI 2. In the native FFI,
the first dynamically allocated Rust-owned policy-bound-context copy reserves capacity
before sensitive bytes are written and has one RAII wipe owner across normal return,
error, and unwind. Neither assertion covers caller/marshalling copies, registers,
paging, process abort, or full-runtime memory erasure.

The canonical source digest covers tracked plus ignored and visible untracked canonical source
inputs under a fixed, verifier-owned non-input policy: exact untracked regular files whose
basename is `.DS_Store`, plus explicitly enumerated generated-output locations. It also excludes
the two named generated evidence files, `artifact/results.json` and
`paper/camera-ready-results.txt`. Worktree `.gitignore`,
`.git/info/exclude`, and `core.excludesFile` cannot remove an input; any untracked `.gitignore`
outside a fixed ephemeral-output prefix fails closed. The transcript is
bound by its exact named hash in the manifest. When Apple-device, Apple-matrix, or performance
evidence is required, the verifier also requires the actually selected proof path and SHA-256 to
equal the corresponding `artifact/results.json` fields; an environment override cannot silently
select another same-source proof. `artifact/evidence_io.py` strict-loads one bounded regular-file
snapshot, and the Apple/performance verifier uses those same bytes for the manifest SHA-256 check
and semantic validation. Duplicate keys, non-finite JSON, symlinks, oversized files, and ordinary
read-time mutation fail closed; one startup results-manifest digest is pinned across subprocess
gates. Apple verification snapshots its logs, profile, entitlements, linkage report, executable,
and static library once each before using the same bytes for semantics and SHA-256. Clean-state
classification uses a fixed `/usr/bin/git`, an explicit repository, and a minimal environment;
it rejects `assume-unchanged`/`skip-worktree`, compares HEAD with the index and actual tracked
bytes/executable modes, and detects untracked inputs without trusting Git's stat cache or exclude
configuration. Every live-worktree proof/package/device entrypoint also dispatches Python through
`artifact/python-env.sh` and `artifact/python_bootstrap.py`: isolated/no-site startup, a fresh
private bytecode-cache prefix, no writes, cleared `PYTHON*` state, standard-library-first import
order, and repository-only script execution. Repository `.pyc`/`.pyo` files fail provenance even
when ignored. This blocks adjacent forged bytecode and user-site/`.pth` startup injection; it does
not attest the interpreter, standard library, dynamic libraries, OS, or privileged host. The
camera-ready lane is separate: it uses fixed `/usr/bin/python3 -I -S` from its root-owned,
read-only Git archive. The canonical digest is a source-input commitment after explicit non-input
exclusions are removed, not a hermetic proof that no build ever reads generated-output locations;
release-grade
source-to-binary closure still requires an isolated checkout and fresh per-lane output roots. The
manifest root itself is intentionally outside the
non-self-referential digest and **must** be bound by clean committed/signed release provenance
before attestation. A clean proof may be captured at parent commit `P` and selected by a clean
successor `H` only when `P` is an ancestor, `P..H` changes exclusively the two named generated
evidence roots, and the canonical source digest remains equal; this breaks the manifest/proof
self-reference without weakening source binding. The finalizer enforces that
`provenance.snapshot_commit` names `P` (or the exact current commit when there is no successor),
and strictly derives the three `footprint_bytes` entries from the canonical
`paper/footprint.csv`; both checks are repeated around domain verification. A dirty diagnostic has
consistency evidence, not an immutable root.
Manifest-only validation requires any promotional local-current status to carry a canonical
selected-proof path, SHA-256, expected schema, matching canonical source digest, generation time,
and pass summary. It deliberately does not claim the locally referenced target/device file is
portable or present in a fresh checkout; only the required Apple/performance domain verifier loads
that proof and its auxiliary artifacts, checks freshness, and may emit the scoped domain marker.
The legacy JSON field `proof_source_tree_sha256`, transcript label `source-tree-sha256`, and
`CLAIM_LEDGER_AND_SOURCE_TREE_PASS` marker are retained for schema/tool compatibility; each denotes
this exclusions-aware canonical **source-input** digest, not an unfiltered Git tree hash or a
hermetic build-input closure.
The Apple manifest keys named `current_dirty_*` and the
`current_dirty_diagnostic_pass` status are also legacy field names. The selected proof's
`source_tree_dirty` value is authoritative; clean-tree single-device evidence may occupy those
fields until a deliberate manifest-schema migration renames them atomically.

The proof wrapper deliberately has no generic `PROOF_TO_BYTE_PASS` marker. It emits separate
markers for manifest/source validation, Tier-1 host execution, formal machine-checking, Apple
single-device or matrix evidence, Android AAR evidence, canonical Android runtime evidence,
independently selected physical Android runtime evidence, a results-bound local-index consumer
receipt, matched-backend host performance, and an optional producer-origin camera-ready capture
bundle.
Only a clean-tree run that requires host smoke + all formal tools + the iPad/iPhone matrix + a
fresh controlled-host performance budget + a warning-denied dependency audit may emit the
explicitly local Apple/core-scoped `PROOF_TO_BYTE_APPLE_LOCAL_CANDIDATE_PASS`; otherwise the final line is a
scoped `PROOF_TO_BYTE_RUN_FINISHED ...` summary (or `PROOF_TO_BYTE_RELEASE_NOT_ATTESTED` for a dirty
diagnostic run). The canonical Android release selector is the clean arm64-v8a/API-35/16-KiB
release-mode AVD. A clean physical proof over the same source and AAR is an additional production
requirement and cannot replace that selector. The independent physical selection and bound verifier
are implemented; `PROOF_TO_BYTE_ANDROID_LOCAL_PRODUCTION_GATE_PASS` additionally requires AAR,
canonical runtime, physical runtime, and local-consumer states all equal 1 on a clean snapshot. It is
a scoped local gate, not distribution, notarization, or a generic all-platform release marker. If
the independent Apple/core local-candidate requirements also pass in the same invocation, the more
specific final marker is `PROOF_TO_BYTE_APPLE_ANDROID_LOCAL_CANDIDATE_PASS`; it has the same local,
non-public provenance boundary. No generic release marker
exists in the proof-to-byte state machine (published GitHub prereleases are recorded separately
as release receipts in `artifact/results.json`, not as proof-to-byte markers). The local-candidate marker does not accept an Apple Development profile as distribution
provenance. Neither a package build nor historical device evidence is promoted to current release
proof.
The wrapper freezes the exact starting commit, canonical source digest, manifest digest, and dirty
state before any domain gate. Its finalizer rechecks those values in one fail-closed Python boundary
and includes the three identifiers in the final marker. A persistent commit or source transition
observed by the final recheck fails; a later merely clean `git status` observation cannot promote
it. This does not make the working tree immutable: a same-UID replace-and-restore between samples
remains outside detection and requires an isolated read-only checkout or a signed or
transparency-backed source root.
The final marker is only a terminal summary inside a successfully completed
`artifact/proof-to-byte.sh` transcript whose exit status and preceding gate output are retained. It
is not signed or independently verifiable, and a detached or copied marker line is not evidence.

The Tamarin and ProVerif gates cover the current four-flight server-authenticated
handshake only. They do not cover PQXDH, SPQR/Triple Ratchet, ML-KEM Braid, Sesame,
crash consistency, or recovery. Likewise, proof-to-byte binds claims and execution
evidence but is not a formal spec-to-Rust refinement; Signal's public SPQR baseline
reports separate hax/F* implementation checks that this artifact does not yet match.

Set `QPERIAPT_REQUIRE_DEPENDENCY_AUDIT=1` together with the other release requirements to execute
the fixed workspace/fuzz dependency verifier. Install its exact tool first with
`PATH="$PWD/target/qperiapt-audit-tool/bin:$PATH" cargo +1.96.1 install cargo-audit
--version 0.22.2 --locked --root target/qperiapt-audit-tool`. The temporary `PATH` prefix prevents
Cargo's post-install path warning; the verifier itself still ignores ambient `PATH`.
The verifier accepts no source-root or executable-path argument: it derives the repository root
from its own fixed module location and executes only
`target/qperiapt-audit-tool/bin/cargo-audit`. Omitting the requirement flag leaves the run scoped
and cannot emit the release marker. The `0.1.5` stable-version release graph now uses the
target-selected `q-periapt-mlkem-native-sys` boundary over vendored
`mlkem-native` v1.2.0, plus pinned `fips204` 0.4.6 and
`sha3` 0.10.9. This removes both the `fips203` path that failed the project binary-CT
gate and the earlier `libcrux`/hax/`proc-macro-error2` advisory path. The current
lockfile passes `cargo audit --deny warnings` with no advisory ignore. RustSec covers
the resolved Rust package graph only; it does not inspect vendored C, compiler output,
side channels, license correctness, or provenance. This closes only the Rust
dependency-advisory gate, not a third-party cryptographic, C/FFI, side-channel,
implementation, or ABI audit.
The vendored trust anchors are upstream commit
`0ba906cb14b1c241476134d7403a811b382ca498` and the immutable GitHub commit
archive SHA-256
`f1975616b99c86819fb959803b090370d206d2b5fc9639146b79ce846864d677`.
The supplemental canonical `git archive --format=tar HEAD mlkem` SHA-256 is
`77603845ef1bc00cfed17635d4d6844bbf2019b656a3baea8ab18041daa74396`.
Exactly `aarch64-apple-darwin`, `aarch64-apple-ios`,
`aarch64-apple-ios-sim`, `aarch64-unknown-linux-gnu`, and
`aarch64-linux-android`, all little-endian, use upstream native arithmetic plus
a fixed per-target FIPS 202 assembly profile: the two Apple Silicon slices
(`aarch64-apple-darwin`, `aarch64-apple-ios-sim`) pin the Armv8.4-A SHA3 x1/x2
Keccak assembly, and the iOS device slice, Android, and generic Linux pin the
Armv8-A scalar x1 and scalar/Neon x4 paths. Every other target, including Wasm,
remains portable C; each native profile is fixed at build time with no runtime
dispatch. This selection does not change ABI 2, key formats, or wire bytes. Upstream
HOL-Light evidence applies only to selected upstream assembly source/object routines,
not downstream reassembly, the Rust/C integration, or the full ABI. The upstream
tag/commit is not a signed provenance statement, and neither upstream mlkem-native
nor this integration has completed an independent audit.

ABI 2 / `0.1.5` is the stable-version source line, succeeding the fully published
`0.1.4` release (`0.1.5` registry publication remains
receipt-gated). Its coordinated stable GitHub publication targets are the Apple XCFramework
`v0.1.5` and the
`abi2-platforms-v0.1.5` platform distribution (Android AAR plus API 35 /
16 KiB-page emulator runtime evidence and GNU/Linux x86_64+aarch64 SDK archives).
The unsigned Windows x64 MSVC package remains an unsupported CI diagnostic and is
excluded from the formal candidate, manifest, attestation, receipt, and release assets.
Machine-checked, versioned Apple and platform
publication receipts live under `release_publications` in `artifact/results.json`;
`swift_xcframework.distribution` is only the active Apple projection and must match
one of those receipts exactly. Scope, verification commands, and explicit
non-goals are in `artifact/stable-release-notes.md`. The `v0.1.4` and
`abi2-platforms-v0.1.4` releases published on 2026-08-30, and all ten 0.1.4 crates are
published on crates.io; those public records are immutable and are the current published
stable set, superseding 0.1.3. Their verified receipt cohort is recorded only at the
annotated tag `v0.1.4-verified-cohort`, not on `main`: reopening the source line returns
`artifact/results.json` to its 190-key initial baseline, which drops the pending 0.1.4
publication leaves, and the receipt finalizer's release proof requires a results-only
descendant of the 0.1.4 release commit, which `main`'s tip is not. `main`'s trusted results
therefore record no 0.1.4 publication at all and still carry `apple_v0_1_3` as the active
Apple selector. That is a statement about where the receipt evidence lives, not about
whether 0.1.4 shipped; the public GitHub and crates.io records are unaffected by it.
The published `v0.1.3` and
`abi2-platforms-v0.1.3` releases, their frozen `apple_v0_1_3`/`platform_v0_1_3`/
`crates_io_v0_1_3` receipts, and the alpha.2 tags and frozen r2
receipt remain immutable historical evidence, and the `v0.1.0`, `v0.1.1`, `v0.1.2`,
`abi2-platforms-v0.1.0`, `abi2-platforms-v0.1.1`, and `abi2-platforms-v0.1.2` tags remain tagged,
unpublished history superseded by the
published 0.1.3 releases (see the 0.1.0 through 0.1.3 history notes in `artifact/stable-release-notes.md`). The `platform_v0_1_5` receipt has
two exact states: candidate verification pending release verification binds the
descriptor-snapshotted final seven-file local release candidate while omitting every
remote-publication field (absence means unrecorded, not no release), while verified
preserves that candidate verbatim and adds exact matching public assets, immutable
stable-release metadata, tag-plus-assets attestation, and fresh-download deep
verification. Receipt transitions are monotonic.
The line has a
frozen exact-nine dynamic `q_periapt_*` export
contract. The static archive constrains that reserved public namespace but retains
unsupported hidden `qpn_mlkem_bridge_*` link symbols; hidden visibility is not
access control, and a same-process static consumer can deliberately call them. It removes
raw/deterministic public product exports, uses OS randomness, major-isolates the
binary/package identities, and rejects ABI1's four-byte state. Package readiness by
itself does not attest platform binaries; any archive promoted to public/current is
attested by its own release receipt, distribution manifest, `SHA256SUMS`, annotated tag, and
GitHub immutable-release/build-provenance attestations. The Apple-only
credentialed lane separately produces the Developer ID-signed, exact-static-only
XCFramework ZIP whose payload has no notarizable executable or bundle; only
`artifact/results.json` plus its public release evidence may call that
asset current. It is neither a complete remote Swift package nor a final app. A
proof-to-byte pass does not by itself authorize production promotion or platform-binary
distribution: every published platform package/index, dependency audit, and clean signed or
transparency-backed provenance must still pass. Device and performance proofs are
required only for the product-readiness or quantitative claims that select them; their
absence never becomes an implicit pass. ABI1 needs explicit authorized
re-enrollment/reset; a version alone cannot be converted into an exact-policy digest.
The noncanonical Continuity research snapshot shape is unrelated and never a release substitute.
The target-selection/source migration changed the canonical source-input digest.
Consequently, portable-derived Apple/Android device results, the controlled-host
matched-backend proof, package artifacts, and binary-CT captures are all historical
even if they passed on their recorded source. Existing publication receipts remain
immutable evidence for the exact artifacts they name, not the target-selected rebuild.
Each selected package, device, performance, or CT lane must be rebuilt or re-collected
for its target against the new digest. Time-varying currentness is
authoritative only through `artifact/results.json` plus the required live domain
verifiers; source prose cannot promote an old proof after a source change. Even fresh
local product-execution and single-host results will not substitute for independent
signed release provenance, device-energy evidence, or cross-implementation performance parity.

`artifact/source_results_assembler.py` is the stable-source proof-input state machine,
not a general-purpose release finalizer. Its `finalize` command performs the
190-to-249 proof-input migration once per source line: once the generated results-only
successor R is installed, the 249 baseline makes that mode inapplicable, and re-running it
is expected to fail closed because `require_initial=True` requires the exact
pre-migration shape. That failure must not be bypassed by relabelling or hand-editing
`artifact/results.json`. The only supported way back is the reviewed `reopen-source`
reverse transform, which re-arms `finalize` for the next line. It requires a fully
installed 249-key manifest and validates every publication leaf fail-closed *before*
removing any, then emits a 190-key initial candidate that recomputes the retained
proof-input digests from the current source tree while dropping the fixed 59-key delta,
and reduces `release_publications` to exactly the five frozen historical leaves. It drops
only in-flight pending publication candidates and refuses outright on any leaf outside
that frozen floor that is not pending, so a published-immutable receipt is never silently
discarded. The source identity (`proof_source_tree_sha256` and
`provenance.snapshot_commit`) is carried over unchanged from the installed manifest,
naming the frozen stable source the line descends from: recording the reopen commit's own
tree would be circular, since that digest is itself a source input to that tree, and the
run-time assembly commit would be orphaned by the atomic repin commit. The reopen runs
under the same clean-source guard as `finalize` and re-samples the proof-input digests
after assembly, failing if the tree changed underneath it. Its candidate is emitted
no-replace under `target/source-results-successors` and must be installed as
`artifact/results.json` in one atomic commit that also repins `INITIAL_RESULTS_SHA256` to
the returned digest. Because a reopen drops its line's pending publication leaves and
refuses on any non-pending leaf outside the floor, a line's own publication receipts reach
`main`'s trusted results only through an explicitly reviewed change that admits them into
that floor; absent that, the durable record of that line's publication is its immutable
public release and registry material plus its annotated verified-cohort tag, not `main`'s
results. Do not physically edit, extract, or delete the assembler between R and verified
publication V; doing so would create a new source change after the evidence freeze. Retain
`verify-installed` and the exact CI dispatch until their durable 249-key
verifiers are extracted into a neutral module; deleting the whole file would also
delete the installed-successor and main-CI gates.

The main CI source gate deliberately recognizes exactly two manifest states. For
the frozen 190-key pre-migration baseline on `S`, `ci-source-gate` requires the
one-shot Level-1 byte authority
`61101393105ca4a8b32ce5c70a5d7e53b6a3c4884cf0ef064887bda9c7033c88`,
pins the worktree manifest to the HEAD blob, validates the exact initial publication state
and fixed 59-key delta, requires a clean expected commit/tree identity, and samples
the complete 249-key input authority twice before emitting
`SOURCE_TRANSITION_READINESS_PASS`. For an exact 249-key installed map it emits
only a non-PASS dispatch marker and CI must run the full `proof-to-byte.sh` gate.
Malformed, mixed, or changing states fail; an initial-readiness failure never falls
back to the installed path.

The source authority `S` must exist on the final, non-rewritten `main` history
*before* any release-scoped handoff or package evidence is collected.
Merge every source change first, fetch `origin/main`, require a clean checkout with
`HEAD == refs/remotes/origin/main`, and record that 40-hex commit as `S`. Evidence
from a feature-branch SHA, a pull-request synthetic merge commit, or any predecessor
that is later merged/rebased is stale and cannot be selected into `R`.

```sh
git fetch --no-tags origin main
S=$(git rev-parse --verify 'HEAD^{commit}')
case "$S" in ''|*[!0-9a-f]*) exit 1 ;; esac
test "${#S}" -eq 40
test "$S" = "$(git rev-parse --verify 'refs/remotes/origin/main^{commit}')"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
```

Use this exact source-results transition after the stable package producers have
completed against that one clean `S`. The Android runtime and consumer run IDs below
are operator-selected evidence identifiers, not examples that may be copied unchanged.
First run the Rust package contract once on that same clean source checkout and
record the one controlled `RUST_PACKAGE_HANDOFF_PASS` path and digest from stderr; its
manifest-last transaction is the only Rust transcript/archive source accepted by the
assembler or later crates.io coordinator. A nonzero exit or anything other than one
controlled PASS marker is failure: never scan for or select a private orphan; after
checking that S is still clean, run a new transaction:

```sh
sh artifact/rust-publish-contract.sh
# Set both values verbatim from the single RUST_PACKAGE_HANDOFF_PASS marker.
: "${RUST_HANDOFF_MANIFEST:?set the emitted repository-relative handoff manifest path}"
: "${RUST_HANDOFF_SHA256:?set the emitted handoff manifest SHA-256}"
case "$RUST_HANDOFF_MANIFEST" in
  target/qperiapt-rust-package-handoffs/transaction.*-*/rust-package-handoff.json) ;;
  *) exit 1 ;;
esac
case "$RUST_HANDOFF_SHA256" in ''|*[!0-9a-f]*) exit 1 ;; esac
test "${#RUST_HANDOFF_SHA256}" -eq 64
test "$(shasum -a 256 "$RUST_HANDOFF_MANIFEST" | awk '{print $1}')" = \
  "$RUST_HANDOFF_SHA256"

: "${ANDROID_RUNTIME_RUN:?set the selected Android runtime run ID}"
: "${CONSUMER_RUN:?set the selected consumer run ID}"
baseline_sha256=$(shasum -a 256 artifact/results.json | awk '{print $1}')
sh artifact/python-run.sh artifact/source_results_assembler.py finalize \
  "$baseline_sha256" \
  --rust-handoff-manifest "$RUST_HANDOFF_MANIFEST" \
  --rust-handoff-sha256 "$RUST_HANDOFF_SHA256" \
  --android-runtime-run "$ANDROID_RUNTIME_RUN" \
  --consumer-run "$CONSUMER_RUN"
```

This core stable-publication transition deterministically marks the historical Apple
device/matrix and performance selectors `stale_requires_rerun`; an absent physical
Android selector remains absent. The corresponding raw verifiers and explicit
`proof-to-byte.sh` requirement flags remain the authority for later product-readiness
or performance claims. A failed optional verifier is never converted into stale
success; only omission from this core transition selects the explicit stale/absent
state.

The command emits one controlled `SOURCE_RESULTS_SUCCESSOR_PASS` marker containing a
repository-relative candidate path and SHA-256. Set the following two values from that
exact marker, require the candidate bytes to match, and install those bytes without
editing their JSON content:

```sh
candidate=target/source-results-successors/transaction.EMITTED_ID/results.json
candidate_sha256=EMITTED_64_LOWERCASE_HEX_SHA256
test "$(shasum -a 256 "$candidate" | awk '{print $1}')" = "$candidate_sha256"
install -m 0644 "$candidate" artifact/results.json
test "$(shasum -a 256 artifact/results.json | awk '{print $1}')" = "$candidate_sha256"
cmp -s "$candidate" artifact/results.json
test "$(git diff --name-only -- artifact/results.json)" = artifact/results.json
git diff --exit-code -- . ':(exclude)artifact/results.json'
test -z "$(git ls-files --others --exclude-standard)"
# Re-sample both pathnames immediately before staging.
test "$(shasum -a 256 "$candidate" | awk '{print $1}')" = "$candidate_sha256"
test "$(shasum -a 256 artifact/results.json | awk '{print $1}')" = "$candidate_sha256"
cmp -s "$candidate" artifact/results.json
git -c core.fsmonitor=false -c core.hooksPath=/dev/null \
  -c core.attributesFile=/dev/null -c core.excludesFile=/dev/null \
  add -- artifact/results.json
test "$(git -c core.fsmonitor=false -c core.hooksPath=/dev/null \
  -c core.attributesFile=/dev/null -c core.excludesFile=/dev/null \
  diff --cached --name-only)" = artifact/results.json
# Re-sample once more after staging and before the hook-disabled commit.
test "$(shasum -a 256 "$candidate" | awk '{print $1}')" = "$candidate_sha256"
test "$(shasum -a 256 artifact/results.json | awk '{print $1}')" = "$candidate_sha256"
cmp -s "$candidate" artifact/results.json
test "$(git -c core.fsmonitor=false -c core.hooksPath=/dev/null \
  -c core.attributesFile=/dev/null -c core.excludesFile=/dev/null \
  show :artifact/results.json | shasum -a 256 | awk '{print $1}')" = \
  "$candidate_sha256"
git -c core.fsmonitor=false -c core.hooksPath=/dev/null \
  -c core.attributesFile=/dev/null -c core.excludesFile=/dev/null commit \
  -m 'release: install stable source results successor'
test "$(git -c core.fsmonitor=false -c core.hooksPath=/dev/null \
  -c core.attributesFile=/dev/null -c core.excludesFile=/dev/null \
  show HEAD:artifact/results.json | shasum -a 256 | awk '{print $1}')" = \
  "$candidate_sha256"
sh artifact/python-run.sh artifact/source_results_assembler.py verify-installed \
  "$candidate_sha256"
```

The source commit must already be clean before `finalize`; the next commit must change
only `artifact/results.json` and be its direct child. Do not tag, publish, delete the
retained candidate, or run any downstream release finalizer unless `verify-installed`
prints `SOURCE_RESULTS_INSTALLED_VERIFY_PASS` for that exact commit.

The expected per-step counts, toolchain, current-source local footprint sizes, and data-file pointers are pinned in
[`artifact/results.json`](artifact/results.json) (every value measured, so drift is visible). A
frozen historical capture is in [`artifact/ci-snapshot.log`](artifact/ci-snapshot.log); it is useful
for provenance, but the current clean gate is the live command output, not that historical log.

---

## Tier 1 — 10-minute host smoke (Rust + C compiler)

Verifies the core composition logic, host-side conformance checks, the real C link smoke, and the
no-admit proof gate. No Docker, symbolic prover, Node, or device hardware is required.

```sh
cargo test --workspace            # KATs, ACVP, differential, proptests, FFI/WASM host vectors
cargo fmt --all --check           # formatting gate
! grep -rnEw 'admit|sorry' --include='*.ec' formal/easycrypt/  # complete EasyCrypt tokens only
```

Expected: all tests pass; the grep finds nothing (exit 0 via the `!`). This establishes byte-identical
KATs, NIST ACVP conformance, the independent-crate differential checks, and that the committed
EasyCrypt proof has no `admit`/`sorry`.

The dk-format separation (Theorem 1, item 5) is witnessed by a runnable example — both the
expanded-`dk` break and its seed-`dk` negative control, against the target-selected
release-graph `mlkem-native` backend for the compilation target:

```sh
cargo run -p q-periapt-backends --example binding_dk_format_witness
```

It prints, for two distinct ML-KEM public keys: over expanded-`dk` the lean (X-Wing-shaped)
combiner collides on K-PK while `ContextBound` does not; over seed-`dk` (z re-derived from a 32-byte
seed, as deployed X-Wing mandates) the attack vector is closed. The same two checks run as the
`binding_keyformat_separation` integration test under Tier 1's `cargo test`.

## Tier 2 — ~1 hour, reproduce the CI gates

Adds the optional SLH-DSA backend, the isolated HQC draft-candidate shadow gate, the
the **pinned-source EasyCrypt container check**, the language bindings, and the cross-target builds.
Extra prerequisites are in parentheses.

```sh
cargo clippy --workspace --all-targets -- -D warnings                  # lint gate
cargo test -p q-periapt-backends --features slh-dsa                    # optional SLH-DSA backend
bash research/hqc-fips207-candidate/scripts/verify.sh                  # independent publish=false HQC-v5/FIPS-207-draft gate
cargo audit --deny warnings                                            # no advisory warning or ignore is release-safe

# Pinned-source binding proof (needs Docker). Builds the exact-base/exact-EasyCrypt image and re-checks
# the proof + seven proof-dependency regression controls as a HARD gate. These controls show that
# the current scripts use named facts; they are not semantic necessity proofs. The checked
# `kctx_without_nonbottom_broken` lemma is the explicit probability-one countermodel for omitting
# `K != bottom` from the explicit-rejection context-binding game:
docker build -f formal/Dockerfile -t q-periapt-ec .
docker run --rm -v "$PWD/artifact:/work/artifact:ro" \
    -v "$PWD/formal/easycrypt:/src:ro" q-periapt-ec \
    opam exec -- sh -c 'sh artifact/python-run.sh \
        artifact/formal_toolchain_contract.py verify-installed --tool easycrypt \
        && mkdir -p /tmp/ec && cp -r /src/. /tmp/ec && cd /tmp/ec \
        && rm -f *.eco continuity/*.eco \
        && MAKEFLAGS="" GNUMAKEFLAGS="" MAKEFILES="" \
        make EC=easycrypt check \
        && EASYCRYPT=easycrypt sh negative-controls.sh \
        && MAKEFLAGS="" GNUMAKEFLAGS="" MAKEFILES="" \
        make -C continuity EC=easycrypt check'

sh bindings/c/build-and-run.sh                                         # C-ABI link smoke (needs cc)
CC_wasm32_unknown_unknown=/absolute/path/to/llvm-clang \
  cargo build -p q-periapt-wasm --target wasm32-unknown-unknown        # wasm32 (needs the target)
cargo build -p q-periapt-core --target thumbv7em-none-eabihf           # no_std embedded (needs the target)
```

The formal-tool contract is a Level-1 accidental-drift check, not executable-byte
attestation. Each identity probe has a 30-second timeout and 64-KiB cap per output
stream, requires strict UTF-8 and exact pinned identities, and fails before any formal
`make` command on missing tools, warnings/errors, malformed output, or version drift.
Release-authority invocations also pass the same fixed basenames as explicit `make`
command-line variables. They clear `MAKEFLAGS`, `GNUMAKEFLAGS`, and `MAKEFILES`
before each `make`, so ambient dry-run, ignore-error, alternate-makefile, and
variable-override settings cannot skip a proof or select another prover.

The WASM compiler path must be absolute and name upstream LLVM Clang with a
`wasm32` backend (`clang --print-targets` must list it); Apple Clang is rejected.
Use `$(brew --prefix llvm)/bin/clang` on macOS or `/usr/bin/clang-18` on Linux.
Pass the same environment variable to `wasm-pack test --node crates/q-periapt-wasm`.

Optional binding faces (each needs its own toolchain): `swift test --package-path bindings/swift`
(Swift); `sh artifact/android-aar.sh` (Android AAR/JNI package proof, Android SDK/NDK + Rust Android
targets); the Kotlin/Panama FFM tests (JDK ≥ 22 + gradle); `wasm-pack test --node
crates/q-periapt-wasm` (wasm-pack + Node). The full GitHub Actions workflow in
`.github/workflows/ci.yml` is the canonical list; `formal-easycrypt` is the proof hard gate. Its
base image and EasyCrypt source are immutable, but apt/opam transitive resolution is not a hermetic
or bit-reproducible closure.

### Consumer embedding readiness gate

For downstream consumers that want the current "download/build/use" contract rather than only the
paper smoke, run:

```sh
sh artifact/embedding-readiness.sh
```

This is fail-closed and warning-clean: it checks locked Cargo metadata, `cargo fmt`, warning-denied
clippy, workspace tests, optional SLH-DSA backend tests, release C-ABI build, generated-header
freshness (`cbindgen` output must match both the C and Swift vendored headers), the C link-and-run
smoke with runtime ABI/suite metadata, host C release archive proof (`artifact/c-package.sh`) through
extracted dynamic/static pkg-config and CMake consumers plus archive license/CBOM/SBOM validation,
Swift XCTest count, Swift XCFramework/binaryTarget pre-publication proof
(`artifact/swift-xcframework.sh`) through an isolated binary consumer, Android AAR/JNI packaging
proof (`artifact/android-aar.sh`) with four ABI slices, native/JNI symbol audits, dex conversion, and
an isolated Java consumer compile, Kotlin/Panama tests with explicit native library loading, WASM
Node tests, and `proof-to-byte.sh`. The Rust crate pre-publication package-ready
surface has a separate package-contract gate,
`sh artifact/rust-publish-contract.sh`, which requires a clean tree by default, validates the
ten-crate publish allow/deny list, checks package file lists, applies every downstream local patch,
and runs registry-bound `cargo package` with rebuilt-archive verification for each publishable crate;
all Cargo warnings fail the gate and no upload command is invoked. It then creates fresh
isolated sys/backend archives. The contract also creates a fresh owned `0700` Cargo home instead
of consuming the caller's Cargo/RustSec cache. The normalized audit fetches its RustSec database
there, then requires the exact upstream origin, a canonical commit, and a clean database worktree
before the owned directory is descriptor-bound cleaned. Cargo-home configuration, credential files,
registry cache, and advisory state are isolated; caller environment, selected
Rust/Cargo/cargo-audit executables, network transport, and the OS runtime remain trusted host
inputs. Because `cargo-audit` 0.22.2's built-in yanked check requires the multi-gigabyte legacy Git
index, the contract checks the same exact locked names, versions, and checksums against the bounded
official crates.io sparse HTTPS index, then runs the warning-denied advisory audit with its
incompatible duplicate yanked path disabled. A yanked, missing, malformed, or mismatched sparse
entry fails the contract; this is a responsibility split, not a warning suppression or skipped
registry check. The sys `.crate` is inspected independently for links/special or
forbidden paths, the fixed 124-entry upstream inventory, the exact packaged 118-code-file hash
subset (excluding six upstream README files), the pinned upstream license and v1.2.0 provenance,
and the fixed target-selected native/portable build surface. Cargo's normalized backend graph is generated
with the sys crate patched in and audited separately, so the provider, retired-HQC/PQCrypto,
inventory, license, and normalized-graph checks cannot be skipped. This no-upload contract does
not prove crates.io upload-API acceptance, crate-name ownership, publishing credentials or
authorization, server-side policy acceptance, or a registry receipt. The coordinated registry
order is sys, core, KEM/signature traits, backends, policy, then
the FFI/WASM/rustls leaves; the dependency-free CLI is part of the same version set.
`artifact/results.json` may declare that source-bound package receipt current only through its
strict schema, exact source identity, advisory snapshot, manifest-last handoff fingerprint,
retained transcript fingerprint, and the exact ten sibling `.crate` archives validated by that
handoff. The assembler and crates.io coordinator both consume the same explicit transaction;
there is no second fixed transcript path or manual-copy authority.
Set `QPERIAPT_REQUIRE_RUST_PACKAGE_CONTRACT=1` to make `proof-to-byte.sh` load that exact selected
handoff, verify its exact inventory plus transcript marker set and ordering, and expose a separate
`rust_package_contract=1` finalizer state. This does not set or replace
`dependency_audit=1`: the explicit workspace/fuzz lock audit remains a separate live gate.
When `QPERIAPT_REQUIRE_DEPENDENCY_AUDIT=1`, that gate snapshots both checked-in
lockfiles, requires their fixed local-package scopes, verifies every crates.io
name, version, checksum, and non-yanked status through the same bounded sparse
HTTPS verifier, and runs warning-denied advisory scans against one freshly
fetched RustSec database in a private Cargo home. The fuzz scan reuses that exact
clean database without fetching again, and both lock snapshots plus the database
commit are revalidated before success. The whole acceptance sequence has one
900-second monotonic deadline; each subprocess retains its smaller stage cap and
the fixed reap window, while owned-directory cleanup still runs on every exit.
CI calls the same verifier; neither path consumes the caller's Cargo-home files
or advisory database. The repository-local `cargo-audit` launcher is a selected trusted-host input,
but its path is fixed by code rather than accepted from a CLI argument or ambient `PATH`.
These SHA-256 values
bind exact lock bytes to one run for accidental mismatch detection; they do not
attest against a hostile host, crates.io, RustSec, system CA store, or network.
The Swift XCFramework gate also requires a clean tree by default; set
`QPERIAPT_ALLOW_DIRTY_SWIFT_XCFRAMEWORK=1` only for local diagnostics. Set
  `QPERIAPT_EMBED_REQUIRE_DEVICE_MATRIX=1` plus
  `QPERIAPT_DEVICE_RESULT_DIR=/absolute/path/to/<matrix-run-dir>` to also
require a fresh iPad+iPhone matrix proof. The Android release transaction is ordered and must remain
on one unchanged clean source snapshot: produce the exact AAR; execute it on the script-owned
arm64-v8a/API-35/16-KiB release-mode AVD; create the first release index with
the explicit `release` channel, dirty mode disabled, Apple matrix inclusion disabled,
`QPERIAPT_RELEASE_INDEX_INCLUDE_ANDROID_RUNTIME=1`, and the exact
`QPERIAPT_ANDROID_RUNTIME_RUN=<32-hex-run-id>`:

```sh
QPERIAPT_RELEASE_INDEX_CHANNEL=release \
QPERIAPT_ALLOW_DIRTY_RELEASE_INDEX=0 \
QPERIAPT_RELEASE_INDEX_INCLUDE_APPLE_MATRIX=0 \
QPERIAPT_RELEASE_INDEX_INCLUDE_ANDROID_RUNTIME=1 \
QPERIAPT_ANDROID_RUNTIME_RUN=<32-hex-run-id> \
sh artifact/local-release-index.sh
```

Then run `sh artifact/local-release-consumer-smoke.sh`
to execute the extracted dynamic and static C consumers and append one receipt; then make one
evidence-only `artifact/results.json` successor selecting the exact AAR, AVD proof, index, and
receipt. Only after that successor exists, set
`QPERIAPT_EMBED_REQUIRE_ANDROID_RUNTIME=1`,
`QPERIAPT_EMBED_REQUIRE_LOCAL_RELEASE_CONSUMER=1`, and
`QPERIAPT_ANDROID_DEVICE_PROOF=target/qperiapt-android-device-smoke-runs/<run-id>/proof/qperiapt-android-device-proof.json`
on `artifact/embedding-readiness.sh`. These options enter a separate read-only final mode before
any package producer or build tool is invoked. The script calls `proof-to-byte` exactly once and
then exits with `EMBEDDING_ANDROID_BOUND_VERIFY_PASS` plus explicit `canonical=1`,
`physical=<0|1>`, and `local_release_consumer=<0|1>` fields; it does not regenerate the fixed AAR
path or generate/repair a receipt. Add
`QPERIAPT_EMBED_REQUIRE_ANDROID_PHYSICAL_RUNTIME=1` and the selected
`QPERIAPT_ANDROID_PHYSICAL_DEVICE_PROOF` for the four-domain production aggregate. Passing this
optional transaction gate proves that the selected current-source Android artifacts and host C
archive consumer receipt are mutually bound; it is not a public release attestation. After the
package gates have produced artifacts,
`sh artifact/local-release-index.sh` creates a local hash-bound index under
`target/qperiapt-local-release/<channel>/<version>/<commit>/` over the C archive, Swift XCFramework zip, and
Android AAR. Release mode requires a clean tree. Set `QPERIAPT_ALLOW_DIRTY_RELEASE_INDEX=1` only for
diagnostic indexes; optional Apple/Android runtime evidence is included as raw-value-omitting proof summaries,
never as copied raw device logs or profiles. An Android summary requires both
`QPERIAPT_RELEASE_INDEX_INCLUDE_ANDROID_RUNTIME=1` and the exact immutable
`QPERIAPT_ANDROID_RUNTIME_RUN=<32-hex-run-id>` selector; release indexes rerun the complete
canonical AVD release-runtime contract (emulator, arm64-v8a, API 35, 16 KiB pages, release mode)
rather than trusting a summary field. Physical-device proofs remain valid explicit runtime evidence,
but they are not the canonical Android proof admitted into the release-channel index. Index schema 5 also projects the
verified page size, release-candidate mode, passing result, and fixed external-adb/native-notifier
admission into the raw-value-omitting Android summary so
offline index consumers can see the canonical release-runtime contract. It accepts only the current producer envelopes
(C schema 2, Swift schema 5, Android schema 4), binds their exact package-only targets and boundaries,
and rejects the credentialed/signed Swift lane because it does not copy `APPLE_DISTRIBUTION.json`.
The local consumer is a producer, not a finalizer: it publishes a private append-only receipt only
after both extracted C consumer modes pass. The receipt binds the index, C archive, indexed Android
AAR, and the index's canonical runtime identity. The results-only successor must bind the exact
receipt path/hash and exact index path/hash before any final verifier accepts
`current_clean_tree_local_index_consumer_pass`.
For a later production promotion, capture a separate clean physical run over the same AAR and
source. The stable package-publication assembler does not select that proof. A separately reviewed
product-readiness evidence transition must first bind it under `android_physical_runtime`; only after
the installed results manifest selects that exact proof may the final bound gate require all four
Android domains in one pinned-manifest transaction:

```sh
QPERIAPT_REQUIRE_ANDROID_AAR=1 \
QPERIAPT_REQUIRE_ANDROID_RUNTIME=1 \
QPERIAPT_ANDROID_DEVICE_PROOF=target/qperiapt-android-device-smoke-runs/<canonical-run-id>/proof/qperiapt-android-device-proof.json \
QPERIAPT_REQUIRE_ANDROID_PHYSICAL_RUNTIME=1 \
QPERIAPT_ANDROID_PHYSICAL_DEVICE_PROOF=target/qperiapt-android-device-smoke-runs/<physical-run-id>/proof/qperiapt-android-device-proof.json \
QPERIAPT_REQUIRE_LOCAL_RELEASE_CONSUMER=1 \
sh artifact/proof-to-byte.sh
```

The physical verifier fixes freshness to 86,400 seconds and derives ABI, page size, SDK, build
tools, and release-candidate mode from the results-selected proof; callers cannot weaken those
facts. A current API-36/4-KiB non-release physical proof is valid supplemental execution evidence.
The production aggregate remains pending until a fresh physical run is captured and selected by
that separate transition; the bound marker, not this document, is the currentness authority. Stable
package publication must leave the physical requirement disabled and must not claim the aggregate.
The emitter and consumer derive the repository root from their installed script location and select
only the fixed channel pointer; arbitrary root, index, and output-path CLI overrides are not supported.
Each `<channel>/<version>/<commit>` tree is immutable once created. A serialized emitter first builds
and verifies a unique mode-0700 sibling staging tree, then publishes it with the host's native atomic
no-replace operation (`renameatx_np(RENAME_EXCL)` on macOS or
`renameat2(RENAME_NOREPLACE)` on Linux) before replacing the single authoritative per-channel pointer
inside one short termination-deferred window. Missing native support fails closed; there is no
check-then-rename fallback that may replace an existing destination. An interruption during package
copying can therefore leave at most an unselected private staging tree; the next serialized emit
removes only strictly named, current-user-owned mode-0700 staging remnants before using a fresh name.
If `SIGKILL` or host loss occurs after final-tree publication but before pointer commit, the next emit
fully verifies that exact channel/version/commit tree, including its complete file inventory,
manifests, checksums, current source identity, ABI contract, and exact requested proof summaries,
then idempotently advances or confirms the pointer without rebuilding or rewriting the tree. A
corrupt, permission-invalid, or proof-selector-mismatched final tree is preserved for investigation
and fails without changing the pointer. Re-emitting an already verified and exactly selected identity
is an idempotent success; a different identity or selector cannot overwrite it. Exact owned pointer
temporary files left by this window are removed only after complete tree and selector verification,
and the already-matching fast path retries the pointer-parent directory sync before returning success.
The local store and consumer work directories use mode 0700, and copied packages, indexes, checksums,
and pointers use mode 0600. Publication tooling must explicitly create separately permissioned public
artifacts rather than reusing this private local store.
Its machine-readable boundary records the required leaf gate, absence of an embedded leaf receipt,
and the trusted local artifact-store assumption. It does not independently authenticate mutable
`target/` bytes or turn locally recomputable hashes into a signed attestation; run the leaf gates
first and use the results-only evidence successor or an external release attestation for durable
provenance. Credentialed Apple distribution uses
`artifact/swift-xcframework-release.sh`, builds from a fixed detached source commit, pins the
Developer ID identity/certificate, verifies the exact static-only ZIP layout, and binds the final
ZIP, SwiftPM checksum, source commit, signature resources, certificate, and slice hashes in public
`APPLE_DISTRIBUTION.json`. This SDK payload has no standalone executable or notarizable bundle, so
notarization is explicitly recorded as not applicable and never as Accepted. The consuming macOS
product retains its own signing and notarization responsibility.
The stable-version GitHub publications are not by themselves a production-readiness
claim. The targets `v0.1.5` and `abi2-platforms-v0.1.5` become public,
immutable, attested non-prerelease releases only when their current verified receipts say so;
the published 0.1.3 and alpha.2 receipts remain `main`'s immutable historical receipt evidence,
and the published 0.1.4 releases are attested by their own immutable public release and registry
material plus the `v0.1.4-verified-cohort` tag rather than by any receipt on `main`. The platform packages carry exact-version
pkg-config/CMake configs, ABI contracts, SBOM/CBOM, and license material. What still
separates them from production promotion: a fresh same-source Apple device matrix,
a current-source canonical Android arm64 AVD transaction plus a clean physical-device proof over
the same source and AAR, a future signed Windows distribution (the current unsigned
diagnostic is excluded),
crates.io/Maven/deb/rpm/MSIX registry publication with independently verifiable
signed or transparency-backed provenance, and independent cryptographic/C-FFI/ABI
review. None of these is silently represented as done.

## Tier 3 — hardware-dependent measurements

These produce the paper's primary network table and the binary constant-time discriminator. They
  need specific hosts and privileges, and are **not** required to validate the security claims.

- **Bare-metal time-to-session (Table VI).** A quiesced bare-metal **Linux x86-64** host with
  Linux kernel 5.14+ and util-linux 2.39+ (`cgroup.kill` and recursive read-only mounts are mandatory),
  unified cgroup v2 plus `cgroup.kill`, Python 3.11+, native Valgrind, and a root-owned/non-writable Rust
  toolchain (default lookup under `/opt/qperiapt-rust/bin`, `/usr/local/bin`, then `/usr/bin`).
  Provision a locked `qperiapt-camera` system account whose primary group is not shared and whose
  shell is `nologin`/`false`; the account must own no process before capture. Also pre-populate a
  root-owned, recursively non-writable, symlink-free Cargo seed at
  `/opt/qperiapt-cargo-home` (or set `QPERIAPT_CARGO_SEED_HOME`). The seed may contain only
  `registry/cache/.../*.crate` and `registry/index/...` files: no pre-extracted `registry/src`, Git
  source, Cargo config, credential, executable, or special file is accepted. Before either build,
  the harness requires an exact one-to-one closure with every crates.io package in `Cargo.lock` and
  verifies each cached `.crate` against the lockfile checksum. Each build gets a fresh writable copy
  of that verified seed and a fresh target directory. Cargo runs `--frozen` and build scripts run in
  a separate network namespace with no host network; measured binaries run in a distinct persistent
  namespace whose only enabled interface is loopback, where the root supervisor applies and verifies
  netem. Use a pipe whose status cannot hide a script failure:

  ```sh
  mkdir -p target/camera-ready
  bash -o pipefail -c \
    'sudo env QPERIAPT_BARE_METAL_CONFIRMED=1 sh camera-ready-bare-metal.sh 2>&1 | \
       /usr/bin/tee target/camera-ready/transcript.txt'
  ```

  (~20 min). Before any untrusted build code can run, the bootstrap copies itself to a root-owned
  launcher and later proves those launcher bytes equal the clean Git archive. The root process is
  only the host-state/build supervisor. Cargo/build.rs, benchmarks, and Valgrind run under the
  dedicated locked account with groups/capabilities cleared, `no_new_privs`, a fixed tool
  environment, and a fresh cgroup v2 per command. Every cgroup has finite process, memory, and swap
  limits; any surviving descendant fails the command and is killed. The supervisor work root is the
  root-owned on-disk `/var/lib/qperiapt-camera-ready-work`, while all runner-owned Cargo homes and
  targets live on a separate 8-GiB/524,288-inode tmpfs. Each untrusted command also receives private
  mount and IPC namespaces plus bounded private `/tmp`, `/var/tmp`, `/dev/shm`, and `/run` mounts.
  The inherited host mount tree is recursively read-only; only the current protected work tree and
  those bounded private mounts are writable. This is not a host-confidentiality boundary: the
  disposable measurement host must contain no unrelated readable secrets.
  Build outputs are copied only after that cgroup is empty into root-owned non-writable measurement
  paths. Valgrind receives a separate root-owned empty HOME and working directory, so build code
  cannot inject `.valgrindrc`. The harness freezes and rechecks the commit, canonical
  canonical source archive, trusted-tool and measured-binary hashes; validates the exact netem
  delay and rejects additional loss/jitter/rate/reorder/corruption; checks tuning before and after
  every measured command; and restores host state before its sole success marker. Measurement rows
  remain compatible with `paper/camera-ready-results.txt`, while the hardened harness adds
  provenance and bundle fields absent from that historical capture. A
  virtualized or emulated host is rejected; such measurements cannot be promoted to primary data.
  This containment limits host escape and resource exhaustion from faulty dependency/build code; it
  is **not** a proof against an actively malicious Cargo dependency modifying sibling extracted
  sources or target artifacts during the same-UID Cargo invocation. The camera lane therefore
  assumes the checksum-pinned dependency closure and compiler are trusted experiment inputs. A
  hostile-dependency source-to-binary claim would require per-action sandboxing or an independent
  reproducible builder and is outside this bundle's stated boundary.
  A successful run prints `bundle-location:` and atomically publishes a root-owned run-id directory
  at `/var/lib/qperiapt-camera-ready/<run-id>/`: the clean source archive, three measured binaries,
  120-row TSV plus canonical summary JSON, build logs, all five raw Memcheck logs, tool identities,
  the lock-closed Cargo-seed manifest, baseline/10ms/25ms/final qdisc snapshots, and canonical
  before/active/after capture metadata. Reverify a fresh capture against the referenced capture
  commit and current canonical source-input tree by explicitly using that emitted run-id directory:

  ```sh
  sh artifact/python-run.sh artifact/camera_ready_proof.py verify \
    --root . \
    --transcript target/camera-ready/transcript.txt \
    --bundle /var/lib/qperiapt-camera-ready/<run-id> \
    --max-age-seconds 86400
  ```

  The verifier permits a successor commit only when its changes are confined to the two named
  generated-evidence exclusions and the canonical source-input digest is unchanged. The resulting
  `CAMERA_READY_BUNDLE_INTEGRITY_PASS` is integrity-checked producer-origin evidence, **not** an
  independent runtime attestation: hashes alone do not prevent the producer from fabricating or
  replaying an entire bundle. A TPM/signing trust anchor plus an external nonce would be required
  for that stronger claim. The committed `paper/camera-ready-results.txt` predates this hardened
  schema and is historical data, not a passing current-tree camera proof. Set
  `QPERIAPT_REQUIRE_CAMERA_READY=1` on `artifact/proof-to-byte.sh` and explicitly set
  `QPERIAPT_CAMERA_READY_BUNDLE=/var/lib/qperiapt-camera-ready/<run-id>`; the transcript continues to
  default to `target/camera-ready/transcript.txt` and may be overridden with
  `QPERIAPT_CAMERA_READY_TRANSCRIPT`. Requiring an explicit bundle path prevents an unbound
  transcript location from silently selecting a different run.
- **Source→binary constant-time discriminator (§V-A).** Valgrind/Memcheck on **x86-64 or aarch64
  Linux** (native or a Linux container; not under nested emulation). `sh ctstats/scripts/ct-gap-probe.sh`
  via Docker, or build `ct_decaps_gap` with `--features valgrind` and run under `valgrind`.
  The current harness requires the genuine-secret ŝ+z probe for every shipped
  ML-KEM-512/768/1024 wrapper to report exact zero and its synthetic planted
  secret-indexed control to report positive, so zero cannot pass vacuously. The superseded
  `fips203` 0.4.3 provider is historical failure evidence, not a pass: [CI run
  29230650107](https://github.com/billlza/q-periapt/actions/runs/29230650107) reported
  34,306 errors / 100 contexts on x86_64 and 30,464 / 70 on aarch64. Earlier `libcrux`
  captures and pre-selection portable `mlkem-native` results are historical too.
  Fresh x86_64-portable and aarch64-native zero/zero passes bound to the release
  source digest are required before promotion. The exact-R tag workflow records those
  two fixed successful CI jobs, the selected run/attempt, and all six successful CodeQL
  language jobs in the attested `ABI2_SOURCE_SECURITY_GATE.json`. The same receipt binds
  `refs/heads/main` to R, the latest exact-R analysis for each fixed CodeQL category,
  adjudicated results, positive rule counts, empty analysis errors/warnings, and an empty
  main-ref open-alert response. Candidate verification
  deeply checks that sanitized receipt and its workflow-source digests; the platform
  pending/verified receipts retain the same structure and subject-digest crosslink. The
  receipt is transaction evidence, not a public product asset, and the contract does not
  claim a run exists until the exact-R workflow has produced it. The committed
  PQClean-HQC counts (193 on aarch64 and 22,849 on x86-64) came from the retired backend and are
  historical older-source evidence only; `ct_hqc_gap` is no longer a current release gate.
- **Symbolic provers.** `make` under `formal/tamarin/` and `formal/proverif/` (Tamarin 1.12.0 +
  Maude 3.5.1; ProVerif 2.05 via opam). The current inventories are five Tamarin lemmas and six
  exact ProVerif queries, including authenticated context agreement. CI gates their presence and
  full `make prove`; Tamarin is invoked with `--quit-on-warning`, and the ProVerif Makefile matches
  each expected result independently.
- **Apple device binding smoke.** `sh artifact/apple-device-smoke.sh` runs the macOS native Swift
  binding tests, builds the Rust `aarch64-apple-ios` staticlib, builds a host-app runner for a
  physical iPhone/iPad, installs it, and accepts only an on-device
  `QPERIAPT_DEVICE_PASS run-id=<32 hex chars>` marker plus the matching run-bound
  result file copied from the app data container and a structured single-device
  proof JSON. Proof schema v4 freezes the git commit and the claim-ledger canonical
  source-input digest before any build, then rechecks both after the device run
  and immediately before proof emission. The verifier recomputes that digest; dirty mode never
  relaxes content or commit binding. The proof also binds the run id, readable named source hashes
  including the signed-policy vector and named Rust workspace source files, worktree dirty status,
  app/staticlib hashes, selected physical-device type and transport, Xcode build log hash,
  copied marker hash, provisioning profile
  validity, codesign entitlements, static Rust FFI linkage, and the weak AppIntents link used for
  Xcode 27 warning-clean app builds. It also binds a schema-v1 trusted-local Xcode receipt captured
  before the first build and reverified after device execution: the resolved Developer directory,
  Xcode/Swift versions, root-owned non-writable installation boundary, Apple code-signing
  identity and authority chain, Gatekeeper `Apple System` assessment, CodeResources, version
  plists, the Xcode executable, `xcodebuild`, and iPhoneOS SDK settings. This detects accidental
  selected-toolchain replacement; it is neither a byte hash of the complete Xcode installation nor
  independent provenance against a hostile administrator or same-UID producer. The build commands
  still execute in a trusted local host environment; this receipt does not attest every selected
  executable, caller environment variable, or byte executed by the build. The verifier
  recomputes `device_id_sha256` from the child
  `device_id`; matrix distinctness cannot be supplied as an unbound self-declared hash. Verification rejects proof inputs outside
  `artifact/device-runs` and app/staticlib paths outside `target`.
  The selected raw evidence tree is privacy-gated as current-user-owned directories at mode 0700
  and regular single-link files at mode 0600, with no symlinks, special files, or extended ACLs;
  the tree is rechecked after verification. Raw device/profile identifiers remain private local
  evidence and are not anonymous or independently replayable from a clean clone.
  Operator-facing validation failures use labels and truncated identifier digests; raw command
  output remains in the private run tree and must not be uploaded as a shared console transcript.
  `QPERIAPT_DEVELOPER_DIR=/Applications/Xcode-27.0.app/Contents/Developer` selects the only
  code-fixed Xcode 27 release path accepted by this lane, without changing global `xcode-select`.
  Arbitrary CLI or environment-selected paths cannot select toolchain filesystem inputs: proof
  entrypoints reject them before I/O, while shared read-only device inspection always discards
  ambient selectors and invokes the fixed toolchain through an absolute system shim.
  This lane requires local signing. Set
  `DEVELOPMENT_TEAM` and an explicit `QPERIAPT_IOS_DEVICE_ID` for every physical run,
  and complete the selected Xcode first-launch/CoreDevice setup before capture,
  and set `QPERIAPT_ALLOW_PROVISIONING_UPDATES=1` only when automatic profile changes are intended;
  otherwise the lane fails closed rather than falling back to a simulator. By default,
  `artifact/proof-to-byte.sh` does not require local signing hardware; set
  `QPERIAPT_REQUIRE_APPLE_DEVICE=1` on `artifact/proof-to-byte.sh` to require and re-verify the
  single-device proof; stale evidence is rejected after `QPERIAPT_DEVICE_PROOF_MAX_AGE_SECONDS`
  (default: 86400). Release verification fixes this value to 86400 seconds and requires the
  proof's profile policy to demand at least 30 valid days; wider thresholds are diagnostic-only.
  The capture freezes the app executable and Rust static-library hashes before installation,
  strictly verifies the app signature, and rechecks both hashes after the run-bound marker returns
  from the app-private container and again during proof emission. This binds persistent local
  artifacts to the installation window; it is not on-device binary attestation. The capture uses a
  random run-scoped bundle identifier, refuses to replace a pre-existing exact identifier, and
  confirms stable removal of only its own app before proof emission. Install/uninstall unknown
  outcomes are reconciled with bounded repeated observations; an unresolved outcome fails the
  gate. `SIGKILL`, host loss, or device loss cannot run traps: derive the random identifier from
  the printed run id and inspect that exact app before any manual cleanup. Raw local evidence
  uses a private umask and is never part of a publishable package or release index.
  For iPhone+iPad family coverage, use the matrix lane:
  `QPERIAPT_IOS_DEVICE_MATRIX='ipad:<ipad-udid>,iphone:<iphone-udid>' sh artifact/apple-device-matrix.sh`.
  The matrix lane writes one proof per device plus `apple-device-matrix-proof.json`, and
  `QPERIAPT_REQUIRE_APPLE_DEVICE_MATRIX=1 sh artifact/proof-to-byte.sh` verifies that both physical
  families are present, fresh, source-bound, and artifact-bound. Matrix schema v5 requires exactly
  canonical `ipad`/iPad over `wired` and `iphone`/iPhone over `localNetwork`, distinct device
  commitments, run ids, one identical selected Xcode receipt, and schema-v4 child proofs; the
  aggregate schema is v5. The former device-type override has been removed. For beta/GM readiness, prefer
  `artifact/apple-device-xcode27-gate.sh`: with `QPERIAPT_IOS_DEVICE_ID` it captures and directly
  verifies the single-device proof; with `QPERIAPT_IOS_DEVICE_MATRIX` it does the same for the
  iPhone+iPad matrix. The capture deliberately stops with `promotion=pending`: select its path and
  SHA-256 in `artifact/results.json`, then run the matching required domain in
  `artifact/proof-to-byte.sh` for manifest-bound promotion.
  By default, Apple device proof requires a clean tree. Use
  `QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE=1` only to generate local diagnostic proof, and
  `QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE_PROOF=1` only to reverify that diagnostic proof.
- **Android runtime binding smoke.** `sh artifact/android-device-smoke.sh` first rebuilds and audits
  the Android AAR, then creates a temporary debuggable APK that consumes the AAR on ART, installs it
  on an adb device or emulator, and accepts only a run-bound
  `QPERIAPT_ANDROID_DEVICE_PASS run-id=<32 hex chars>` marker copied from the app-private
  files directory. The ABI2 runtime checks cover metadata, exact signed-policy decision/digest,
  OS-random atomic key generation and encapsulation, context-bound roundtrip, ABI1
  legacy-state/rollback/tamper rejection, secret wipe, and boundary fail-closed behavior;
  raw combine/X-Wing/deterministic paths are forbidden exports. The private adb bootstrap listener
  descriptor is bound before the first client operation; Darwin rechecks retain it, while Linux
  rechecks require it to remain the sole `LISTEN` descriptor and admit only exact-socket
  `CONNECTED` descriptors alongside it. Current proof schema v6 records hashed
  adb serial and build fingerprint only, hashes the AAR/APK/result/logcat/named inputs, and freezes
  the claim-ledger canonical source-input digest before the build. It recomputes
  that digest before proof staging, so a source change during the run fails instead of binding old
  binaries to new source. Manifest-bound release verification accepts only an explicitly selected
  canonical run:
  `QPERIAPT_REQUIRE_ANDROID_AAR=1 QPERIAPT_REQUIRE_ANDROID_RUNTIME=1 QPERIAPT_ANDROID_DEVICE_PROOF=target/qperiapt-android-device-smoke-runs/<run-id>/proof/qperiapt-android-device-proof.json sh artifact/proof-to-byte.sh`.
  It requires emulator, arm64-v8a, API 35, 16 KiB pages, release mode, and the exact
  results-selected current AAR. By default the producer requires a clean tree.
  `QPERIAPT_ALLOW_DIRTY_ANDROID_DEVICE=1` can generate a local diagnostic proof, which may be
  inspected only with the direct Android verifier and its explicit dirty opt-in; it can never be
  supplied to manifest-bound `proof-to-byte` or selected as current release evidence. Physical runs require
  both `QPERIAPT_ANDROID_SERIAL=<serial>` and `QPERIAPT_ANDROID_EXPECT_DEVICE_KIND=physical` and are
  separately verified. A clean physical run over the same source and exact AAR is an additional
  production-promotion requirement, never a substitute for the canonical AVD. It records and
  verifies the real device parameters; an API-36/4-KiB physical phone remains valid supplemental
  execution evidence and does not need to imitate the AVD's API-35/16-KiB/release-mode profile.
  Results bind physical evidence independently under `android_physical_runtime`; the bound verifier
  uses `--results-binding android_physical_runtime` internally and emits
  `PROOF_TO_BYTE_ANDROID_PHYSICAL_RUNTIME_PASS`. The physical proof cannot occupy or satisfy the
  canonical `android_device_runtime` section. A current-source physical selection has not been
  captured merely because this verifier path exists.
  CI job `bindings-android-runtime-16k` consumes the exact AAR artifact from
  `bindings-android-aar` and runs it on real x86_64 API-35 `google_apis_ps16k` ART on every push and
  pull request. That is an independent package-face gate; it does not enter the arm64 results
  selector and is not physical-device production evidence.
  To boot the local canonical AVD, set `QPERIAPT_ANDROID_BOOT_AVD=1`,
  `QPERIAPT_ANDROID_ADB_PROFILE=macos-account`,
  `QPERIAPT_ANDROID_EXPECT_DEVICE_KIND=emulator`, and
  `QPERIAPT_ANDROID_EXPECT_ABI=arm64-v8a` on the release host. The AVD name is not caller input:
  the bounded runtime derives `QPeriapt_Release_16K_API_35_V1` from that fixed profile/ABI pair and admits it
  only beneath the private `avd-home` child of the account runtime-state directory. CI likewise
  derives `QPeriapt_Release_16K_API_35_CI_V1` from `linux-system` plus `x86_64`. The default
  `~/.android/avd` fallback root, if it exists, must be current-user-owned, non-symlink, and not
  group/other writable; its existing parent chain must meet the same ownership/writeability boundary,
  and macOS allow ACLs are also rejected. In all cases the derived private name
  must be absent there. The producer never chmods or deletes it, while unrelated historical AVDs may remain.
  The AVD runs with a read-only userdata overlay.
  The smoke refuses to replace an existing package. One 45-second post-install remote-observation
  deadline requires two consecutive path-stable reads whose installed APK bytes match the run
  capability exactly, followed by an exact local signer check. Cleanup uses a separate 45-second
  remote-observation budget shared by its ownership recheck, uninstall request, and repeated absence
  observations; its local signer check is outside that remote-command budget. A single
  typed package query maps an arbitrary nonzero `adb` result or a clean bounded timeout to an
  explicit retryable state; neither state is accepted as absence, and either resets consecutive
  absence observations. Successful empty output alone means absent, the one exact package line
  means present, and malformed output, resource-boundary failure, or command-capability/owned-server
  drift fails immediately. On the script-owned AVD only, a package-query failure followed by an
  exact private device table that omits the receipt-bound serial may consume the same cleanup
  deadline to attempt one authenticated, listener-bound transport registration for the whole run.
  An online, offline, unauthorized, ambiguous, or inconclusive table never triggers registration;
  physical devices never use this recovery path. Recovery proves neither package absence nor
  ownership and must return to the package query before any cleanup decision. It neither overwrites
  the initial registration evidence nor extends the cleanup deadline. Path, pull, or byte observation
  failures likewise reset ownership
  convergence instead of weakening the identity check. Cleanup uninstalls only after its recheck
  passes, reconciles command-unknown outcomes with repeated absence observations, and never clears
  global logcat buffers. One sanitized append-only journal records phase, cleanup invocation, attempt,
  typed state, and consecutive count without raw device output; recurring cleanup cannot truncate an
  earlier phase. On CI failure, only that journal is uploaded for diagnosis. Raw command and uninstall
  output remains in the private run tree, and a failed lane still publishes no runtime proof. It requires
  the current account's non-symlink home that is not writable by group or other users, an owner-controlled non-symlink adb
  identity directory that is not group/other writable, owner-protected adb key files, and an already
  authorized target. macOS deny-only ACLs may restrict those nodes further, but any allow ACL is
  rejected. The standard IPv4 and IPv6 adb endpoints must refuse connections at startup and at the
  source-bound runtime checkpoints; the script never reuses or stops a pre-existing default server.
  It instead owns one fixed `adb.sock` in a random, mode-0700,
  allow-ACL-free `/tmp/qperiapt-adb.<8 chars>/` directory and routes every client through its exact
  `localfilesystem:` endpoint. The server disables mDNS and auto-connect. Physical proof enables
  only USB scanning, binds `--one-device` to the explicit serial, and rechecks a `usb:` devpath before
  staging; the owned AVD lane disables USB and automatic emulator scanning. Immediately after
  spawning the owned server, all parent/client scanners remain disabled so a client-autostarted
  replacement cannot attach to a device. Listener PID/start identity, executable, key, endpoint,
  transport environment, and `mdns_enabled: false` status are checked before selection and again
  after the last device query. The AVD lane disables both automatic scanners; after binding the exact
  child PID to its fixed console/adb listener pair, it explicitly registers `emu:<console>,<adb>`
  through the private socket and rechecks both identities before selection or shutdown. The emulator
  uses `-no-direct-adb` only together with `-adb-path` fixed to the run-owned adb snapshot. Its external
  adb child's exact ADB-routing projection is fixed to the private Unix-socket client settings, while
  launcher-added non-routing variables remain outside that commitment and the native emulator
  notifier is redirected away from 5037 to fixed closed loopback port 5586, above the automatic
  transport range ending at 5585. Four mode-0600, no-replace checkpoint receipts record IPv4 and IPv6
  `ECONNREFUSED` for both 5037 and 5586 at emulator pre-exec, post-registration, runtime pre-cleanup,
  and post-cleanup. Runtime proof schema v6 and evidence bundle schema v2 carry the fixed checkpoint
  bytes plus a raw-value-omitting, source-bound `emulator_control` admission receipt binding the
  run-owned external-adb digest/routing environment, native-notifier policy, backend digest/identity,
  fixed ports, listener and registration response digests, and private-adb identity/status digests.
  Raw HOME/key/socket/UID/PID/serial values are excluded from the public proof and bundle. This is local
  control-plane evidence, not independent hostile-builder attestation.
  Cleanup, private-server protocol shutdown, and socket removal must all succeed before the proof is
  published inside the run's append-only
  `target/qperiapt-android-device-smoke-runs/<32-hex-run-id>/` tree; cleanup failure produces no PASS
  marker or accepted proof, and never modifies a proof selected by an earlier results manifest. A
  stable, account-private host/account-scoped open-file lock serializes every checkout before the
  unique run root is created. Before the private adb server can release that lock, a durable
  whole-runtime receipt binds the originating run, adb snapshot, private endpoint, server identity,
  and (for the AVD lane) emulator identity. Long-lived children retain the registered lock descriptor
  with close-on-exec set; the kernel closes it only when their fixed exec succeeds, so the next lane
  can validate and recover an interrupted runtime. Capability creation defers
  HUP/INT/TERM until its owned 0600 state is either armed or removed. The script never sends
  TERM/KILL to a cached PID.
  The private socket directory starts at mode 0700 and is durably reconciled through the receipt's
  schema-v5 phases to `ADB_SEALED` plus an actual mode of 0500 before any adb client is admitted;
  an interrupted seal is completed before recovery uses the endpoint. Schema-v4 runtime receipts
  are intentionally rejected rather than guessed or migrated. Normal success requires an accepted
  authenticated emulator-console shutdown request (for an AVD), an accepted private-adb protocol
  shutdown request, and zero exit status from both owned children. Crash recovery may finalize an
  exact identity already proven absent, but it cannot turn that offline cleanup into a PASS for the
  interrupted run. The console token is never written to the receipt or proof; only its file
  identity and digest are retained for strict revalidation. Console replies are parsed as fixed,
  line-delimited terminal frames. The authentication grammar includes the console's complete fixed
  pre-authentication guidance, the exact current-account token path, both authentication acknowledgements,
  and a command-specific terminal frame. Receipt of that exact terminal frame completes the command
  without waiting for socket EOF, and bytes after that delimiter are not interpreted as part of the frame.
  Every adb/lsof call is selected from a finite Android operation table and executed through the
  private run capability; the generic bounded-process module has no arbitrary command or output CLI.
  Capability creation consumes the selected SDK adb from one already-open descriptor while hashing
  and copying it into a fixed run-owned mode-0500 executable under the private work directory. Every
  subsequent command, server exec, listener check, and server-status identity check uses that snapshot,
  so an ordinary SDK path replacement after capability creation cannot change the executable selected
  by the run. adb itself is selected from the fixed `auto`, `macos-account`, `linux-account`,
  `linux-system`, or `linux-opt` profiles (`QPERIAPT_ANDROID_ADB_PROFILE`); arbitrary `QPERIAPT_ADB`
  paths are rejected.
  AVD transport still requires an exclusive trusted evidence host because another locally started
  listener could appear between the fixed 5037/5586 probes or reach an emulator port. The checkpoint
  receipts prove only that each exact loopback connect attempt was refused; they are not packet-level
  proof that the emulator never attempted a connection between checkpoints. The private snapshot is
  Level-1 reliability hardening, not a
  hostile same-UID isolation boundary; that stronger threat model requires a separate account or
  isolated runner with a read-only checkout. New authorization prompts are outside the gate. If
  `SIGKILL` or host loss prevents traps, the next lane first acquires the account-scoped lock and
  consumes the receipt: on the same boot it revalidates the exact process/listener identities and
  uses an authenticated emulator-console protocol that is independent of the private adb server,
  followed by the private-adb protocol when that server is still live; after a confirmed reboot it
  performs offline cleanup only. Unsafe receipt/filesystem/listener/path mismatches are preserved and
  rejected for explicit operator review. A PID/start-token mismatch is treated as the exact owned
  process being absent and is never signalled. Device loss can still
  leave app removal unresolved; compare any orphaned `dev.qperiapt.androidsmoke` with the private run
  APK before manual removal. This recovery does not replace the exclusive-host requirement or
  continuously reserve the probed loopback ports between checkpoints.
  The fixed emulator argv does not enable gRPC. Listener evidence binds the required console/adb
  pair; it is not a claim that the emulator process has no other TCP listeners.
- **Profile and implementation performance gate.** Collect one paired host proof with:

  ```sh
  sh artifact/python-run.sh artifact/performance_gate.py collect --root . \
    --raw target/performance/paired-profile.jsonl \
    --proof target/performance/paired-profile-proof.json
  ```

  Raw schema v5 carries two separately named estimands in one process. `profile_non_regression`
  preserves the matched ContextBound/CompatXWing comparison over the same ML-KEM-768 seed-dk +
  X25519 backend, keys, coins, deterministic ciphertext corpus, and ABBA/BAAB schedule. Its strict
  nested `profile_inputs` records the fixed suite/version/application context for ContextBound and
  canonical absence (`[]`, `0`, `[]`) for CompatXWing. `implementation_improvement` is a
  separate ContextBound `hybrid_core` native/portable comparison over an
  `expanded_fips203_2400` key and the same coins, corpus, suite, version, and context.
  It covers encapsulation and decapsulation only; `includes_ffi=false` and
  `includes_os_rng=false`, so it is not a C-ABI, policy, entropy, rustls, or complete-product
  measurement. The portable implementation is a symbol-renamed static
  archive compiled only for this evidence build; it is not a product backend, Cargo feature,
  runtime override, or shipping API. The harness generates one expanded keypair, supplies
  the same key bytes/coins/corpus to both implementations, and checks every per-case
  encapsulation/decapsulation output for byte equality before timing; portable key generation
  is neither invoked nor compared. It then uses ABBA/BAAB ordering for both estimands.
  Native and portable C compile under the same
  O3/PIC/macOS-11/function-and-data-section contract with per-implementation
  `-march` pins (native `armv8.4-a+sha3`, portable reference `armv8-a`); the Rust harness is O3 with thin LTO
  and one codegen unit under the stable Rust/Cargo 1.96.1 producer. The 5 s warm-up and 20,480
  samples apply per variant/operation. Budget schema v10 records that exact collection size separately
  from its statistical minimum, and the collection CLI cannot override either samples
  or warm-up. Unrounded batch totals use 256/1/2 calls for
  combine/encapsulate/decapsulate, and analysis divides by the authenticated iteration count.

  Budget schema v10 preregisters the implementation-improvement primary one-sided 95% upper
  limits before any formal collection: native/portable p50 and p95 must be at most 0.95 and p99
  at most 1.0 for both registered ContextBound hybrid-core operations. The verifier rejects threshold drift and
  blocks any failure. This implemented gate is not itself a performance result: do not report a
  quantitative improvement until a fresh clean-source, controlled-host proof-schema-v8 run meets
  the full sample budget and is selected by `artifact/results.json`.

  Paired primary percentile/bootstrap estimates use consecutive 1,024-pair blocks; nearest-rank p99
  therefore has 11 tail observations in each estimate block rather than three. Budget schema v10
  preserves the profile statistical contract: it pins a minimum of 10 and also recomputes the former
  256-pair estimator as a regression guard;
  every published ratio/delta limit must pass at both block scales. Separately parameterized
  stability windows use 64/256/256 pairs for
  combine/encapsulate/decapsulate. Every statistical block contains whole
  ABBA cycles and a balanced multiple of the 64-case corpus. The 5% block-median CV threshold is
  unchanged. The profile and implementation upper bounds are per-metric one-sided 95% bootstrap bounds, not a
  joint 95% family guarantee; span-5 coverage under autocorrelation has not been independently
  calibrated. The verifier
  rejects malformed/missing pairs, iteration or schema drift, invalid totals, unstable block
  medians, source/binary/budget drift, stale evidence, any uncontrolled pre-build/pre-run/post-run/
  post-analysis thermal or power observation, or any
  published ratio/absolute-delta budget failure. The verifier fixes policy to
  `artifact/performance-budgets.json`; alternate paths fail even when their bytes happen to match.
  That policy also fixes the rustup toolchain and host target plus the Cargo, Rustc,
  Xcode Clang, and Xcode `ar` executable paths and hashes, plus the canonical macOS SDK path,
  version, and settings digest (and version output where available). Collection selects those fixed tools before executing them,
  rejects repository/ancestor/user Cargo configuration, clears caller compiler/wrapper/loader controls, fixes system
  tool lookup, builds offline in a fresh private target, and rechecks those four executables. The
  user-writable Cargo registry cache, Rust sysroot/driver, OS tools/libraries, and same-UID
  replace-and-restore races remain trusted. The verifier also trusts the local collector to have
  built the content-addressed binary it records; it does not independently rebuild it. Therefore
  this is a strengthened single-host diagnostic, not hermetic or hostile-builder attestation.
  Proof schema v8, raw schema v5, and budget schema v10 are required; older files
  fail closed and must be recollected. Shared CI runs only a short schema exercise; numeric
  decisions require controlled hardware. Reverify with
  `QPERIAPT_REQUIRE_PERFORMANCE=1 sh artifact/proof-to-byte.sh`. Dirty diagnostic collection and
  verification require the explicit `--allow-dirty` and
  `QPERIAPT_ALLOW_DIRTY_PERFORMANCE_PROOF=1` opt-ins and never qualify for release attestation.
  Process-level CPU and compositor energy are outside the authenticated performance schema. Before
  collection, observe the host without changing repository inputs; if WindowServer, MenuBarAgent,
  or another persistent process is continuously busy, defer the run. Do not kill WindowServer,
  lower budgets, or automate restart-and-retry loops until a favorable sample appears. A future
  device/host energy claim requires a separate calibrated energy lane with explicit hardware,
  duration, power, thermal, and selection-bias controls.
- **Footprint (platform-dependent).** `sh paper/footprint.sh` writes `paper/footprint.csv` for the
  host it runs on (cdylib + WASM module sizes). The committed rows are a
  Darwin 27.0.0 arm64 local capture with Rust 1.96.1 (the same patch release the
  Apple r1 and r2 Android/Linux packages pin; the r2 Windows package pins 1.97.0),
  `wasm-pack` 0.15.0, and
  Homebrew LLVM Clang 22.1.8: 667.8 KiB stripped C ABI, 97.7 KiB lean WASM, and
  332.3 KiB signed-policy WASM. They are platform/toolchain-specific local diagnostics,
  not signed provenance, a cross-platform binary-size claim, or a description of any
  published release binary.
