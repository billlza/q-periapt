# Current SDK source: clean local archive producer

The SDK 0.2 producer completed successfully on macOS arm64 at source
`5678d1019861fa1b04f3a219ba3fde7e0ddaaba8`, finishing at
2026-11-05 20:03:08 UTC. It produces the current SDK workspace identity
`c064df108a07da40099f9c2fe8115577d54f421fea918a0fefb1810d76a42c4d`.
This supplies a matching local producer for later candidate consumers; it does
not publish packages or close Continuity's product ABI, platform, proof,
external-review or release gates.

The command was the existing
`sh artifact/rust-publish-contract.sh --profile sdk-020 --output target/sdk-020`,
with Rust/Cargo 1.98.1 and the existing scoped cargo-audit 0.22.2 executable.
The repository's isolated Python dispatcher was used. Original 900-second
component limits were retained, with no shorter outer supervisor deadline.
The direct command returned zero and its stderr was empty.

The main checkout's strict source preflight refused existing Python bytecode
caches and 23 untracked source inputs. These were preserved, including the
untracked witness-census directory. A new full local clone checked out the exact
commit with a real `.git` directory; the producer's normal before/after checks
confirmed clean, unchanged source. The dirty diagnostic option was not used.

## Actual package and consumer checks

All twelve SDK cohort archives were built and validated, totalling 5,765,394
bytes. The external Rust consumer reconstructs nine exact archive-derived
packages outside the checkout and passes its four public API tests. Its actual
package trees were checked again after completion against the archive bytes.
This is an installed archive-derived consumer, not a public-registry installation
or an independent implementation of the protocol.

Strict all-target consumer Clippy passed with warnings denied. Workspace, fuzz
and consumer dependency audits used the same RustSec database commit:
`26fd2d43f7280a1fb925a3743ec463017afe7119`.

| Audited lock | Packages | Reported vulnerabilities | Reported warnings |
| --- | ---: | ---: | ---: |
| Workspace | 290 | 0 | 0 |
| Fuzz | 51 | 0 | 0 |
| External consumer | 112 | 0 | 0 |

These are the recorded audit results for those locks and that database, not a
claim that no vulnerability exists. The external consumer resolves 102 external
packages. Locked dependencies, vendor checks, normalized manifests and source
member verification retain the original producer's strict checks.

The final [SDK report](RUST_SDK_PACKAGE.json) has SHA-256
`1e40fc2ae0c7c113509ae2a5c5a858cbd73a8a6fd7f63e66203316c4c61e228d`.
It records `git_dirty=false`, `diagnostic_only=false`, `sources_unchanged=true`,
`publication_performed=false` and `release_claim_eligible=false`.
The before/after source inventories and a fresh source readback agree. All
twelve archives were reread with exact lengths, hashes and member inventories.

The new producer is distinct from the earlier `75bbe6…` hosted JNI SDK inputs.
Candidate C/JNI/WASM packages and affected runtime evidence still need to be
bound to their applicable current inputs. The existing six-partition hosted
wave, final source qualification, formal review and publication remain open.

## Retained evidence

`CAPTURE.zip` includes all twelve actual archives, producer reports and command
streams, consumer lock/audit evidence, the clean-clone receipts, source/dispatcher
inputs and independent readback. The caller-owned temporary consumer and build
caches are not exported. The live clean source and producer outputs remain
available for follow-up consumers.

All 133 captured members were reread against `FILES.json`: 6,030,180 bytes,
SHA-256 `2fac380b3ba4a24c9d96d52166c0bcc152dff37c1f9658d287cc0498b8aa9bd5`.
`READBACK.json` binds the source, twelve archives, nine external package trees,
four consumer tests, successful command receipts and audit identities.
No dependency version, global installation, source gate, timeout or release
authorization was changed to obtain this result.
