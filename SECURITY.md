# Security Policy

## Supported releases

Q-Periapt 0.1.5 is the stable SemVer source line, succeeding the fully published
0.1.4 release. Security fixes are provided for
the latest ABI 2 publication set only while its verified receipt selects it as
current:

| Publication | Scope | Supported |
| --- | --- | --- |
| `0.1.5` source line | Rust source/crates and ABI 2 contract | Yes |
| `v0.1.5` | Apple XCFramework | When selected by a verified current receipt |
| `abi2-platforms-v0.1.5` | Android and GNU/Linux | When selected by a verified current receipt |
| `v0.1.4`, `abi2-platforms-v0.1.4` | Published 2026-08-30: immutable GitHub releases (Apple XCFramework; Android and GNU/Linux), plus the ten `0.1.4` crates on crates.io. **This is the current published stable set.** Its verified cohort is recorded at the annotated tag [`v0.1.4-verified-cohort`](https://github.com/billlza/q-periapt/tree/v0.1.4-verified-cohort) rather than on `main`: reopening the source line for 0.1.5 returns `artifact/results.json` to its initial baseline, and the finalizer's release proof requires a results-only descendant of the 0.1.4 release commit, which `main`'s tip is not. The published GitHub and crates.io records are immutable and unaffected by that; `main`'s trusted results therefore still carry `apple_v0_1_3` as the active selector | Until superseded by the verified 0.1.5 receipts |
| `v0.1.3`, `abi2-platforms-v0.1.3` | Published 2026-08-25: immutable GitHub releases (Apple XCFramework; Android and GNU/Linux), plus the ten `0.1.3` crates on crates.io. Superseded by the published 0.1.4 set; its frozen verified receipts remain the recorded selection in `main`'s trusted results | No |
| `v0.1.2`, `abi2-platforms-v0.1.2` | Tagged on 2026-08-23 but never published: the tag-triggered platform release run built a candidate that verified and produced the platform assembly plus both pending receipts, but the first end-to-end coordinated GitHub-release publication run against real GitHub could not finalize because of several first-real-publish defects in the stable release publication and observation paths (since fixed on this source line); no GitHub release, crates.io publication, or signed Apple distribution exists for 0.1.2; superseded by the published 0.1.3 releases | No |
| `v0.1.1`, `abi2-platforms-v0.1.1` | Tagged on 2026-08-22 but never published: the tag-triggered platform release run built a candidate that verified, but the coordinated GitHub-release publication could not finalize because of a publication receipt IO staging bug (since fixed on this source line); no GitHub release, crates.io publication, or signed Apple distribution exists for 0.1.1; superseded by the 0.1.2 tags | No |
| `v0.1.0`, `abi2-platforms-v0.1.0` | Tagged on 2026-08-21 but never published: no GitHub release, crates.io publication, or signed Apple distribution exists for 0.1.0; superseded by the 0.1.1 tags | No |
| Unsigned Windows x64 diagnostic | CI-only, unsupported, not a stable release asset | No |
| `v0.1.0-alpha.2-r1`, `abi2-platforms-v0.1.0-alpha.2-r2` | Published prerelease predecessors, superseded by the verified 0.1.3 stable receipts | No |
| Older publications | Superseded historical artifacts | No |

The Windows package remains useful for CI diagnostics, but it is unsigned and is
excluded from the stable candidate, manifest, release assets, attestation, and
receipt. Supporting it requires a real Authenticode producer/verifier plus
certificate and timestamp-authority gates; SHA-256 or a GitHub build attestation
alone does not establish Windows publisher identity or SmartScreen reputation.

## Reporting a vulnerability

Use GitHub's **Report a vulnerability** form in the repository Security tab. Do
not open a public issue for a suspected vulnerability.

Please include:

- the exact release tag, artifact digest, platform, and architecture;
- a minimal reproduction or proof of concept;
- the expected and observed security boundary;
- the likely confidentiality, integrity, or availability impact; and
- any known mitigation, without including credentials or unrelated personal data.

The maintainer targets an initial acknowledgement within five business days and
a triage update within ten business days. Remediation and coordinated disclosure
timing depend on severity, exploitability, and whether upstream cryptographic or
platform dependencies are involved. Reports remain private until a coordinated
disclosure date or a published fix is available.

This project does not currently operate a bug-bounty program.
