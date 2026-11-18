# Security Policy

## Supported releases

Security fixes follow the latest verified ABI 2 publication, currently
**0.2.0**. Use the [installation guide](docs/SDK_GETTING_STARTED.md) to choose a
package and the [verified release record](https://github.com/billlza/q-periapt/tree/v0.2.0-verified-cohort/release/0.2.0) for its scope. The 0.2.0
SDK wrappers require the matching 51-export library. Report vulnerabilities in
release and preview builds through the same private channel described below.

| Publication | Scope | Supported |
| --- | --- | --- |
| [`v0.2.0`](https://github.com/billlza/q-periapt/releases/tag/v0.2.0), [`abi2-platforms-v0.2.0`](https://github.com/billlza/q-periapt/releases/tag/abi2-platforms-v0.2.0) and the [0.2.0 Rust SDK](https://crates.io/crates/q-periapt-sdk/0.2.0) | Current SDK assets and twelve crates.io packages | Yes, within the published scope |
| `v0.1.5`, `abi2-platforms-v0.1.5` | Previous ABI 2 cohort. [Historical verification](https://github.com/billlza/q-periapt/tree/v0.1.5-verified-cohort) | Superseded by 0.2.0 |
| `v0.1.4`, `abi2-platforms-v0.1.4` | Published 2026-08-30; immutable history recorded at `v0.1.4-verified-cohort`. Superseded by the verified 0.1.5 cohort; downstream builds should upgrade | No |
| `v0.1.3`, `abi2-platforms-v0.1.3` | Published 2026-08-25: immutable GitHub releases (Apple XCFramework; Android and GNU/Linux), plus the ten `0.1.3` crates on crates.io. Superseded by the published 0.1.4 set; its frozen verified receipts remain the recorded selection in `main`'s trusted results | No |
| `v0.1.2`, `abi2-platforms-v0.1.2` | Tagged on 2026-08-23 but never published: the tag-triggered platform release run built a candidate that verified and produced the platform assembly plus both pending receipts, but the first end-to-end coordinated GitHub-release publication run against real GitHub could not finalize because of several first-real-publish defects in the stable release publication and observation paths (since fixed on this source line); no GitHub release, crates.io publication, or signed Apple distribution exists for 0.1.2; superseded by the published 0.1.3 releases | No |
| `v0.1.1`, `abi2-platforms-v0.1.1` | Tagged on 2026-08-22 but never published: the tag-triggered platform release run built a candidate that verified, but the coordinated GitHub-release publication could not finalize because of a publication receipt IO staging bug (since fixed on this source line); no GitHub release, crates.io publication, or signed Apple distribution exists for 0.1.1; superseded by the 0.1.2 tags | No |
| `v0.1.0`, `abi2-platforms-v0.1.0` | Tagged on 2026-08-21 but never published: no GitHub release, crates.io publication, or signed Apple distribution exists for 0.1.0; superseded by the 0.1.1 tags | No |
| Historical Windows x64 CI diagnostics | Development builds from earlier releases | No |
| `v0.1.0-alpha.2-r1`, `abi2-platforms-v0.1.0-alpha.2-r2` | Published prerelease predecessors, superseded by the verified 0.1.3 stable receipts | No |
| Older publications | Superseded historical artifacts | No |

Under the historical 0.1.5 profile, the Windows diagnostic is unsigned and is excluded
from the stable candidate for that release. Version 0.2.0 distributes the
[Windows x64 MSVC archive](https://github.com/billlza/q-periapt/releases/download/abi2-platforms-v0.2.0/q-periapt-c-abi2-0.2.0-x86_64-pc-windows-msvc.zip) on GitHub. A checksum verifies the bytes.
A GitHub release attestation does not establish Windows publisher identity or
SmartScreen reputation.

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
