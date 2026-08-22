# Security Policy

## Supported releases

Q-Periapt 0.1.1 is the stable SemVer source line. Security fixes are provided for
the latest ABI 2 publication set only while its verified receipt selects it as
current:

| Publication | Scope | Supported |
| --- | --- | --- |
| `0.1.1` source line | Rust source/crates and ABI 2 contract | Yes |
| `v0.1.1` | Apple XCFramework | When selected by a verified current receipt |
| `abi2-platforms-v0.1.1` | Android and GNU/Linux | When selected by a verified current receipt |
| `v0.1.0`, `abi2-platforms-v0.1.0` | Tagged on 2026-08-21 but never published: no GitHub release, crates.io publication, or signed Apple distribution exists for 0.1.0; superseded by the 0.1.1 tags | No |
| Unsigned Windows x64 diagnostic | CI-only, unsupported, not a stable release asset | No |
| `v0.1.0-alpha.2-r1`, `abi2-platforms-v0.1.0-alpha.2-r2` | Published predecessors | Until superseded by the corresponding verified stable receipts |
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
