# Security Policy

## Supported releases

Q-Periapt is currently an alpha prerelease. Security fixes are provided for the
latest ABI 2 publication set while it remains current:

| Publication | Scope | Supported |
| --- | --- | --- |
| `v0.1.0-alpha.2-r1` | Apple XCFramework | Yes |
| `abi2-platforms-v0.1.0-alpha.2-r2` | Android, GNU/Linux, unsigned experimental Windows | Yes |
| `v0.1.0-alpha.2` and older publications | Superseded artifacts | No |

The Windows r2 archive is intentionally an unsigned experimental prerelease. A
GitHub attestation and published SHA-256 digests establish provenance and byte
integrity, but they do not provide Authenticode publisher identity or SmartScreen
reputation.

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
