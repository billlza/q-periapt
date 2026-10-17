# Rustls 0.23.46 security update

Source `c2fe036ecd2dcf79d9608171dd772d029499d6a9` replaces rustls 0.23.45
with 0.23.46 in the workspace and isolated Continuity lockfiles. Five direct
manifest requirements also exclude the affected older release. Both lockfile
diffs change only the rustls version and checksum; unrelated dependencies and
frozen external comparison lockfiles remain unchanged.

The [upstream release](https://github.com/rustls/rustls/releases/tag/v%2F0.23.46)
was published on 2026-10-14. The preceding source f09e8cf0 failed both
[dependency audit](https://github.com/billlza/q-periapt/actions/runs/38577906591/job/115899772027)
and [Rust package verification](https://github.com/billlza/q-periapt/actions/runs/38577906591/job/115899771760)
on four advisories from the same RustSec database commit
`caee11f41fab07d676c0a4655a2a5dd1f94da97c`. The failed package artifact is
retained with its GitHub-provided SHA-256 and original audit JSON. No advisory,
warning or test is ignored.

| Advisory | Upstream issue |
| --- | --- |
| RUSTSEC-2026-0346 / [GHSA-c8m5-c952-6cm4](https://github.com/rustls/rustls/security/advisories/GHSA-c8m5-c952-6cm4) | Debug formatting of client session values can expose key material |
| RUSTSEC-2026-0347 / [GHSA-vp88-798v-h67f](https://github.com/rustls/rustls/security/advisories/GHSA-vp88-798v-h67f) | Buffered application data can be sent after ECH rejection |
| RUSTSEC-2026-0348 / [GHSA-h2v8-394m-p7vv](https://github.com/rustls/rustls/security/advisories/GHSA-h2v8-394m-p7vv) | Enabled Brotli certificate decoding can allocate excessive memory |
| RUSTSEC-2026-0349 / [GHSA-w44r-93j7-qv28](https://github.com/rustls/rustls/security/advisories/GHSA-w44r-93j7-qv28) | Unauthenticated ServerHello can influence later key-exchange hints |

The standard product factory already disables resumption and early data, permits
one hybrid group, and configures neither ECH nor a custom session-value logger.
The selected manifest features do not enable Brotli. These are specific exposure
boundaries, not a claim that all downstream rustls use is unaffected. Updating the
dependency also protects consumers using its wider configuration interface.

Local validation uses the patched source and real cryptography: 31 native Rustls
tests, 16 witness TLS tests, a separate TLS 1.2 additive-feature run with 21 tests,
strict all-target Clippy, and Rust 1.90 checking. Eight independent OpenSSL 3.6.4
cases cover both accepted directions and wrong-name, missing-client-certificate,
classical-only and TLS 1.2 refusal as applicable. Actual CLI output matches every
configured algorithm choice in the retained native CBOM fixture. These tests do
not replace upstream vulnerability proofs or qualification of every platform.

The clean-source Rust package producer generated twelve 0.2.0 crate archives.
A separate consumer used exact archive-derived package sources outside the
checkout and passed four tests: controlled key ownership/revocation, signed policy
transition, mutual-identity reference connection with fragmented I/O, and durable
store restart/rollback rejection. Its Clippy run passed. The resolved consumer
lock contains rustls 0.23.46. Workspace, fuzz and consumer audits report zero
vulnerabilities and zero warnings against the same advisory database as the failed
CI run. The package report retains `git_dirty: false`, `diagnostic_only: false`,
`sources_unchanged: true`, and `release_claim_eligible: false`; no registry upload
was performed.

Unsuccessful local attempts are preserved: dependency update initially used an
offline build environment before the new crate was fetched; the fixed-path audit
tool was initially absent; package attempt 01 correctly rejected staged source;
attempt 02 found no cargo-audit on the isolated PATH. An existing owned
cargo-audit 0.22.2 executable was copied to the local tool directory and added only
to the package process PATH. No global installation, dirty-source override or
weakened gate was used. Attempt 03 completed against the clean commit.

`CAPTURE.zip` binds command receipts, public interoperability logs, source inputs,
failed CI evidence, twelve crate archives and the full package/consumer report.
Fresh private test credentials, private databases, Cargo caches and credentials
are excluded. Earlier 0.23.45 device and performance results retain their original
scope; current platform/package CI and targeted device refresh remain separate
release requirements. CodeQL's existing SummaryStats timeout is not fixed by this
dependency checkpoint. Evidence-only follow-up commits must match all recorded
package source inputs and pass their own exact-commit source gate.
