# Prebuilt policy maintenance package qualification

Builder: `2e5e01e0fa70e66d3b27432acab4c28a6d22ced2`.
Qualified Rust archive source: `de2c49e9e572972165a05411d2a11777f06e31b2`.
These are deliberately separate identities: unchanged crate bytes were reused
while the native package producer and archive contract were added.

The [user entrypoint](../../../../docs/POLICY_MAINTENANCE.md) is a standalone
archive containing `bin/qperiapt`, instructions and notices. Rust, C and Swift
applications use the same offline maintenance command. Its dependencies remain
outside the ordinary SDK runtime closure. The producer reuses the canonical
Rust archive validators, lock identities, release profile, license collector,
deterministic archive implementation and installed migration scenarios.

## Observed results

- The complete artifact discovery suite passed **2,657 tests**, with no skips,
  on the clean and unchanged builder source.
- The macOS arm64 package built offline from exact cohort archives outside the
  checkout. It includes 80 third-party license records and the Rust/mlkem-native
  notices. Its native binary reports version 0.2.0 and declares macOS 13.0 in its
  Mach-O deployment metadata.
- The package was archived, hash-checked, extracted, inventoried and executed.
  All seven installed scenarios passed.
- A second installation used `/usr/bin/tar` independently of the Python archive
  reader. It passed the same seven scenarios, and the binary and complete
  manifested payload remained unchanged.

The seven scenarios are original-format conversion, current-format retry,
oversized independent state, missing-store refusal, corruption of each of the
two transaction slots, and final current-format retry. Existing feature tests
separately cover authenticated inputs, process cuts and typed I/O failures; these
seven scenarios do not establish those other properties by themselves.

Package:
`q-periapt-policy-maintenance-0.2.0-aarch64-apple-darwin.tar.gz`, 1,211,410 bytes.

| Object | SHA-256 |
| --- | --- |
| Archive | `a80fe1900dcd1ae926250ec99aaafa2f4d25b4010bee4fcfe20fffa6e263d929` |
| Manifest | `5f97167c2facfb883bd779aab92a23cb2b691106f07a3e22d464291573dc36be` |
| Executable | `b5f34977117502142b7375875fb436feb1ee0803d2291517db406a2f719c6d50` |

The actual package and separately installed binary remain at the local paths in
`QUALIFICATION.json`. `CAPTURES.zip` retains source-pinned run records, logs,
manifest, license inventory, installation results and the failed initial run.
Its internal `MEMBERS.json` covers every other member by length and SHA-256.

## Executable-mode regression

The initial producer at `6d671ba6` correctly stopped after extraction: the shared
archive dialect canonicalized every ordinary file to mode `0644`, including the
CLI binary. The manifest expected `0755`; that mismatch was not ignored.

Tar creation, audit and extraction now accept an explicit immutable set of exact
archive paths requiring `0755`. The maintenance package authorizes only its
`bin/qperiapt`. Unlisted regular files retain `0644`; omitted, unexpected,
directory or noncanonical executable paths are refused. Default library archives
and ZIP behavior remain unchanged. The regression checks deterministic output,
permission-policy mismatches, refusal before extraction, and actual execution
of a POSIX test program after unpacking. The retained real old/new archives show
the CLI mode changing from `0644` to `0755`.

## CI and remaining limits

CI now defines native maintenance package jobs on Ubuntu 22.04 x86_64, Ubuntu
22.04 arm64 and macOS 15 arm64, consuming the same-run Rust archive cohort. The
jobs bind the selected Git commit and native target, use a fresh credential-free
Cargo cache and retain the native artifact plus qualification records. They have
not run for this builder at recording time: the next push awaits completion and
retention of Rust CodeQL job `113272915154`.

Actionlint 1.7.12 returned the same two existing `ubuntu-26.04` label diagnostics
on the baseline and this workflow, with no new diagnostics. That label is listed
in the [official runner table](https://docs.github.com/en/actions/reference/runners/github-hosted-runners),
and the retained GitHub job responses show successful runs using it. No linter
suppression or runner downgrade was introduced.

This is local macOS arm64 package qualification. Native Linux package execution,
macOS signing/notarization, minimum-OS execution and the full SDK/Continuity
security and release gates remain open. The archive is a candidate; no public
release, registry upload, merge, Intel Mac support, Continuity migration or
power-loss recovery claim is established.
