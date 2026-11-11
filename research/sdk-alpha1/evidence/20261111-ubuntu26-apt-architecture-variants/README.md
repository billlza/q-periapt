# Ubuntu 26 APT architecture-variant repair

Four Ubuntu 26 jobs in [SDK CI run 43059460473](https://github.com/billlza/q-periapt/actions/runs/43059460473), source `2f42d2ce913421f9b7a7df39fbc56845d55717de`, fetched and accepted their Ubuntu mirror indexes, then stopped when the package solver proposed downgrades. The noninteractive downgrade protection rejected each transaction with exit code 100.

The isolated helper generated `arch=amd64` from `dpkg --print-architecture`. That explicit source setting replaces APT's default architecture selection, excluding configured architecture variants such as `amd64v3`. The repair removes that source filter and retains the native architecture solely for mirror selection.

## Frozen failures

| Job | Requested packages | Proposed downgrades |
| --- | --- | ---: |
| ProVerif, 130657939476 | libgtk2.0-dev, ocaml, pkg-config | 61 |
| RISC-V cross, 130657939332 | qemu-user, gcc-riscv64-linux-gnu | 16 |
| Tamarin, 130657939191 | graphviz, unzip | 1: unzip |
| AVX2, 130657939157 | valgrind | 2: libc-bin, libc6-i386 |

All four jobs report `ubuntu-26.04`, image `20261101.186.1`. Each helper identifies its native architecture as `amd64`; its complete update log downloads 13 package indexes, all for `amd64`. Every update reaches the install solver. The error is the explicit downgrade refusal, rather than the earlier Ubuntu DNS outage.

The four complete original logs under `logs/` retain their BOM and terminal escape sequences. Their Git blob identities were recomputed from the saved bytes and match the supplied public blobs. `FAILURE_ANALYSIS.json` records exact source and job identities, byte/hash bindings, requested packages, complete proposed downgrade lists and original APT line ranges. The jobs do not include a full `apt-config` or installed-package dump; the separate Ubuntu 26 hosted validation captures the actual runner variant configuration and the corrected installation plan.

## Mechanism and source repair

Ubuntu's [26.04 release notes](https://documentation.ubuntu.com/release-notes/26.04/summary-for-lts-users/#architecture-variants-and-amd64v3) describe `amd64v3` selection through `APT::Architecture-Variants`; the same release notes describe AMD64v3-based 26.04 cloud images. A full original HTML readback, UTC timestamps, HTTP status and digest are retained under `primary/`.

Ubuntu’s [supported-architectures documentation](https://documentation.ubuntu.com/project/how-ubuntu-is-made/concepts/supported-architectures/#architecture-variants) explains the variant policy. The [Resolute sources.list manual](https://manpages.ubuntu.com/manpages/resolute/man5/sources.list.5.html), provided by apt 3.2.1ubuntu0.1, specifies that an explicit `arch` option replaces the default architecture set. Original HTML and retrieval receipts for both are also retained.

The [Ubuntu apt 3.2.1ubuntu0.1 source package](https://archive.ubuntu.com/ubuntu/pool/main/a/apt/apt_3.2.1ubuntu0.1.dsc) confirms the mechanism for the package version named by the Resolute manual. Its 2,477,440-byte source archive matches the SHA-256 and byte count in the official DSC. The original DSC, two source members, and retrieval/checksum receipt are included; the archive itself is excluded from this compact packet.

In `debmetaindex.cc`, `parsePlusMinusArchOptions` uses an explicit `arch` list directly. Only when that value is absent does it combine `getArchitectures()` with enabled `getArchitectureVariants(true)`. The companion `aptconfiguration.cc` shows that enabled variants come from APT's existing configuration and CPU/base-architecture rules. These two files also match byte-for-byte the independently retrieved [upstream APT source revision](https://github.com/Debian/apt/blob/6b128124271e94bdb0f4e7850d9286170d712b04/apt-pkg/deb/debmetaindex.cc). This is source-mechanism evidence; the exact APT version installed on the hosted runner belongs to the separate runtime readback.

Local commit `0c80fb1273bbd994cfe092bdb12ef69ec23f9c5c`, tree `d30b89eb9c661bf514618f511f5979ec0b062e9c`, changes only `artifact/ci_apt.sh`: three added lines and two removed lines. `fix.patch` is the exact diff from SDK source `2f42d2ce...`.

The generated source keeps its installed Ubuntu archive keyring, fixed HTTPS mirror, suite, pockets and components. The update/install transaction body is byte-identical to the previous source: shared private indexes, signature and time checks, noninteractive operation, one 360-second deadline, bounded retries, and the default refusal to downgrade remain in force. No `--allow-downgrades` option is added. Removing the filter follows the runner's configured architecture and variant policy; it does not enable a new variant.

## Local verification

`bash -n` and `git diff --check` passed. The existing 13 isolated host/tool-location controls passed against the repaired helper, with the source assertion adapted to the restored APT default selection. The controls retain update and install failures, update and install deadlines, supported mirror routes, input rejection, consistent transaction options and workspace cleanup. Their complete output is in `CONTROLS.json`, and the replay script is `check_controls.py`.

Those controls use fixtures; the actual Ubuntu 26 package solver, archive signature validation and tool consumers are covered by a separate hosted run. `VALIDATION.json` binds the local commit, source hashes, transaction-body comparison and local verification scope. This packet starts no workflows and changes no repository ref.
