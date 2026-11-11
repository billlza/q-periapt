# Ubuntu 26 architecture-variant qualification

[Run 43062177678](https://github.com/billlza/q-periapt/actions/runs/43062177678), job [130667389723](https://github.com/billlza/q-periapt/actions/runs/43062177678/job/130667389723), passed the actual Ubuntu 26 installation and all dependency consumers. The eight requested dependencies were prepared in **59.40 seconds**. The installed-package census changed from **1,234 to 1,380**: 146 new packages, with all 1,234 preexisting package identities and versions retained exactly. The independently recomputed TSV comparison matches the original transition receipt: zero upgrades, downgrades or removals.

This packet follows the [sealed four-failure and minimal-fix evidence](../20261111-ubuntu26-apt-architecture-variants/README.md), which is preserved without modification. It also retains a fifth original failure on the same pre-fix SDK source: Binary CT `x86_64-portable`, job 130657939481. That job's valgrind install was rejected after proposing downgrades of `libc-bin` and `libc6-i386`; its later CT checks were not reached. `FIFTH_FAILURE.json` identifies the complete original log and exact APT lines. The saved log's recomputed Git blob identity matches the supplied public original.

## Fixed source and actual runner policy

The qualified production source is `96e9a63cf8359b130003cd851008a7ce3649aea7`, tree `d30b89eb9c661bf514618f511f5979ec0b062e9c`. That tree exactly matches local fix `0c80fb1273bbd994cfe092bdb12ef69ec23f9c5c`. The diagnostic workflow is a separate child commit, `6fa6291f7e2c68a98bcf739b2eea72a59bd165bc`, and checks out the exact production candidate. `SOURCE_BINDING.json`, the original `source.txt`, `workflow.yml`, the API job snapshot and successful clean-source step bind this execution to that source.

The runner is Ubuntu 26.04.1, image `20261101.186.1`. Its actual installed APT version is **3.2.0** and dpkg version is **1.23.7ubuntu1**. Its native architecture is `amd64`, while its existing APT configuration enables `APT::Architecture-Variants "amd64v3"`. The retained architecture file contains the complete `APT::Architecture*` entries emitted by the diagnostic, together with OS and native-architecture information; it does not capture unrelated APT configuration keys.

The corrected source leaves APT's architecture selection intact. The actual update downloaded **13 amd64v3 package indexes** and selected no separate amd64 package indexes. The five pre-fix failure logs had downloaded 13 amd64 package indexes instead. The fixed transaction succeeds with the same signature, time, deadline and downgrade protections. Its original installation log records `0 upgraded, 146 newly installed, 0 to remove` and contains no downgrade override.

The source-mechanism evidence in the preceding packet uses official Ubuntu APT 3.2.1ubuntu0.1, the version named by the Resolute manual. The runtime package version above comes directly from this runner's original installed-package inventories; the two version observations are kept distinct.

## Eight dependencies and actual consumers

| Requested dependency | Installed version | State |
| --- | --- | --- |
| valgrind | 1:3.26.0-0ubuntu1 | new |
| qemu-user | 1:10.2.1+ds-1ubuntu3.3 | new |
| gcc-riscv64-linux-gnu | 4:15.2.0-5ubuntu1 | new |
| graphviz | 14.1.2-1ubuntu1 | new |
| unzip | 6.0-29ubuntu1 | retained |
| libgtk2.0-dev | 2.24.33-10 | new |
| ocaml | 5.4.0-3ubuntu1 | new |
| pkg-config | 2.5.1-4 | retained |

The hosted workflow executed the following consumers after installation:

- **Valgrind:** compiled a C program using the Memcheck client header and executed it under Memcheck with an error exit code. The log records zero errors.
- **RISC-V tools:** cross-compiled a C program with `riscv64-linux-gnu-gcc`, then executed it using `qemu-riscv64`; the program emitted `RISCV_CONSUMER_OK`.
- **Formal-tool dependencies:** Graphviz wrote a nonempty SVG, unzip checked a real archive, OCaml compiled and executed its program, and GTK2 was located through pkg-config and used to compile and execute a C program. The log reaches both OCaml and complete dependency success markers. The original log preserves its nonfatal OCaml file-name and GTK deprecation warnings.
- **Existing OpenSSL consumer:** CMake/PkgConfig found OpenSSL 3.5.5, compiled the repository's `witness_tls_peer.c`, and passed its `identity` CTest, 1/1. This checks the existing native tool consumer after the package installation.

The API snapshot records success for installation, all three consumer steps, clean source and evidence upload. These results qualify the dependency preparation and the executed consumers for this Ubuntu 26 runner. Full project CI results remain attached to their own SDK runs.

## Original evidence and independent readback

Artifact `13873294590` is **38,191 bytes**, SHA-256 `5b14796db2e16db53f3e6bce200a7570ea8dc7afcd8635795b5f559cd649f746`. The downloaded ZIP matches GitHub's size and digest. Its exact ten-member census, CRC and per-member hashes were checked; all original members are retained under `artifact/`, and the small original ZIP is included.

`READBACK_VERIFICATION.json` records an independent comparison of the before/after TSV inventories, the JSON transition receipt, all eight dependency identities, the selected architecture indexes, consumer logs, source bindings and successful API steps. `VERIFY_READBACK.py` and its full `verification.log` reproduce this readback from the retained packet. The verification reads existing files and metadata; it does not execute APT, compilers, consumers, test suites or another CI run. The complete original job log is also included.

`MANIFEST.json` binds every other file in this packet by byte size, SHA-256 and Git blob identity, and binds the unchanged prior failure packet by its original manifest hash. The publication parent is the Stage4 terminal evidence commit `7b82b487fba9b70f66ae3d38e909a0ed194a2ee5`.
