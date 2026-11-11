# Continuity 0.2.0 Linux native companion

The native companion packages the **existing Release C owner library** after
the installed Rust/C producer completes its Debug and Release scenarios. The
formal archive identity is
`q-periapt-continuity-native-0.2.0-<target>.zip`, for an executed
`x86_64-unknown-linux-gnu` or `aarch64-unknown-linux-gnu` host. Each target keeps
its own build, execution receipt and archive digest. The existing Linux CI
invocation produces the host archive together with its C qualification.

The package retains `qpc-owner/1`: 158 exported functions, the unchanged public
header and declaration snapshot. Its internal library filename remains
`libq_periapt_continuity_c_consumer.so`. SDK C ABI 2 has a separate namespace.

## Archive and installed use

The archive has one directory named after the archive basename. It contains:

- `include/qpc_owner.h` and `include/abi/qpc-owner-v1.json`;
- `lib/libq_periapt_continuity_c_consumer.so`;
- `PACKAGE_CONTENTS.json`, binding source commit/tree, actual qualified library,
  runtime dependencies and symbol versions, C execution receipt and every member;
- project, Rust standard-library, external Rust and mlkem-native notices.

Verify the archive's SHA-256 against the selected release manifest before
extracting it. Compile against `include/` and link against `lib/` with
`-lq_periapt_continuity_c_consumer`. Install the shared library in the application's
controlled library directory and select that directory through its loader
configuration. The library retains its fixed SONAME. Its `NEEDED` and required
GLIBC/GCC symbol versions are recorded in `PACKAGE_CONTENTS.json`; the deployment
must provide those system runtimes. No alternate loader path or additional
non-system shared library is admitted by this producer.

After creating the deterministic ZIP, the producer independently extracts it,
verifies the entire member inventory and the native ABI/loader metadata again,
then compiles and executes a fresh C probe against the extracted header/library.
The probe checks its loaded library's actual path and exercises argument refusal
and closed-handle behavior. The complete original C scenarios remain attached
to the exact unchanged library through `C_CONSUMER.json`.

## Produce from the installed package qualification

Add `--with-native-package` to the existing `artifact/continuity_package.py`
invocation with `--with-c-consumer`. It requires the full Debug/Release execution
and supported Linux host. `--native-engine-package-id` selects the corresponding
engine row ID in the coordinated manifest; its default is `continuity-engine`.

The output includes the archive and three JSON records:

| Record | Binding |
| --- | --- |
| `CONTINUITY_NATIVE_PACKAGE.json` | Actual source, exact C execution receipt/library, loader inventory, archive readback and relocated probe |
| `CONTINUITY_NATIVE_DISTRIBUTION.json` | Native package `0.2.0`, source commit/tree, engine dependency, `continuity_c` interface and artifact digest |
| `CONTINUITY_NATIVE_PACKAGE_ROW.json` | A native distribution row accepted by the existing release-manifest schema |

The emitted references are relative to this producer's output directory. Copy
the records and artifacts together when assembling a coordinated manifest, or
rewrite its file paths consistently while preserving the file hashes. The
normative lock, selected-source checks and publication use the repository's
`docs/continuity/RELEASE_0_2_ADMISSION_PLAN.md` at the source commit recorded in
`PACKAGE_CONTENTS.json`. Production success records a
native distribution artifact and its verification; release eligibility and
publication flags remain false until that coordinated admission.
