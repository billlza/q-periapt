# Linux x86-64 AVX2 candidate

This is an opt-in 0.2.0 source candidate, not a qualified native release.
ABI major and library names remain 2. Windows/MSVC and other x86 targets retain
their existing default paths and require separate native-backend qualification.

## Source and dispatch boundary

The 124 vendored files still match mlkem-native v1.2.0 at
`0ba906cb14b1c241476134d7403a811b382ca498`; no upstream code was edited.
`mlkem_bridge_x86_64.c` and its assembly wrapper select the pinned x86 arithmetic
and four-way Keccak headers directly. Both the baseline portable C unit and
native wrapper compile with baseline x86-64 flags. The native assembly has a
separate namespace so that the two implementations cannot accidentally resolve
to the same link symbols.

`src/x86_cpu.rs` checks the following before the private raw boundary calls a
native function:

| Register | Required bits |
| --- | --- |
| CPUID maximum basic leaf | At least 7 |
| CPUID(1, 0).ECX | SSSE3 (9), SSE4.1 (19), POPCNT (23), XSAVE (26), OSXSAVE (27), AVX (28) |
| CPUID(7, 0).EBX | AVX2 (5), BMI2 (8) |
| XGETBV(0), after XSAVE/OSXSAVE checks | XMM state (1) and YMM state (2) |

The register/OS-state model follows the architecture checks in
[Rust's x86 runtime detection](https://doc.rust-lang.org/src/std_detect/detect/os/x86.rs.html).
Inspection of the actual pinned assembly additionally identified `pshufb`,
`pblendw`, `pinsrd`, `pinsrq`, `popcntq` and `pextq`. A first AVX2-only gate was
insufficient: a synthetic missing-feature test failed before adding all these
requirements. The implementation now checks the entire set, not CPU model names.

The process caches public capabilities only. There is no externally writable
force-native flag. Missing capabilities choose the unchanged portable algorithm.
Unsupported build targets, CPU compiler overrides and non-baseline Rust target
features fail at build time; they do not silently produce a different candidate.
The dispatcher remains allocation-free and `no_std`. A typed CPUID function
boundary accommodates the unsafe signature in the [Rust 1.85 stdarch source](https://github.com/rust-lang/stdarch/blob/684de0d6fef708cae08214fef9643dd9ec7296e1/crates/core_arch/src/x86/cpuid.rs)
and its safe signature in the pinned current compiler. The complete workspace's
minimum-Rust-version qualification is still a separate release check.

## Qualification commands

On a native Linux x86-64 GNU host with every required capability:

```sh
cargo clippy --locked -p q-periapt-mlkem-native-sys -p q-periapt-backends \
  -p q-periapt-sdk -p q-periapt-ffi --all-targets \
  --features q-periapt-ffi/linux-x86_64-avx2 -- -D warnings
cargo test --locked --release -p q-periapt-mlkem-native-sys -p q-periapt-backends \
  -p q-periapt-sdk -p q-periapt-ffi --features q-periapt-ffi/linux-x86_64-avx2
cargo build --locked --release -p q-periapt-ctstats --bin ct_decaps_gap \
  --features valgrind,linux-x86_64-avx2
sh artifact/x86-avx2-ct.sh
```

The three native/portable differential tests deliberately fail when the host
cannot execute the candidate. They compare key generation, encapsulation,
decapsulation, implicit rejection, noncanonical public keys and corrupted H(EK)
for all three parameter sets. Existing backend tests also include independent
RustCrypto differential/conformance and strict-import checks.

`x86-avx2-ct.sh` requires the actual native identity inside Memcheck, a detected
planted leak with its dedicated exit status, and zero errors/contexts in every
genuine-secret probe. A tool crash, unavailable AVX2 under instrumentation or a
portable path fails qualification. It retains all controls and probe logs and
rechecks the probe binary hash. This is binary dataflow evidence, not a proof of
all timing behavior. Tail latency and the source/formal assurance boundary must
also be evaluated separately.

CI uses a separate `x86-avx2-candidate` job. Its observed execution is recorded
below, independently of its workflow declaration.

## Observed state and remaining work

The initial 2026-09-25 checkpoint ran macOS/ARM baseline and candidate
CPU/compiler-admission tests. Linux GNU core, SDK, FFI and their test executables cross-compiled using
Clang 22 and task-local, checksum-verified Rust 1.96.1 GNU standard libraries and
Zig 0.15.2 glibc/link inputs. Disassembly checks distinguish baseline C objects
from the separate AVX assembly object. Cross compilation does not execute the
candidate; that checkpoint contained no native Linux KAT/differential/CT/performance results.
No VM, emulator or Linux endpoint was started as a substitute.

Later hosted execution is separate evidence. At `caca8a7`, the
[native x86 job](https://github.com/billlza/q-periapt/actions/runs/36338497784/job/108673836461)
passes strict Clippy, KAT, native/portable and independent implementation
differentials, rejection/import and SDK checks. Its final marker is
`AVX2_BINARY_CT_PASS parameters=512,768,1024`, after the planted-leak control and
genuine-secret probes. The raw job log is retained with that source cohort.
This closes the earlier absence of native candidate execution; controlled
performance, wider side-channel coverage and separate non-GNU qualification
remain open. The opt-in feature is still off in the default SDK packages.

The historical 0.1.5 sys source allowlist rejects the changed local TCB, including
the new dispatcher. Its failed checks and exact historical bytes are retained.
An explicit alpha.1 source profile now binds all sixteen local source/build files,
including CPU admission and raw dispatch. The package inspector selects only a
known version's profile. Unknown versions, changed bytes, missing/extra files and
cross-version substitution fail. Historical lexical and mutation checks continue
against the immutable 0.1.5 fixture; current source has its own tests.

This is a source-identity boundary, not native or CT qualification. The candidate
feature remains off by default. All eighteen workspace packages and internal
requirements now use 0.2.0-alpha.1. A local diagnostic sys `.crate` was actually
packaged and rebuilt on macOS/ARM, and its sixteen source files match the alpha
profile. Complete SDK distribution and installed-consumer checks remain open in
the [release-readiness ledger](SDK_0_2_RELEASE_READINESS.md).

The [local candidate checkpoint](../research/sdk-alpha1/evidence/20260925-x86-candidate/manifest.json)
retains source/binary identities, the missing-instruction-feature counterexample,
compiler override controls, cross-build and disassembly observations, and the
historical source-allowlist failures. Its release and native-execution eligibility
are explicitly false.
