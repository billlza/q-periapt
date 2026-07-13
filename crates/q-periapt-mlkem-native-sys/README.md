<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# q-periapt-mlkem-native-sys

This crate is the single native-code and `unsafe` boundary for Q-Periapt's
portable ML-KEM implementation. It vendors the `mlkem/` subtree from
`pq-code-package/mlkem-native` v1.2.0 and exposes only safe, allocation-free,
exact-array Rust operations for ML-KEM-512, ML-KEM-768, and ML-KEM-1024.

Despite the `-sys` suffix, raw C declarations are private. Callers use
`MlKem512`, `MlKem768`, or `MlKem1024` and provide all output storage in place.
An error always leaves every output filled with zeroes.

## Security boundary

- All upstream KEM entry points and parameter-dependent helpers have static
  linkage in one C translation unit. mlkem-native's remaining shared FIPS 202
  helpers use a unique versioned namespace and hidden visibility.
- Rust links only versioned `qpn_mlkem_bridge_v1_2_0_*` symbols. Those symbols
  have hidden visibility and deliberately do not use the product-reserved
  `q_periapt_` prefix.
- Public Rust signatures encode every C buffer length as an array type.
- Safe Rust makes mutable inputs and outputs disjoint. The crate also performs
  checked address-range comparisons for the two shared inputs accepted by
  encapsulation and decapsulation.
- Expanded decapsulation keys pass both checks required by the product import
  contract: the embedded public key is checked for canonical encoding, then
  upstream decapsulation verifies `H(EK)` before using the secret key.
- Malformed ciphertext is handled by FIPS 203 implicit rejection and is not
  reported as an API failure.

The crate is portable-C only. Its configuration rejects the upstream native
arithmetic and FIPS 202 backend selectors, and the build compiles no upstream
`.S` file. It contains no Cargo feature that enables a native backend or
compile-time CPU assumptions. Native builds retain mlkem-native's small inline
value barrier, which is part of the portable C constant-time strategy rather
than an optimized arithmetic/Keccak implementation. Freestanding targets that
cannot support it select the integration's fixed-loop memory/zeroization
helpers and upstream's C value barrier. This applies to Wasm and bare-metal
builds so their C object does not depend on target C-library headers. Windows
uses its normal C runtime functions and upstream's `SecureZeroMemory` path. Those
small helpers are part of this crate's integration TCB. The crate is `no_std`
at the Rust runtime boundary, but building it requires a supported C compiler.

mlkem-native v1.2.0 declares its randomized functions even when their
definitions are disabled, which conflicts with strict GCC diagnostics once the
upstream API has static linkage. The translation unit therefore retains those
functions as unreachable static-inline code and binds a private random-byte
provider that zeroes its requested buffer and returns failure. No randomized
function has a bridge or Rust declaration, and deterministic operations never
call this provider. It is neither a public API nor a runtime fallback.

The upstream project provides CBMC memory/type-safety evidence for C and
separate formal evidence for selected assembly backends. This crate does not
use those assembly backends, and it does not claim that portable C has a full
functional-correctness or source-level constant-time proof. It has not received
an independent security audit.

ELF and Mach-O builds mark the bridge and remaining versioned helpers hidden.
COFF has no equivalent source-level visibility class; the bridge deliberately
has no `dllexport`, so a normal MSVC DLL does not export it. Final product
libraries must nevertheless retain an exact export allowlist gate, especially
for MinGW linkers that can be configured to export all symbols.

Hidden visibility is not an access-control boundary for a static archive. A
static `q-periapt-ffi` consumer can deliberately declare and link the versioned
`qpn_mlkem_bridge_*` symbols that the safe Rust layer itself needs. Those link
symbols are unsupported implementation details, absent from the public header,
and may change without ABI notice. The exact-nine claim therefore applies to all
named exports of the `cdylib`/DLL. For a `staticlib`, only the reserved public
`q_periapt_*` namespace is constrained to those nine names; the embedding process
is a trusted same-address-space boundary, not a sandbox.

## Vendored source

[`vendor/PROVENANCE.md`](vendor/PROVENANCE.md) records the immutable commit and
archive hashes. [`vendor/INVENTORY.sha256`](vendor/INVENTORY.sha256) covers all
124 files in the repository copy of the upstream `mlkem/` subtree. From a full
Q-Periapt repository checkout, run:

```text
python3 scripts/verify-vendor.py
```

The published `.crate` deliberately contains the pinned inventory, provenance,
licenses, and all 118 build-relevant upstream code files, but not the repository
maintenance scripts. Crates.io package readers verify its immutable contents via
the archive checksum and inventory; the commands in this section require a
repository checkout.

The repository retains the exact upstream subtree. The crates.io package
contains all 118 code files (`.c`, `.h`, `.inc`, and `.S`) but excludes the six
CC-BY-4.0 upstream README files because they do not participate in the build.
The packaged code is available under Apache-2.0 or MIT, matching this crate.

From a repository checkout, reproduce the pinned import from an already
downloaded archive:

```text
python3 scripts/update-vendor.py --archive /path/to/pinned-archive.tar.gz
```

Without `--archive`, the update script downloads the immutable commit archive,
verifies it before extraction, rejects unsafe paths and non-regular selected
members, and replaces the subtree only after complete staging.

## Resource bounds

The upstream v1.2.0 headers report the following maximum cumulative stack
allocations for the portable configurations used here:

| Parameter set | Key generation | Encapsulation | Decapsulation |
| --- | ---: | ---: | ---: |
| ML-KEM-512 | 5,824 bytes | 8,384 bytes | 9,152 bytes |
| ML-KEM-768 | 10,176 bytes | 13,248 bytes | 14,336 bytes |
| ML-KEM-1024 | 15,552 bytes | 19,136 bytes | 20,704 bytes |

These are C implementation bounds and do not include caller or Rust stack use.
