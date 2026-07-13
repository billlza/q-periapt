<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Vendored license inventory

The upstream `LICENSE`, reproduced as `LICENSE.mlkem-native`, states that all
source code under `mlkem/` is available under the recipient's choice of:

```text
Apache-2.0 OR ISC OR MIT
```

This covers the 118 vendored `.c`, `.h`, `.inc`, and `.S` files. The crates.io
package distributes those files under the Apache-2.0 or MIT option, matching
the package's SPDX expression.

The following six upstream documentation files are `CC-BY-4.0`:

- `README.md`
- `src/fips202/native/armv81m/README.md`
- `src/native/aarch64/README.md`
- `src/native/ppc64le/README.md`
- `src/native/riscv64/README.md`
- `src/native/x86_64/README.md`

They remain in the repository's exact upstream subtree and in the per-file
inventory, but Cargo's package allowlist excludes them because none is used by
the portable build.
