# Cargo dependency alias capture

Captured on 2026-10-08 with Cargo 1.98.1, commit
`797e8a9bca276c1c9f9f738d2a20f484fa4eea9d`, on macOS arm64. This fixture uses
seven synthetic packages served by a loopback sparse registry. The receiver
captures one request and deliberately returns HTTP 403. No public registry is
contacted or updated; the fresh Cargo home contains only a noncredential token.
An explicit denying proxy prevents an accidentally selected external endpoint.

Reproduce with an actual toolchain directory containing `bin/cargo` and
`bin/rustc` (the output directory must not exist):

```sh
python3 artifact/testdata/crates_io_uploader/registry-alias-fixture.capture.py \
  /absolute/fresh/capture /absolute/cargo-1.98.1-toolchain
```

`cargo publish --registry dummy-registry --allow-dirty` performs Cargo's normal
archive verification before the local rejection. The `.cargo.toml` and
`.readme.md` files are extracted from the captured archive. `.metadata.json` is
the unmodified JSON segment of the captured wire request, not output from the
derivation under test. Two independent captures reproduced these three files
byte-for-byte. The generator retains the complete request, archive, command
output, request paths and Cargo version in its output directory.

The upload destination is an alternate registry, so Cargo includes the
crates.io `registry` URL on every dependency. The golden test asserts that exact
URL, then removes only this destination-dependent field before comparing the
derivation for a crates.io upload. It also asserts that parsing and serializing
the raw capture reproduces the raw bytes. This projection is explicit; this
fixture does not claim that a request was sent to the public crates.io endpoint.

The capture covers normal, dev, build and target dependencies; optional aliases
with explicit `dep:alias` features; an unrenamed dependency with an omitted
alias field; and `package` explicitly equal to the table name. The latter still
emits `explicit_name_in_toml`.

SHA-256:

| File | Digest |
| --- | --- |
| `registry-alias-fixture.cargo.toml` | `3139278821448f09beb33c759f60754c7915d79179d897f3826dad1fe12dedbf` |
| `registry-alias-fixture.metadata.json` | `ad36651c1ffd5bd0a13c53a7be103cc0ef41a6f658645780f07a9021a9d1b191` |
| `registry-alias-fixture.readme.md` | `3f3ac78d9bcdee7c2f47f78fc18d224a4cc4f3d5f81d73a6bbc76e5df9246689` |

Upstream semantics are documented in the [Cargo registry publish API](https://doc.rust-lang.org/cargo/reference/registry-web-api.html#publish).
Field order and omission rules were also checked against Cargo's exact
[serialization struct](https://github.com/rust-lang/cargo/blob/797e8a9bca276c1c9f9f738d2a20f484fa4eea9d/crates/crates-io/lib.rs)
and [dependency derivation](https://github.com/rust-lang/cargo/blob/797e8a9bca276c1c9f9f738d2a20f484fa4eea9d/src/cargo/ops/registry/publish.rs).
