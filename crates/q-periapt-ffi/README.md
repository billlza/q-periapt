# q-periapt-ffi

C ABI 2 for Q-Periapt's signed-policy runtime, owned keys, protocol-key
derivation, connections and supported host-policy persistence.

The 0.2.0 SDK has 51 C exports. Its new-integration entry points are the
`q_periapt_sdk_*` runtime/owner functions; the four serialized-decision
operations are deprecated for new integrations. Continuity's `qpc-owner/1`
interface is distributed separately.

## Install or build

Start with the [language and platform installation guide](https://github.com/billlza/q-periapt/blob/main/docs/SDK_GETTING_STARTED.md)
for prebuilt native/Apple packages and the matching headers. For Rust-hosted
embedding builds:

```sh
cargo add 'q-periapt-ffi@=0.2.0'
```

- [0.2.0 Rust declarations](https://docs.rs/q-periapt-ffi/0.2.0/q_periapt_ffi_abi2/)
- [SDK C header](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/crates/q-periapt-ffi/include/q_periapt.h)
- [Machine-readable ABI contract](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/crates/q-periapt-ffi/abi/q-periapt-c-abi-v2-sdk-020.json)
- [Host-policy storage API and platform scope](https://github.com/billlza/q-periapt/blob/main/docs/SDK_HOST_STORE.md)

Callers retain valid allocations for every pointer/length pair and release
owned handles through the matching API. Input ranges and lengths are checked;
an arbitrary inaccessible pointer cannot be made safe by a C ABI length check.
The runtime requires independently pinned policy trust and the documented
persist-before-use sequence.

## Release and evidence

- [Published 0.2.0 package and qualification record](https://github.com/billlza/q-periapt/tree/v0.2.0-verified-cohort/release/0.2.0)
- [Proofs, performance results and reproduction entry points](https://github.com/billlza/q-periapt/blob/main/docs/EVIDENCE_INDEX.md)
- [Changelog](https://github.com/billlza/q-periapt/blob/main/CHANGELOG.md)
