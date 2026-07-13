# q-periapt-wasm

WASM bindings for the PQ/T hybrid suite (ML-KEM-768 + X25519 + SHA3) via
`wasm-bindgen` — the same one Rust core, exposed to JavaScript/TypeScript.

The WASM face is the current stateless KEM/policy API, not a prekey or ratchet
implementation. It provides no persistent session, multi-device, recovery, or
PQ3/Signal parity claim. See
[`../../docs/CONTINUITY_RESEARCH.md`](../../docs/CONTINUITY_RESEARCH.md) for the
future-only session architecture and proof requirements.

Randomness (encapsulation coins, key seeds) is supplied **by the JS caller** as a
`Uint8Array`, so there is no in-WASM entropy dependency.

## Build

The portable C ML-KEM provider requires upstream LLVM Clang with a `wasm32`
backend. Set `CC_wasm32_unknown_unknown` to the compiler's **absolute path**;
the build validates that it is a regular Clang executable, rejects Apple Clang,
and requires `clang --print-targets` to list `wasm32`.

```sh
# macOS (Homebrew LLVM; do not use /usr/bin/clang):
export CC_wasm32_unknown_unknown="$(brew --prefix llvm)/bin/clang"

# Linux CI equivalent:
# export CC_wasm32_unknown_unknown=/usr/bin/clang-18

# Compiles to wasm32 (proves portability; checked in CI):
cargo build --locked -p q-periapt-wasm --target wasm32-unknown-unknown

# Full JS package with bindings (needs wasm-pack):
wasm-pack build crates/q-periapt-wasm --target web
```

## Current-source local footprint (platform/toolchain-specific)

On Darwin 27.0.0 arm64, the current working source built with Rust 1.96.0,
`wasm-pack` 0.15.0, and Homebrew LLVM Clang 22.1.8 measured **97.7 KiB**
(100,034 bytes) for the lean default module (`encapsulate` / `decapsulate` /
`combine` / keygen only):

```sh
wasm-pack build crates/q-periapt-wasm --release --target web
```

The optional signed-policy path (`decision_from_signed_policy`, behind the
off-by-default `signed-policy` feature) links an ML-DSA verifier and measured
**332.6 KiB** (340,625 bytes) in the same run:

```sh
wasm-pack build crates/q-periapt-wasm --release --target web -- --features signed-policy
```

These are current-source **local diagnostics**, not architecture-independent package
sizes, clean signed provenance, or a cross-platform binary claim. Reproduce all
three local artifacts (including the C ABI row) from a repository checkout with:

```sh
CC_wasm32_unknown_unknown="$(brew --prefix llvm)/bin/clang" sh paper/footprint.sh
```

The exact host/toolchain/result rows live at `paper/footprint.csv` in the repository
checkout (that file is not part of this crate package); regenerate them for every
platform or toolchain named in a footprint claim.

## API

```ts
import init, {
  mlkem768_keypair,
  mlkem768_xwing_keypair,
  x25519_keypair,
  version,
  fixed_suite_id,
  encapsulate,
  decapsulate,
} from "./pkg/q_periapt_wasm.js";
await init();

if (version().length === 0) throw new Error("empty q-periapt WASM version");
if (new TextDecoder().decode(fixed_suite_id()) !== "ML-KEM-768+X25519") {
  throw new Error("q-periapt WASM suite mismatch");
}

const kemPq = mlkem768_keypair(seed64);   // { sk, pk } as Uint8Array
const kemX  = x25519_keypair(scalar32);
const enc   = encapsulate(2, suiteId, 1, kemPq.pk, kemX.pk, context, randPq, randTrad);
//            -> { ct_pq, ct_trad, secret }
const secret = decapsulate(2, suiteId, 1, kemPq.sk, enc.ct_pq, kemPq.pk,
                           kemX.sk, enc.ct_trad, kemX.pk, context);

// X-Wing construction compatibility uses the seed-dk key format; this is not an
// independent endpoint/HPKE interoperability claim:
const xwingPq = mlkem768_xwing_keypair(seed32); // sk is 32 bytes
const xwingEnc = encapsulate(1, suiteId, 1, xwingPq.pk, kemX.pk,
                             new Uint8Array(), randPq, randTrad);
const xwingSecret = decapsulate(1, suiteId, 1, xwingPq.sk, xwingEnc.ct_pq,
                                xwingPq.pk, kemX.sk, xwingEnc.ct_trad,
                                kemX.pk, new Uint8Array());
```

With `--features signed-policy`, use `decision_from_signed_policy` to verify a
domain-separated signed policy against the module's fixed ML-KEM-768 + X25519 suite,
persist the returned bytes `4..40` as `(version,digest)` trusted state, and pass the
full decision to `encapsulate_with_decision` / `decapsulate_with_decision`. Those APIs
commit the exact policy digest and application context and reject `CompatXWing` or an
incompatible L5 policy.

The WASM decision is still a caller-supplied 40-byte array, not an unforgeable handle;
JavaScript can also invoke the low-level metadata APIs above. The signed-policy claim
therefore applies only when a trusted caller preserves the returned decision and uses
the decision-controlled APIs. Treat untrusted JS as requiring an opaque service or
separate trust boundary.

## Cross-platform consistency

The decapsulation logic is verified on the host against
`bindings/shared-test-vectors.json` (`cargo test -p q-periapt-wasm`,
`decapsulate_matches_shared_vector`) — the same oracle the C / Swift bindings use.
The tests also cover keypair -> encapsulate -> decapsulate for both ContextBound
expanded keys and CompatXWing seed-dk keys, plus version/fixed-suite metadata. Running
the *actual* WASM build against the vector uses `wasm-pack test` (needs Node); the
wasm32 build itself is gated in CI.
