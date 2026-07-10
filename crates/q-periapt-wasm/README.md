# q-periapt-wasm

WASM bindings for the PQ/T hybrid suite (ML-KEM-768 + X25519 + SHA3) via
`wasm-bindgen` — the same one Rust core, exposed to JavaScript/TypeScript.

Randomness (encapsulation coins, key seeds) is supplied **by the JS caller** as a
`Uint8Array`, so there is no in-WASM entropy dependency.

## Build

```sh
# Compiles to wasm32 (proves portability; checked in CI):
cargo build -p q-periapt-wasm --target wasm32-unknown-unknown

# Full JS package with bindings (needs wasm-pack):
wasm-pack build crates/q-periapt-wasm --target web
```

## Footprint (reproducible)

The lean default module — `encapsulate` / `decapsulate` / `combine` / keygen only — is
**≈195 KiB** (199 711 bytes, `wasm-pack 0.15`, `--release`):

```sh
wasm-pack build crates/q-periapt-wasm --release --target web        # ≈195 KiB
```

The optional signed-policy path (`profile_from_signed_policy`, behind the off-by-default
`signed-policy` feature) links an ML-DSA verifier, which grows the module to **≈586 KiB**:

```sh
wasm-pack build crates/q-periapt-wasm --release --target web -- --features signed-policy  # ≈586 KiB
```

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

// X-Wing interop uses the seed-dk key format:
const xwingPq = mlkem768_xwing_keypair(seed32); // sk is 32 bytes
const xwingEnc = encapsulate(1, suiteId, 1, xwingPq.pk, kemX.pk,
                             new Uint8Array(), randPq, randTrad);
const xwingSecret = decapsulate(1, suiteId, 1, xwingPq.sk, xwingEnc.ct_pq,
                                xwingPq.pk, kemX.sk, xwingEnc.ct_trad,
                                kemX.pk, new Uint8Array());
```

## Cross-platform consistency

The decapsulation logic is verified on the host against
`bindings/shared-test-vectors.json` (`cargo test -p q-periapt-wasm`,
`decapsulate_matches_shared_vector`) — the same oracle the C / Swift bindings use.
The tests also cover keypair -> encapsulate -> decapsulate for both ContextBound
expanded keys and CompatXWing seed-dk keys, plus version/fixed-suite metadata. Running
the *actual* WASM build against the vector uses `wasm-pack test` (needs Node); the
wasm32 build itself is gated in CI.
