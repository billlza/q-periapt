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

## API

```ts
import init, { mlkem768_keypair, x25519_keypair, encapsulate, decapsulate } from "./pkg/q_periapt_wasm.js";
await init();

const kemPq = mlkem768_keypair(seed64);   // { sk, pk } as Uint8Array
const kemX  = x25519_keypair(scalar32);
const enc   = encapsulate(2, suiteId, 1, kemPq.pk, kemX.pk, context, randPq, randTrad);
//            -> { ct_pq, ct_trad, secret }
const secret = decapsulate(2, suiteId, 1, kemPq.sk, enc.ct_pq, kemPq.pk,
                           kemX.sk, enc.ct_trad, kemX.pk, context);
```

## Cross-platform consistency

The decapsulation logic is verified on the host against
`bindings/shared-test-vectors.json` (`cargo test -p q-periapt-wasm`,
`decapsulate_matches_shared_vector`) — the same oracle the C / Swift bindings use.
Running the *actual* WASM build against the vector uses `wasm-pack test` (needs
Node); the wasm32 build itself is gated in CI.
