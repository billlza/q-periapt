# Explicit expanded-key transfer (unpublished 0.2.0-alpha.1)

The default path generates an owned hybrid key with platform randomness and
returns only its public key. Professional transfer is a separately named API:
`q_periapt_sdk::expert`, C `q_periapt_sdk_expert_key_*`, Swift/JVM
`QPeriaptExpert`, Android `QPeriaptSDK.Expert`, and WASM `QPeriaptExpert`.
There is no caller-supplied seed/coin parameter or default private-key getter.

## Plaintext format version 1

The representation is exactly 2440 bytes. Multi-byte lengths are not encoded:

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 3 | ASCII `QPK` |
| 3 | 1 | Format version `1` |
| 4 | 1 | Fixed ML-KEM-768 + X25519 suite code `1` |
| 5 | 1 | ContextBound profile code `2` |
| 6 | 1 | Expanded-key representation code `1` |
| 7 | 1 | Reserved; must be zero |
| 8 | 2400 | FIPS-expanded ML-KEM-768 decapsulation key |
| 2408 | 32 | X25519 input scalar, as retained by the owner |

All eight header bytes must match exactly. Length failures return `InvalidLength`
or native `ERR_LENGTH=-2`; unsupported format or failed key-consistency checks
return `InvalidPrivateKey` / `ERR_INVALID_PRIVATE_KEY=-13`.

An import requires a separately verified, open, enabled runtime and a live-key
quota slot. It derives both paired public keys. The existing native ML-KEM
provider checks the embedded public key's canonical encoding and its stored
hash; a fresh platform-random 32-byte challenge then drives encapsulation and
decapsulation, whose shared secrets are compared in constant time. Errors return
the key quota and erase owned secret temporaries. Subsequent decapsulation keeps
the provider's integrity checks; import does not create an unchecked hot path.

These are the applicable expanded-key consistency checks in
[FIPS 203, section 7.1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf).
No seed is supplied, so seed consistency cannot be verified. A successful check
does not certify generation entropy or make the representation seed-derived
X-Wing material. The X25519 scalar's entropy cannot be inferred from its bytes.

## Security and lifetime boundary

The format is plaintext, unauthenticated, and contains no authorization token,
trust root or policy epoch. Import intentionally binds it to the supplied
runtime's current policy. Applications must authenticate and encrypt any storage
or transport, authorize that rebinding, and obey the protocol's key lifetime and
freshness requirements. SDK ownership does not authorize ephemeral-key reuse.

Rust exports use a non-cloneable zeroizing heap owner. Explicit `close()` clears
it; drop erases its buffer. Foreign exports copy into caller-owned memory, which
remains usable after the native runtime is revoked. FFM/JNI/WASM erase their
owned temporary buffers on normal/error paths. Swift copy-on-write arrays,
Java/JS garbage-collected copies, caller copies, compiler temporaries, registers,
process snapshots and swap are outside a whole-process erasure guarantee.

Cross-language consumers exercise export/import public-key pairing, actual
ContextBound roundtrips, format rejection, and revocation. Core tests also cover
damaged embedded public-key/hash/private-prefix material, entropy failure and
quota recovery.
