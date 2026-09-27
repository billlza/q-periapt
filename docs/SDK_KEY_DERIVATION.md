# Owned application-key derivation, version 1

The unpublished 0.2.0-alpha.1 SDK can derive a 32-byte application key from an
owned ContextBound shared secret without first exporting that secret. This is
an additional application-key layer. Existing ContextBound and CompatXWing
combiner bytes are unchanged, and this is not the TLS key schedule.

The primitive is [HKDF-SHA-256, RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html),
using RustCrypto `hkdf` 0.13.0, `hmac` 0.13.0 and `sha2` 0.11.0. HKDF's extract
and expand steps both run. The protocol-specific framing below is the SDK's
version-1 contract, not an IETF interoperability claim.

## Exact bytes

IKM is the 32-byte combined KEM secret. Salt is the ASCII bytes
`QPeriapt-SDK-HKDF-SHA256-v1`, without a terminator. Output length is 32 bytes.
The HKDF info is the following ordered concatenation, streamed as components:

| Field | Encoding |
| --- | --- |
| Domain | ASCII `QPeriapt-SDK-Key-v1`, no terminator |
| Suite | `u32_be(1)`, ML-KEM-768+X25519 |
| Profile | `u32_be(2)`, ContextBound |
| Policy state | Existing 36-byte `version_be || exact_signed_document_digest` |
| Trust root | SHA-256 of the exact 1952-byte ML-DSA-65 verification key verified by the runtime |
| Purpose | `u32_be(code)`, from the closed table below |
| Protocol label | `u16_be(byte_length) || label` |
| Context | `u32_be(byte_length) || context` |
| Output length | `u16_be(32)` |

Labels contain 1..255 bytes of ASCII 0x21..0x7e. Choose a stable label identifying
your application protocol, version, algorithm and exporter use. Whitespace,
NUL and non-ASCII bytes are rejected; no normalization is performed. Context is
0..65536 bytes, typically an authenticated protocol transcript or session context.
Different splits of label/context cannot collide merely through concatenation.

| Code | Purpose | Shared direction interpretation |
| --- | --- | --- |
| 1 | Initiator traffic | Initiator sends, responder receives |
| 2 | Responder traffic | Responder sends, initiator receives |
| 3 | Initiator confirmation | Initiator's confirmation computation |
| 4 | Responder confirmation | Responder's confirmation computation |
| 5 | Exporter | Label identifies the specific application use |

These are global roles agreed by the protocol, not local “send” and “receive”
labels. Identical input tuples reproduce the same key; use fresh KEM handshakes
where fresh session keys are required. Derivation does not authenticate a peer,
perform key confirmation, select a cipher, allocate nonces or prevent replay.
Applications still provide those protocol properties. Incorrect roots, policy
states, directions, labels or contexts produce different keys.

## Ownership and language parity

Rust `SharedSecret::derive_key` returns a non-cloneable `DerivedKey`. C adds
`q_periapt_sdk_secret_derive` and `q_periapt_sdk_derived_key_export` to ABI **2**;
the unpublished current export table is exactly 20 names, including the original
nine unchanged declarations. Existing library filenames/identities and statuses
remain unchanged. `ERR_PURPOSE=-12` is additive.

Swift, Kotlin/JVM, Android and WASM expose corresponding `deriveKey`/`derive_key`
operations, named purposes and a separate derived-key owner. A derived-key handle
cannot be passed as a KEM secret or recursively derived. It survives closing the
source secret but is revoked by runtime close. Its explicit `exportForProtocol`
method copies bytes for an external cipher/MAC; the recipient owns their erasure.
Closing the owner cannot erase already exported copies.

Derivation uses the existing operation admission budget. Native derived handles
also consume the bounded registry's live/pending slots. Native close/publication,
borrowing and failure-output rules are unchanged. Input lengths are checked
before JNI/FFM/WASM copies. WASM accepts only the five exact numeric codes;
fractional values, NaN, infinity and large values cannot wrap into another role.

## Erasure and evidence boundary

The returned owner and explicit Rust export copies use `ZeroizingBytes`. The
PRK returned by `Hkdf::extract` is erased immediately; `Hkdf::new` is deliberately
not used because it discards that returned array. HMAC/digest/SHA-256 zeroize
features clear owned hash states and residual block buffers on drop. These
features do **not** guarantee erasure of every upstream intermediate array,
compiler/register copy, JavaScript/Swift/JVM export, swap page or crash dump.

This boundary was checked against the pinned
[HKDF implementation](https://github.com/RustCrypto/KDFs/blob/hkdf-v0.13.0/hkdf/src/lib.rs)
and [HMAC implementation](https://github.com/RustCrypto/MACs/blob/hmac-v0.13.0/hmac/src/block_api.rs).
In particular HKDF's internal expansion output and HMAC's internal padded-key
and inner-hash arrays are not all wipe-guaranteed. No whole-process erasure or
malicious-same-process isolation claim is made.

Tests cover the RFC 5869 Appendix A.1 first block, independent Python-HMAC
framing bytes, every purpose, policy/root/context separation, input boundaries,
resource admission, type confusion and revocation. Real host C, Swift, JVM,
JNI and Node consumers exercise the Rust implementation. Android ART, hosted
CI, current installed packages, binary CT and external security review remain
separate release gates in [the readiness ledger](SDK_0_2_RELEASE_READINESS.md).

The framing vector uses public test-only material: IKM=`07` repeated 32 times,
policy-state=`02` repeated 36 times, root-digest=`03` repeated 32 times, purpose=1,
label=`app/v1/aes256`, context=`transcript`. Its output is
`899c3fe0b3419a6f3947c4e237daf8970b2c29442d9fce4385d30d2558242f65`.
