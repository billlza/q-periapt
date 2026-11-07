# Conditional root extraction and its exact encoding

The [root-extraction corollary](../../../../docs/continuity/ROOT_EXTRACTION_QROM_V1.md)
applies the existing shared-root HMAC calculation to the two calls made by
`response::derive_root`. It retains one compression oracle, counted preparation,
the exact public-salt state-pair aliases and the restrictions on raw contribution
or PRK disclosure. The single unused random-table entry is resampled with its
quantum prepared state explicitly retained. The two reductions include the
five ordinary Expand calls and the retained two public pad-state calls in their
respective query budgets.

This is a conditional mathematical step, not the actual accepted-prefix proof.
The ML-KEM/ContextBound contribution, authentication, allowed state acquisition,
multi-epoch composition and external review remain outstanding. The note also
gives a simple counterexample to extending its root-replacement game with raw
PRK disclosure. No protocol primitive, product source or security promise was
changed. The earlier primitive lemma has its own independent internal review;
that review does not claim to review this new corollary.

## Source and finite checks

The source is clean qualification revision
`ff072bd66b1f5d3bdbb80171ee39bad15cbc3c20`. The source-derived Expand input has
40 domain bytes, 25 label bytes, a 32-byte response-core digest and the HKDF
counter byte: 98 bytes total. HKDF's information string has 97 bytes.

Sixty-four combinations of four salts, four contributions and four core digests
agree between the real library HKDF call and a manual compression construction.
Each combination also rejects three altered constructions: the wrong Extract
padding offset, the wrong Expand padding offset and the wrong Expand counter.
There are 192 negative comparisons. The manual paths use four compression
calls for Extract and five for Expand, including the consumed key-pad length
in SHA-256 padding. These fixed fixtures verify encodings and call arithmetic;
they do not test uniformity, pseudorandomness or a quantum security bound.

The exact dependencies are hkdf 0.13.0, hmac 0.13.0 and sha2 0.11.0. The first
execution reused the previously hashed 38-package vendor closure, then built
the 14 packages selected by its new lockfile, entirely offline with Rust
1.98.1 and warnings denied. Both source checkouts, the private tools and vendor
inputs were rehashed unchanged. The complete driver took 40.143 seconds; its
commands retained their existing 900-second bounds.

For a separate portable replay, all files of those 14 locked dependency packages,
including licenses and Cargo checksums, were copied into a fresh fixture. Its
only configuration adaptation makes the vendor path relative. A new locked,
offline build reproduced the original 64-result stdout byte-for-byte and left
every input unchanged. The original and portable binary identities are retained
separately. Neither execution runs the whole SDK or establishes a new platform
qualification.

## Archive and reproduction

`CAPTURE.zip` contains the mathematical note and working derivation, pinned
product source and licenses, original fixture/configuration and command streams,
the complete portable fixture/vendor tree, upstream primitive-review identity
and all result readbacks. No dependency download is required to build the
portable fixture with an already available compatible Rust toolchain.

After extraction, enter `fixture/` so Cargo finds its local source configuration:

```sh
cd fixture
RUSTFLAGS='-D warnings' CARGO_NET_OFFLINE=true cargo run --locked --offline
```

The capture contains 746 members, all reread byte-for-byte. It is 1,876,497 bytes
with SHA-256 `1539de4cbd341df7400919a77fe8d8d15a0a7aa5a1647bf184def18b8424e416`.
`FILES.json`, `READBACK.json` and `SHA256.json` retain exact identities and scope.
No Tamarin search, hosted CI, release operation or external-review completion
is claimed from this record.
