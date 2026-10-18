# Independent volatile bootstrap checkpoint

An independent Python/OpenSSL initiator and the actual Rust candidate responder
complete all three bootstrap flights with fresh keys and randomized signatures.
They independently construct identical 492-byte prekey selections and bootstrap
context digests. The Python side signs and encapsulates the initial flight,
verifies and decapsulates the Rust reply, and emits the final confirmation; the
Rust responder verifies that confirmation. Both retain the same session ID.

The retained final run uses hash-pinned PyPI wheels: cryptography 48.0.1 with its
OpenSSL **4.0.1** provider. The earlier runs against the locally built package
reported OpenSSL **3.6.4**. These are separate observed provider configurations;
the CI workflow uses the pinned wheels. All runs and the actual final Rust
executable are in `CAPTURE.zip`; no private key or combined secret is recorded.

The final run executes ten native commands and 35 Python refusal controls. A
correctly signed initial carrying a changed ML-KEM ciphertext fails actual Rust
confirmation, after which the original initial remains usable. A separate
synthetic verification-key seam tests valid dual signatures with an invalid
responder MAC; it cannot finish or yield a pending session. The real exchange
also rejects independent ML-DSA/ECDSA corruption, high-S aliases, truncated and
extended envelopes, changed trust pins, bad proofs, expiry and closed owners.
Exact initial/final retransmissions retain the original bytes, while conflicting
replays fail. Public native input/output control frames are retained and their
recorded hashes and statuses were read back independently of execution.

The native counterpart builds and passes Clippy with `-D warnings`; format and
workflow lint pass. Its 116 external registry versions/checksums match the
candidate lockfile. The first lockfile-generation attempt selected newer
dependencies and was deliberately stopped with exit 143. That rejected lock and
build log remain retained; the corrected build reuses the original dependency
versions. The new native source is mandatory in the exact 720-file Rust inventory;
all 46 quality-gate tests pass against a snapshot of those actual source bytes.
No new CodeQL database/query execution is claimed.

The code and run instructions are in
[`continuity-openssl-peer`](../../../continuity-openssl-peer/README.md).
`CHECKS.json` records source, provider and executable hashes and the capture
digest. The prepared Linux x86_64/Apple Silicon workflow has not yet qualified
this source at capture time.

This closes only the first independent **volatile bootstrap** experiment. It
does not close independent durable sessions, traffic, rekey, witness, renewal,
revocation, installed packages or the 0.2.0 release. Python temporary bytes have
no zeroization guarantee, and the fixed test trust ceremony is not operational
enrollment. No root-export test hook was added to the Rust product interface.
