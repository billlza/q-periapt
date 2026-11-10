# Retained second offer under asymmetric confirmation

A fresh implementation experiment holds the first rekey receipt while its
responder commits the next offer. At capture, the initiator's public progress is
`(confirmed=0, send=1, receive=0, pending=1)` and the responder's is
`(confirmed=1, send=1, receive=1, pending=2)`. The responder's committed phase-3
offer still retains its generation token. Both public progress records and the
exact second offer survive honest restart.

One captured responder state supplies its epoch-one root, journal identity,
wrapping key and retained token. No initiator snapshot, signing owner, future
root, traffic key or later private state is passed to the predictor. The honest
peers then receive the delayed receipt, finish epoch two and restart. The
predictor receives public offer/response wires and actual ciphertext. It
successfully decrypts six newly generated random 128-byte application payloads,
three in each direction; it is not given the expected plaintext as input. A
wrong wrapping key returns `InvalidPrivateKey`. The experiment uses real SDK
sealed-operation replay, the documented KDF and independent traffic owners.

This is a constructive counterexample to an exposure bound defined as the
smaller confirmed epoch plus one. That bound is one at capture, yet epoch-two
traffic is reconstructible. Asymmetric progress is legitimate protocol behavior;
no production transition was changed. This does not establish a maximum exposure
bound, epoch-three secrecy or full-device compromise recovery. In particular,
the predictor's single snapshot excludes signer files; the same wrapping key
plus an encrypted signer file would expose identity authority too.

The [dependency analysis](../../../../docs/continuity/RECOVERY_DEPENDENCIES_V1.md)
maps all ten plan phases and identifies phase 8's advanced root despite its
lagging confirmed counter. That table is a source review, not an executed attack
at every phase. It also separates encapsulation reservation ancestry, retained
traffic, identity material and future access to encrypted images. Construction-
specific KEM, HKDF, authentication and lifecycle proof obligations remain open.

Qualification uses base `ed95b1b0a6ea688b7359d4b1673bd33f4173a42d` plus the captured
test-only patch. The original two reservation tests still require epoch one,
real process-kill cuts and six recovered messages each; all states in this run
are newly created. Their shared traffic checker now takes an explicit expected
epoch, preserving the original assertions while checking epoch two separately.
No failed or accepted historical private cohort is reopened.

Actual commands use Rust 1.98.1, offline locked dependencies and `-D warnings`:

- `cargo test --locked --offline --manifest-path research/continuity-identity-candidate/Cargo.toml --lib --all-features durable::messages::tests::reservation_disclosure:: -- --nocapture`: 3 passed, 0 ignored; 18 actual decryptions across three fresh cases.
- The same command filtered to `control_progress::`: 5 passed, 0 ignored.
- The same command filtered to `send_budget::`: 7 passed, 0 ignored.
- `cargo clippy --offline --locked --manifest-path research/continuity-identity-candidate/Cargo.toml --all-features --all-targets -- -D warnings`: passed.
- `rustfmt --edition 2021 --check` on the changed test file: passed.

The full argv, tool paths, stdout and stderr are retained. The complete library
suite was not rerun for this test-only change; current package/device acceptance
remains scoped to its recorded sources, and hosted security checks are separate.
No before/after bug-fix claim is made: this experiment records behavior of the
existing protocol rather than changing it to satisfy a new expectation.

`CAPTURE.zip` contains 36 members, including exact reviewed sources and
public command receipts. Its SHA-256 is `8d5423aa16f7bc2d5738e590fca3b70cfc18524576cae232c204ae57d596cda5`.
Independent archive readback verifies each member digest, all three exact
experiment markers and 15 passing tests. Capture selection is an explicit source
and public-receipt allowlist; no private runtime store or key is included.
This checkpoint is not release qualification.
