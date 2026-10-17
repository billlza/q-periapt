# Two additional derivation-related CodeQL dispositions

This record reviews results **709 and 710** (zero-based SARIF indices, not
GitHub alert IDs) from the retained 809-result Rust analysis at
`67e1a5b03bf263ab175bc2261e4b70413ce8d79f`.

* Result 709 starts at the integer zero in a checked transcript-size fold.
  That sum is passed to a staging-buffer reservation hint. It is not absorbed
  into the cryptographic transcript or assigned to a bootstrap nonce. All four
  supplied paths and all three named nonce sinks were checked. Those sinks use
  the private plan's nonce, generated through `getrandom` during reservation
  or restored from the authenticated retained plan. This disposition does not
  prove arbitrary nonce uniqueness or compromise recovery.
* Result 710 correctly identifies the fixed public HKDF salt. That is an
  intentional version-1 protocol constant, not a hard-coded operational secret.
  The derivation applies both extract and expand to the combined KEM secret.
  Its security assumption is pseudorandom KEM input, not weak/password input;
  the fixed salt provides neither fresh entropy nor peer authentication.
  [RFC 5869 sections 2.2 and 3.1](https://datatracker.ietf.org/doc/html/rfc5869#section-3.1)
  permit use without random salt and describe stronger extraction properties
  from suitable random salt. Changing the constant changes protocol outputs.

The 11 source files covering all supplied paths, the concrete staging backend
and nonce construction are byte-identical between the analyzed commit and
`8ccc7aec088bf4e3fd62a9176fe7b81d1ef96558`. Raw selected results, every supplied
flow, source identities and complete inspected files are in `CAPTURES.zip`.
`DISPOSITIONS.json` states the individual reasons and remaining scope.

On that current source, the explicit private Rust 1.98.1 toolchain ran
`cargo test -p q-periapt-sdk --locked --offline --lib purpose::tests:: -- --nocapture`
with `RUSTFLAGS=-D warnings`: **2 passed, 0 failed, 21 filtered**. These are the
existing RFC 5869 Appendix A.1 and independent-HMAC framing/domain tests;
no new regression or whole-protocol proof is claimed. The source's version-1
key-derivation documentation now explains the fixed-salt boundary. Product
implementation and protocol bytes are unchanged.

Together with the preceding seven-result scoped review, **9 distinct results
have dispositions and 800 remain without completed dispositions** in this exact
809-result analysis. The earlier 780-result analysis and any later CI analysis
have separate identities and counts. There was no remote dismissal, query
suppression or passing aggregate security claim.
