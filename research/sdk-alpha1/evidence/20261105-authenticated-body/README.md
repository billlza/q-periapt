# Conditional body-origin reduction and source correspondence

The [body-origin note](../../../../docs/continuity/AUTHENTICATED_BODY_LEMMA_V1.md)
states the precise single-target implication from an accepted, previously
unsigned purpose/body to a forgery under a chosen-rnd ML-DSA signing interface.
It gives the reduction, query/freshness rules, simulation-error term and the
conditions required for a guessed multi-user target. It does not establish
the underlying primitive assumption or Continuity's accepted-prefix simulation.

Eight relevant current source files match the already completed Release run
on source `4effa8b2b25e7403ab912b65894a7d1e73695542`, implementation
`f560d803c43a24fff222daa5e5e5bd623bfdf874`. They also match the qualification
checkout `ff072bd66b1f5d3bdbb80171ee39bad15cbc3c20`. Four `fips204` source files
were checked against crate 0.4.6, SHA-256
`c9fb5a367b9846933e271a3c2a992930743f82ae5e8cb7faa780715a80fa0b15`;
the crate manifest and both licenses accompany the excerpts. The source
inventory confirms 39 distinct purpose tags and the exact signing envelope.

The three reused passing tests cover the bootstrap classical-signature alias
and two final READY boundaries. `original-run/EXTRACTS.json` records their exact
line numbers and the four-control/four-alias marker, with full original stream
paths, sizes and hashes. `FORMAL_RELEASE_RESULT.json` is the original complete
run receipt. These are extracted observations from that run; the full streams
remain at their recorded local paths and no new runtime test was executed here.

This evidence shows why PQ body origin alone cannot establish original wire
origin after classical-key disclosure. It does not demonstrate a rekey attack.
Nonce-aware primitive security, the shared SHAKE/oracle correspondence, bounded
signer behavior, identity/authorization and whole-state simulation remain
explicit proof obligations. The working research notes preserve these gaps.

`CAPTURE.zip` has 24 members and 163,090 bytes, SHA-256
`e1b96c96e075986b04f83b077eeea3e5cf9685e649a7e7d6f37175e6b38232e0`.
Every member was reread byte-for-byte. `FILES.json` identifies all source,
dependency, note and receipt bytes. No product implementation, security claim,
protocol, external-review status or release status changed.
