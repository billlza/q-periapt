# Reuse the authenticated opening snapshot

The independent session's constructor previously entered the ordinary metadata
read/release path after its journal had already recovered and authenticated the
opening image. In a required-witness store that made three identical logical
head queries, each with its own fresh signature/challenge. Internal journal
factories now transfer the recovered snapshot directly into construction.
The constructor still decodes it, validates the authenticated local-renewal
control and closes on failure. It stores no snapshot cache or output permit.
Every operation retains its own original fresh-state, current-authority and
release checks. Public raw journal `create/open` still return only a journal.

The genuine native witness probe measures three queries before and one after,
with all four requests/replies independently signature-checked against their
original enrolled heads. That removes two exchanges and 14,682 bytes including
the four-byte request/reply framing per exchange. Fresh random inputs are used
in both runs. This is exact request/byte accounting, not a latency or energy
benchmark, and the probe releases no business output.

All fourteen runtime lanes and eight public readers pass on an identical
70-source closure. Versions five and six both assert a single opening Query.
The 36-worker witness lane records 266 native commands, versus 329 before this
change; the new dedicated opening assertion itself adds one command. Peer
renewal/revocation returns to 479 signed replies across its four unchanged
profiles. Local joint-renewal retains all 104 worker operations, 22 real kills
and 93 direct refusal executions, now with 384 valid signed replies across
386 distinct challenges. Its Applied/Closed/unprepared-close/ordinary-pending
boundaries, exact ciphertexts, rekey, expiry, cancellation and control-record
refusals remain intact. The reentrant final-reply test still withholds output
after revocation, with 48 genuine signed replies and five actual advances.

Python AST and diff checks pass. Native Rust sources, dependencies and the
ARM64 executable are unchanged from the qualified `061ff030` input set, SHA-256
`906ae3b314f5f840e2f02d056e9e17e0ffed14f6bd918414386c5da481e0db70`.
Its previous strict build/Clippy/format receipt is retained without recompiling
unchanged native code. The Rust census stays 725; no new CodeQL/prover or unchanged
performance run is claimed.

`CAPTURE.zip` contains both probes, all final public runtime records, eight
readers and outputs, current sources, four relevant pre-change sources from
`b5030724`, the unchanged executable and a verified manifest. It is 29,429,413
bytes with 9,328 members, SHA-256
`8b472157409dfdf4e7c2437e99f03f4816fd6a6949c7f7d0e13dae186b36774b`.
Private images, signing and wrapping keys are excluded; original private states
remain local. Public replay cannot rederive private MAC/AEAD or prove arbitrary
concurrency. This changes only independent-reference opening, not product ABI,
state format, installed lifecycle, power-loss/erasure guarantees, witness rollback
resistance or construction-wide PCS. Hosted execution for this optimization is
pending separately from the `061ff030` local-renewal matrix.
