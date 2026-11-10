# Positive recovery with shared wrapping keys

Status: **all 20 universal properties, including the original key-scoped recovery
formula, verify together in a fresh process without automatic proof search.**
The [shared-storage model](../../../continuity-recovery-symbolic/shared-storage.spthy)
and every complete query declaration are unchanged from the preceding checkpoint.
The final replay takes 739.706 seconds under the existing 900-second deadline,
12 GiB heap limit and one-thread setting, using Tamarin 1.12.0 / Maude 3.5.1.
The main theorem verifies in eight steps after all 19 dependencies have verified
in that same process. This is a scoped symbolic result, not release qualification.

The sufficient conditions remain:

- Both target KEM reservations occur after the target Cut.
- Neither actual target signing key is revealed or has its signer file captured
  anywhere in the trace. File capture is conservatively counted before decryption.
- No target-session generation or encapsulation entropy is disclosed anywhere
  in the trace.
- No acquired target revision was saved after Cut. Other-session captures and
  unrelated identity disclosure remain permitted by the formula.

Signing keys and wrapping keys can be reused independently in either role across
unbounded sessions. Captured records use explicit perfect symmetric encryption;
signer-file encryption uses a purpose-separated hash abstraction of its KDF.
The result no longer assumes wrapping keys are independent for every session or
that unsealing is gated by a session-local disclosure flag.

The earlier monolithic search reached its deadline, and reusing old scripts left
ten properties incomplete. This checkpoint searches independent groups and then
replays their complete composition. Five causal properties, eight provenance and
authentication properties, one root-constructor property and two storage-timing
properties supply the previously missing proof bodies. Four earlier conditional
scripts become admissible only after this complete 20-property replay. The
encapsulation-derivation lemma precedes the two root-authentication lemmas to
preserve their checked component scope; full declarations and the main formula
are unchanged. Four unused legacy existential placeholders remain incomplete and
are not premises of the universal result.

A separate witness,
`shared_device_identity_and_storage_recovery_is_executable`, verifies in 47
search steps and 168 independent replay steps. The same target initiator identity
and wrapping key are used by the sibling responder. Three distinct identity keys
and three distinct wrapping keys are required. The sibling commits a signed
response, and both target peers confirm before the target application message.
Both target reservations follow Cut, with no identity, entropy or snapshot
disclosure. Exact formula/model readback and independent proof replay validate
this existential statement; no large diagnostic graph is exported. It shows
that these combined-owner premises permit actual protocol steps, not secrecy by
itself. The earlier 85-step sibling-wrapping-key attack is carried byte-for-byte
from the [prior archive](../20261015-recovery-shared-storage/README.md), on the same
unchanged operational model; it was not rerun in this checkpoint.

Four parser-valid mutations are rejected: deleting the main theorem, excluding
all identity disclosure instead of the actual target key, reverting to independent
wrapping-key allocation, and adding a late snapshot-prohibition restriction.
A separate unchanged-formula control removes the record-origin proof: exit zero
and a verified downstream timing property still fail admission when that helper
is incomplete.

Terminal GHC statistics report 545.557 seconds of garbage collection out of
739.532 elapsed seconds, with 11,447,976,656 bytes maximum residency and 12,481 MiB
total memory in use. These are prover costs on this host, not SDK performance
measurements. The short native sample lacks useful symbols; it does not identify
a GC function. Attribution comes from the terminal RTS statistics. Resource
limits were not raised, and hosted Linux qualification remains required.

The projection still performs one exchange per session with freshly sampled,
publicly revealed initial roots. It assumes perfect cryptography and honest
signing randomness. Whole-journal AEAD image/restore correspondence, arbitrary
inherited-root correlations, multiple epochs, concrete HKDF/AEAD/hybrid and
known-signing-coins security, SDK refinement and external review remain open.
This establishes no general bound on exposed messages/epochs or recovery after
target identity disclosure.
No runtime recovery flag follows from the unobservable disclosure conditions.
The existing two CI profiles have not yet been extended to this new certificate.

`CAPTURE.json` records all member digests and the accepted proof/control receipts.
`READBACK.json` records a complete readback of all 148 members. The archive is
499,850 bytes; SHA-256:
`9655446a492219424eee05614fd2b4589072e07c07293dc92323bbefb170c0be`.
All retained inputs are public symbolic material. Private device and SDK test
cohorts remain sealed.
