# Shared-root HMAC reduction and encoding correspondence

The [conditional security note](../../../../docs/continuity/SHARED_ROOT_HMAC_V1.md)
now treats a uniformly hidden 32-byte value used in both HMAC input positions,
with one ideal compression oracle. Each reduction retains the other interface;
the final table preserves aliases of the public salt-state pair. An independent
internal applicability review checked the original DFH and Hosoyamada–Iwata
statements and the complete simulations. Its initialization and message-length
clarifications are incorporated in the note. This is neither external review nor
the actual accepted-prefix or multi-epoch protocol proof.

The source correspondence uses clean qualification commit
`ff072bd66b1f5d3bdbb80171ee39bad15cbc3c20`. The five relevant candidate source and
lock files were identical to MAIN before and after execution. The actual pinned
`hmac 0.13.0`, `hkdf 0.13.0` and `sha2 0.11.0` libraries were compiled in an
isolated fixture. Its dependency closure was supplied offline from original
registry archives: each archive's SHA-256 matches the candidate lock, and each
member matches the existing registry source bytes. No dependency was upgraded.
The fixture selected 14 dependency packages from that pinned closure; exact
checksums and source-file manifests are retained.

The executed comparison covered four synthetic roots and message lengths
`0, 1, 31, 32, 55, 56, 63, 64, 65, 119, 120, 127, 128, 1024` bytes:

- All 56 row evaluations matched the explicit compression construction with the
  64-byte key-pad length offset. All 56 deliberately unshifted constructions
  differed, demonstrating that the check detects that encoding mistake.
- All 16 salt/root column evaluations matched both HMAC and HKDF-Extract.
- Four shared root/root input pairs retained exact equality, and four absent-salt
  calls equalled the explicit 32-byte zero salt.

`cargo generate-lockfile --offline` and `cargo run --locked --offline` exited
zero under the existing 900-second command limit and `RUSTFLAGS=-D warnings`.
The retained Cargo output passed the unchanged warning validator. The successful
preparation, build, execution and final source/tool readback took 32.496 seconds;
the build itself reports 2.26 seconds. The executable SHA-256 is
`074a4f9395b5f9cee7f781bcefca467c0bf6085d43cb1d99005e503e4d020b19`.
Finite evaluations substantiate this byte correspondence, not computational
security or the ideal-oracle premise.

Three preparer failures are retained. First, the strict source guard rejected
MAIN's pre-existing bytecode and untracked source inputs; the fixture was then
bound to the actual clean qualification clone, with explicit file equivalence.
Second, the preparer incorrectly expected vendor checksum metadata in a Cargo
registry extraction. Third, the SDK-specific archive reader required inputs
that arbitrary registry crates need not contain. The final isolated vendor
reader verifies the original pinned archives, safe regular members and normalized
package identity. None of these failures reached a Cargo command or encoding
test; no product validator, source or assertion was changed.

The frozen draft hash is
`839074528e9e972289838ad18b13be5891e6beba232488c08b3cd233055b309b`;
the internal review hash is
`cd74b4205630c467c93aae47aa30cbe82dccfa1f89c01d1232be0f80b56b66f2`.
The final note states joint product initialization, counts all oracle-dependent
preparation, and includes `8*(64+L)<2^64`. It identifies the bound as Real/J
output probability, with no hidden-root disclosure or numerical security-bit
claim from unspecified asymptotic constants. The integrating review checked the
primary statements, padding, query budgets, full-domain permutation, salt aliases
and classical exceptional-query coupling; it did not independently reproduce
the cited papers' complete compressed-oracle proofs.

`CAPTURE.zip` retains the draft, review, final note, source snapshots, exact
fixture source and lock, successful command streams, preparer failures and
assessment. All 38 members were reread byte-for-byte. The ZIP is 153,607 bytes,
SHA-256 `f496ddcd4c93c58955f638c543344d2224dde93776c2be054adc8bb812545743`.
Third-party source archives, compiled dependencies and the papers are not
redistributed in this capture. Their identities and original source links are
recorded for reproduction. No release or product security assumption was changed.
