Wrote `/Users/bill/Desktop/Desktop/pqt_hybrid_suite/docs/COMBINER_SPEC.md`.

It is the authoritative byte-exact spec of both combiner profiles, written against the actual code I read in `pqt-core/src/lib.rs`, `pqt-kem/src/lib.rs`, `pqt-policy/src/lib.rs`, and `docs/policy/default.policy.toml`.

Key contents:
- **Profile A (CompatXWing):** exact `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)`, 32+32+32+32+6 = **134 bytes**, one Keccak block (rate 136), label `5c 2e 2f 2f 5e 5c` = `\.//^\`. Includes the mandatory 32-byte length-validation fix and the C2PRI guard requirement.
- **Profile B (ContextBound):** GHP/QSF split-key-PRF over `DOMAIN ‖ profile ‖ LP(suite_id) ‖ LP(profile_id) ‖ LP(policy_version) ‖ LP(ss_i…) ‖ LP(ct_i…) ‖ LP(pk_i…) ‖ LP(transcript) ‖ LP(context)`, with `LP(x)=LE32(len)‖x`.
- **Length-prefix reconciliation:** spec fixes the canonical width at `u32`/`LE32` and flags that the current code emits `LE64` (gap #4) — code and EasyCrypt model must match.
- **IND-CCA binding arguments** for both profiles, with honest scope (PQ standard-model EasyCrypt MVP; classical ROM+SDH and full handshake out of scope).
- **Test-vector plan:** ~25 KATs across positive/negative/binding/CT/cross-platform/differential, each with explicit pass conditions.

Honesty fixes incorporated from the adversarial review:
- Demoted the `~1,774` / `~12,586` cycle figures and `~7x` / `8-10%` numbers to "estimates, measured in M4"; reframed the Profile B cost as **9–10 Keccak permutations vs 1**, explicitly *hash-only* and a small fraction of ML-KEM-dominated encap/decap.
- Per-(backend,arch) CT-coverage matrix instead of a blanket binary-CT claim; HQC marked known-leaky; ML-DSA rejection-sampling as an auditable carve-out; dudect ≠ assembly-CT proof.
- Transport vs standalone never conflated (0x11EC concatenation, ML-KEM-first ordering, no ciphertext mixing).

A **Conformance gaps (§11)** table maps every spec requirement to the exact divergence in current code (line numbers included) with severity, so KATs can be written against the spec and the gaps are tracked rather than silently claimed as done.