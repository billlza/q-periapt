File written to `/Users/bill/Desktop/Desktop/q-periapt/docs/ROADMAP.md`.

Summary of what it contains:

- **Honest positioning header** — explicit "what we do NOT claim" (not faster than X-Wing/NIST primitives, no own FIPS validation, tracks-not-sets standards, no completed third-party audit), and the one genuinely defensible structural win (agility + assumption diversity, which X-Wing cannot do without forking) led up front per the nit fix.
- **Six milestones M0→M5** (Core/X-Wing parity → Side-channel CI → Context-bound profile + policy/sig → FFI/bindings → Transport+P99 → Formal models), each with concrete deliverables and measurable, checkbox exit criteria.
- **Requirement→milestone traceability table** mapping every blueprint requirement and every incorporated review fix to a milestone and its exit-criterion anchor.
- **Verification plan** broken out by technique (KAT / fuzz / dudect / ctgrind / static-symbolic / differential / cross-compiler-clangover / formal) with cumulative gating.
- **Formal-model scope** stated explicitly (EasyCrypt PQ-case + Tamarin symbolic in scope; classical ROM+SDH and full computational handshake out of MVP; "formally verified" not claimed for the suite).

Adversarial-review findings incorporated (all valid ones), with the honesty corrections that were load-bearing:
- **Critical fixes baked into milestones:** Profile-A 32-byte length validation (M0); `Kem::C2PRI` const + `assert_c2pri_or_bind_ct` guard forcing HQC/X25519 to Profile B (M0 hook / M2 enforcement); implicit-rejection cmov + no `?`-early-return in decap (M1); CT-coverage matrix replacing the blanket "every cell re-verified" claim (M1); per-backend CT attestation + "we select, not we audited" KyberSlash reframe (M1); real backends wired replacing `ToyKem`/`ToyXof` (M0); downgrade-floor + signed-policy fail-closed (M2).
- **Perf honesty:** demoted absolute cycle counts (1,774 / 12,586) to "blocks not cycles, TBD in M4 harness"; **removed the unsourced 8–10% X-Wing win** figure; clarified the hash delta is a small fraction of ML-KEM-dominated encap/decap.
- **Scope honesty:** P99 reframed from "where we win" to "where we refuse to mis-measure"; cross-platform win restated as reduced audit surface, not unique interop; ML-DSA rejection-loop carved out as an allowlisted benign leak; ctgrind "variable-latency detection" claim dropped; transport concatenation-vs-combiner layer separation + IND-CCA2 guard; FFI failure-path + `q_periapt_last_error_str` side-channel constraints; SLH-DSA 2²⁴ cap; `u64` LE prefix spec↔code reconciliation; toolchain/matrix pin reconciliation; fuzzing brought forward to M2.

The "accurate but no change needed" low/nit findings (X-Wing standards status, C2PRI rationale) are reflected in the positioning text as-is.