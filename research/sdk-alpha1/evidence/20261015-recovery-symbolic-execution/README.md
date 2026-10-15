# Unchanged-model normal execution witness

The existing protected-state theory now has a verified normal execution witness.
The trace places Cut before both fresh reservations, completes both endpoint
confirmations and then emits an application event, with no extra snapshot,
identity or entropy disclosure anywhere. It establishes that the modeled normal
path is non-vacuous; it does not establish recovery secrecy.

Interactive selection applies 32 proof methods to the original theory. The
checked trace follows actual offer, response, final and receipt signing rules,
then discharges knowledge of already public transcript values. No lemma-edit,
rule-edit or restriction-changing operation is used. The initial input remains
byte-identical to the committed model. Initial and final closed-theory exports
have identical rule/equation/restriction prefixes and all five full lemma
declarations, including quantifier kinds, annotations and formulas.

A new Tamarin 1.12.0 / Maude 3.5.1 process, with **no `--prove` flag**, replays the
exported proof methods and reports `recovery_is_executable` verified in 59 steps.
A further invocation on the same exact exported input proves
`generation_secret_origin` in 182 steps and retains the verified 59-step witness.
The three remaining queries report analysis incomplete and are not accepted:
recovery secrecy, pre-cut reservation exposure, and later-storage-access exposure.
The concrete SDK disclosure experiments retain their separate empirical status.

The executable certificate includes unselected lemmas and unexplored alternative
branches. The accepted existential claim needs one fully checked trace. It does
not discharge any all-traces claim. A missing-proof control removes the witness
methods while keeping all model declarations unchanged: Tamarin still exits zero,
but reports analysis incomplete, and the verifier rejects it. Six additional
controls reject a renamed required lemma, a changed quantifier kind, a new reuse
annotation, a changed signature equation, a changed formula and an extra lemma.

The first helper launch failed to import its local `client2` module before any
proof API mutation. A source-path wrapper then executes the unchanged helper.
This setup failure is separate from proof outcomes. The owned loopback server is
stopped, its PID is absent and its port refuses connections. No private SDK
cohort, device runtime or global tool installation is opened or changed.

The [model scope](../../../continuity-recovery-symbolic/README.md) remains narrow:
ideal KEM/hash/signature primitives, ideal protected-state confidentiality, and
one exchange per independently initialized pair. Shared multi-session journals,
concrete hybrid/HKDF security, exposed ML-DSA coins, real message chains/ACKs,
policy and lifecycle transitions, and Rust refinement remain open. The explicit
nested-encryption alternative is not proved by this witness. The earlier
automated timeouts remain in the [preceding checkpoint](../20261015-recovery-symbolic/README.md).
Manual witness construction does not establish a single root cause for all those
search failures, but it disproves the hypothesis that this normal trace is
unreachable in the unchanged model.

`CAPTURE.zip` contains 229 public members, SHA-256 `d0f05fb682d270a53c3e9287ff1b73841d0342409894a8756f1eac99471e2bcd`.
The replayed certificate is `proof/export-19.spthy`, SHA-256 `aac9974eb871cdecbec628e9e3d3f893ceddad7e74871497a0f0c43e2a469019`.
Archive readback verifies all member digests and final replay/control/cleanup
records. HTTP inputs and responses preserve the proof-method choices; generated
proof terms are evidence, not production implementation. The official arm64 tool
pins and successful fixed version/health contract are included.

The base source is `b31c8f9f5b197958e43b5fc2cf6e17ced64f8414`. Only research status
and evidence change. No protocol, runtime, primitive, wire, authorization or
release gate is weakened. The full 0.2.0 goal and current-source hosted checks
remain open.
