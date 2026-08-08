# Formal proof plan — ContextBound binding (EasyCrypt)

This directory holds the proof that is the project's actual **mathematical**
contribution. Per `docs/BINDING_SECURITY.md`, the defensible delta vs X-Wing is
**stronger proof coverage / minimal assumptions** (and the *mechanization
itself*), **not** a stronger primitive. Read `BINDING_SECURITY.md` first; this
file is the engineering plan for §4.

This proof covers a combiner binding game only. It does not model identities,
prekeys, replay, ratchets, FS/PCS, multi-device state, recovery, or persistence,
and it is not a spec-to-Rust refinement. The future Q-Periapt Continuity work has
separate protocol, storage, and implementation-linkage gates in
[`../../docs/CONTINUITY_RESEARCH.md`](../../docs/CONTINUITY_RESEARCH.md).
The `publish = false` lifecycle model under `models/` is finite executable testing.
Its separate [`continuity`](continuity) diagnostics prove only LP8 projection
injectivity and explicit Lifecycle policy/direction plus named prekey-field omission
collisions. The hermetic CI image now compiles both diagnostics from scratch alongside
the paper proof, but they remain non-normative. They prove neither SHA3 injectivity nor
a protocol theorem or model-to-Rust refinement and do not enlarge the paper's
ContextBound contribution.

## Independent migration hard gate

[`MigrationBindingV2.ec`](MigrationBindingV2.ec) is a separate proof artifact for
the Migration Contract V2 KDF boundary. It proves projection injectivity from
the exact 13-field V2 M0..M12 projection to the authenticated state identity
`(committed_epoch, committed_state_digest)`, then proves
`MIG-BIND-K-STATE`: equal non-bottom accepted keys for distinct state identities
reduce to a collision in the modeled KDF/hash `H`. Its
`omitted_state_negative_control` is an explicit probability-one winner when both
state-identity projections are removed.

The stronger full-state theorem models the exact 12-field canonical
`MigrationStateV1` body committed by V2 M10 and a separate state hash
`H_state`. `mig_bind_k_full_state_bad_event_decomposition` proves that equal
non-bottom accepted keys for different full-state bodies imply either an outer
context collision or a state-digest collision, yielding the union bound
`Adv_CR(H_context) + Adv_CR(H_state)`. Transition-signature EUF-CMA remains a
separate protocol assumption.

This model starts with abstract byte strings supplied to the KDF. It does not
prove equality of digest preimages, concrete Rust serialization, signatures,
persistence/crash behavior, IPC behavior, protocol acceptance, Lean refinement,
or specification-to-Rust/model-to-byte refinement. It is not a proof about the
existing 315-byte phase-1 V1 context. V2 uses the distinct domain
`Q-PERIAPT-MIGRATION-CONTEXT/v2` and the unsigned-u16 big-endian schema bytes
`[0, 2]`. A checked constant-mapping lemma prevents width drift in the formal
projection. Those remain separate gates.

## File: [`BindingViaCR.ec`](BindingViaCR.ec)

Formalizes `bind_le_cr`: a generic transcript-projection collision bound for the
ContextBound combiner, reducing **only** to collision-resistance of the hash with
no binding assumption on ML-KEM / X25519. Its ciphertext/public-key projections
instantiate the standard **MAL-BIND-K-CT** and **MAL-BIND-K-PK** notions. A separate
context projection gives a self-defined
context-parameterized **MAL-BIND-K-CTX** syntactic extension. K-CTX is outside the
published CDM lattice and does not inherit CDM monotonicity. The load-bearing
step, `encode_inj` (injectivity of the fixed-width length-prefixed encoding), is
**proved** (the encoding is modeled concretely and its injectivity machine-checked),
not assumed — mirrored by the Rust negative-KAT in `q-periapt-core`.

> **STATUS: MACHINE-CHECKED.** ✅ `make check`
> (`easycrypt compile -no-eco BindingViaCR.ec`) passes
> with EasyCrypt dev (OCaml 5.4.1) + Z3 4.16.0. `bind_le_cr` is verified. Honest
> scope still applies (`BINDING_SECURITY.md` §5/§6): `encode_inj` is now a **proved
> lemma** (the encoding is modeled concretely and its injectivity machine-checked,
> reducing to two elementary facts about an 8-byte length field; mirrored by the
> q-periapt-core negative KAT), H's collision-resistance is an assumption, IND-CCA2
> robustness is argued on paper (not mechanized), and there is no spec↔implementation
> linkage proof.

```sh
make check   # checks required names, then compiles both root proof files
```

### Pinned-source container check (the CI hard gate)

The [`formal/Dockerfile`](../Dockerfile) pins the base image manifest and the exact EasyCrypt commit
the proofs check under (`r2026.06`, commit
`50ae51d106dfb6611235f4a8bb7f46275d34a38d`). The `formal-easycrypt` CI job re-runs the proof
**and** its proof-dependency regression controls inside that image as a **hard gate** — if
`BindingViaCR.ec` stops checking, or an expected proof-script dependency changes, CI fails.
Debian apt metadata and the transitive opam solver graph are not snapshot-pinned, so this is a
pinned-source container gate, not a hermetic or bit-reproducible toolchain. Reproduce it locally:

```sh
docker build -f formal/Dockerfile -t q-periapt-ec .
# Mount read-only, copy into a container-owned directory, remove any local generated
# outputs, and re-check both root proofs, all seven dependency controls, and both
# continuity diagnostics from source. `.eco` files and the control log are ignored
# local outputs and are not committed evidence.
docker run --rm -v "$PWD/formal/easycrypt:/src:ro" q-periapt-ec \
    opam exec -- sh -c 'mkdir -p /tmp/ec && cp -r /src/. /tmp/ec && cd /tmp/ec \
        && rm -f *.eco continuity/*.eco negative-controls.log \
        && EC=easycrypt make check && sh negative-controls.sh \
        && EC=easycrypt make -C continuity check'
```

The historical `negative-controls.sh` filename is retained because the CI entrypoint invokes it.
Its controls remove named facts from selected `smt()` hints and verify that the current edited
proof script no longer compiles. They are **proof-dependency regression controls**, not logical
necessity proofs: failure of an automated tactic is not a counterexample. Semantic necessity is
claimed only where `BindingViaCR.ec` contains an explicit checked counterexample. In particular,
`kctx_without_nonbottom_broken` constructs two rejecting executions with distinct contexts and
proves a probability-1 win when the explicit-rejection game omits `K != bottom`. The file does not
currently contain a corresponding semantic countermodel for removing the `jrej_inj` idealization;
the script's J-related controls establish only that the present reduction scripts use that axiom.

## Tool

**EasyCrypt** — the only viable choice: the reusable ecosystem is all in EasyCrypt.
SSProve/Coq, Lean, CryptHOL have no PQ-KEM/binding artifacts.

Reusable artifacts to audit **before** committing (go/no-go gate):
- `sandbox-quantum/EasyCrypt-KEMs` — mechanizes CDM binding notions; confirmed to
  prove **`LEAK-BIND-K-PK` for ML-KEM** (scope the thesis to what is actually
  importable; the `MAL` game / monotonicity edges may need rebuilding).
- `formosa-crypto/formosa-mlkem` — verified ML-KEM IND-CCA (ePrint 2024/843).
- `formosa-crypto/formosa-x-wing` — **WIP** X-Wing IND-CCA proof. Do **not** take
  its completion as given.

## The single committed theorem (MVP success criterion)

> **`MAL-BIND-K-CT` for ContextBound, reducing only to collision-resistance of
> SHA3-256** (no binding assumption on ML-KEM or X25519).

Structure (the load-bearing, novel half):
1. Model SHA3-256 as collision-resistant (game `CR`, advantage `Adv_CR`).
2. **Injective-encoding lemma**: the fixed-width-BE length-prefixed concatenation
   over the canonical field order (`docs/BINDING_SECURITY.md` §3.2) is injective
   on the field tuple. Finite/combinatorial; low risk. This is the step the whole
   reduction hinges on, and it matches the implementation in
   [`q_periapt_core::combine`](../../crates/q-periapt-core/src/lib.rs) (`Profile::ContextBound`).
3. **Reduction**: two transcripts with `K0 = K1`, agreeing CT-set, differing in
   some element ⇒ either equal hash inputs (contradicting injectivity) or a SHA3
   collision. Bound: `Adv_MAL-BIND-K-CT ≤ Adv_CR`.

`MAL-BIND-K-PK` and the syntactic `MAL-BIND-K-CTX` extension follow by the identical
collision-reduction structure (each is another injectively-encoded absorbed field).
The standard CT/PK joint / `LEAK` / `HON` corollaries follow by CDM monotonicity;
that statement does not extend to K-CTX. These are **stretch**, not the
committed deliverable.

## What we explicitly do NOT mechanize

- **IND-CCA2 robustness** — argue on paper from the GHP18 combiner result and the
  published X-Wing IND-CCA proof; the extra hashed inputs do not break the
  reduction. Mechanizing it depends on the WIP `formosa-x-wing` and is high-risk.
- A verified-implementation linkage (abstract spec ↔ Rust) — out of scope.

## Declared assumptions / trust base

Collision-resistance (and, for the KDF, PRF/ROM) of SHA3-256/SHAKE-256; ML-KEM-768
IND-CCA and X25519 strong-DH (ROM) **only** for the IND-CCA paper argument — the
binding theorems assume **none** of these. FIPS 203 64-byte seed `dk` with import
validation is a spec requirement, not a proof dependency.

## Honest effort (single doctoral student)

Budget **8–12 weeks of EasyCrypt ramp-up before any thesis-specific proof**. Then
target the **one** committed theorem (`MAL-BIND-K-CT` via CR). Treat K-PK, K-CTX,
monotonicity corollaries, and the Tamarin protocol-motivation model as stretch.
Do not plan four parallel mechanization tracks.

## Open questions to resolve against primary PDFs first

- ePrint **2026/140** "On the Necessity of Public Contexts in Hybrid KEMs: A Case
  Study of X-Wing" — overlaps the public-context problem. Treat novelty/priority as
  an open literature-review item; do not call the local wrapper a CDM axis.
- ePrint **2025/1416** (generic hash-combiner binding, Thm 4) and **2025/1397**
  ("Starfighters", QSF generality) — confirm exact bounds / any combiner-level
  notion X-Wing fails before publishing the comparison.
