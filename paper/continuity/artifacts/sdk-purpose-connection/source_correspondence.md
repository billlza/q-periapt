# Native owned purpose-key derivation and the finite entry table

Source pin: `228c944fc476e3e57d6c08063cacb19bca5b360e`.

This research instantiates the finite entry-table proof with an existing SDK workload: one ContextBound `SharedSecret` produces several purpose keys through `SharedSecret::derive_key`. The actual SDK information strings have variable lengths, and its returned key objects have independent liveness. The companion `sdk-purpose-connection.tex` supplies the required length-parameterized table lemma, a native owned-API correspondence proposition and a conditional single-key application consequence. The existing durable 97-byte root theorem retains its original source scope.

## 1. Selected source workload

The public Rust call sequence already supported by the pinned SDK is:

1. Admit a runtime from its signed policy and pinned trust root.
2. Generate a recipient key and encapsulate to it with an application context; the result contains an owned `SharedSecret`. The peer may decapsulate the same ciphertext and context to obtain its corresponding owner.
3. On one source owner, call `derive_key` for the five declared purposes, using a protocol label and application context. A source may be used again with the same complete inputs or with different available inputs.
4. Export a derived key for the application's cipher/MAC, close individual derived/source owners, or close a runtime. Each operation preserves the actual object and runtime checks.

The existing Rust test `purpose_derivation_agrees_across_peers_and_revokes_with_its_runtime` runs this five-purpose sequence on both peers (`crates/q-periapt-sdk/src/tests.rs`, lines 763–812). Its label is `app/v1/aes256` and its context is `authenticated-transcript`. The Android native SDK smoke consumer also performs the same two-peer, five-purpose fanout for context lengths 0, 32 and 65536 (`bindings/android/smoke/sdk/dev/qperiapt/androidsmoke/QPeriaptSDKWorkload.java`, lines 75–98).

These source programs establish an actual multiple-output call surface. The Rust test exports keys to compare its fixtures; its role here is source evidence for functional and ownership behavior. The cryptographic result below follows from the reduction.

An additional source test signs the same policy document under another trust root, obtains equal ContextBound secrets for equal deterministic KEM inputs, and derives different fixture purpose keys because the complete SDK info includes the runtime root digest (`tests.rs`, lines 857–897). The general theorem concerns exact effective info bytes and retains the possibility of numeric key or digest collisions.

## 2. Complete SDK encoding

The relevant implementation is `crates/q-periapt-sdk/src/purpose.rs`.

### Extract salt

The HKDF salt is the exact ASCII string

```
QPeriapt-SDK-HKDF-SHA256-v1
```

It has 27 bytes. Define its canonical 32-byte representative

\[
r_0=\sigma\Vert\mathtt{00}^5.
\]

Both HMAC keys produce the same 64-byte zero-padded key block. Hence, with the same compression oracle and every message `m`,

\[
\operatorname{HMAC}(\sigma,m)=\operatorname{HMAC}(r_0,m).
\]

This is pointwise equality of both inner and outer pad blocks. It introduces no entropy or distinguishing term. The padding convention is the HMAC definition in RFC 2104, Section 2; the retained primitive appendix writes the corresponding 32-byte-key pad blocks explicitly.

### Information fields

The SDK passes these components, in order, to `expand_multi_info`:

| Field | Actual encoding | Width |
|---|---|---:|
| Domain | `QPeriapt-SDK-Key-v1` | 19 |
| Suite | big-endian `u32(1)`, fixed ML-KEM-768+X25519 | 4 |
| Profile | big-endian `u32(2)`, ContextBound | 4 |
| Policy state | version BE32 followed by exact-document digest | 36 |
| Trust root | SHA-256 of the pinned verification-key bytes | 32 |
| Purpose | closed enum code BE32, one of 1–5 | 4 |
| Label length | BE16 | 2 |
| Label | exact input bytes | 1–255 |
| Context length | BE32 | 4 |
| Context | exact input bytes | 0–65536 |
| Output length | BE16(32) | 2 |

`TrustedPolicyState::encode` supplies the 36-byte state (`crates/q-periapt-policy/src/lib.rs`, lines 159–199). The runtime computes and retains its trust-root digest during verified construction (`crates/q-periapt-sdk/src/lib.rs`, lines 245–307). Both are available authenticated metadata of the caller's runtime; their actual preparation remains counted.

For label `a` and context `c`, the complete concatenation `I` has length

\[
|I|=107+|a|+|c|,
\quad108\le |I|\le65898.
\]

Since the output has 32 bytes, HKDF uses its first Expand block:

\[
P=F(r_0,S),\qquad K_I=F(P,I\Vert\mathtt{01}).
\]

Its row message has length 109 through 65899. With the retained convention

\[
\ell(L)=1+\left\lceil\frac{L+9}{64}\right\rceil,
\]

the full SDK maximum gives `ell(65899)=1031`, or 1033 compression calls for a fresh HMAC evaluation when its two key pads are included.

The five-purpose native fixture has label length 13 and context length 24. Its info length is 144, its HMAC message length is 145, and `ell(145)=4`.

### Exact descriptor and parsing

The key-table descriptor is

\[
e=(\Gamma(r_0),I).
\]

For this SDK schedule the salt class is constant, so the effective varying index is the complete `I`. The fixed-width fields and the two length fields provide a unique parser. The final two bytes encode output length 32. Every successful source call supplies exactly this encoding.

An owner ID, source-pointer identity, runtime pointer or original reservation ID remains separate provenance/lifecycle metadata. A runtime's actual policy-state and root-digest bytes are fields of `I`. Two runtimes with equal effective metadata and the same purpose/label/context therefore share the same key entry for a common protected contribution, while each runtime retains its own revocation state. A collision of raw trust-root digests is represented by equality of that effective field.

## 3. The available owned-API controller

### Protected source family

The entry experiment starts with one uniform protected contribution `S`, initially independent of the public compression oracle and auxiliary state. It may be represented by several native `SharedSecret` owners, such as the two matching peers. Each carries its actual runtime and local open/closed state. The family identity records their common protected source; it is determined by the chosen provenance/combiner interface, with the common value represented by that provenance.

The contribution has its declared purpose-derivation interface. Internal Extract material remains within HKDF. Known independent contributions and their native computations can be present in the surrounding controller; their oracle work is included in its budget.

The controller can choose future purposes, labels and contexts adaptively using available data: public policy bindings, prior returned values, native lifecycle/status responses, its independent coins and public oracle computation. It preserves the native order of input checks and admission. Every game evaluates this code on its own trace.

### Two tables with different jobs

The correspondence retains both:

| Table | Identity | Contents |
|---|---|---|
| Cryptographic key table | Protected family and full effective info `I` | One key value or protected application-key handle |
| Native owner table | Actual Rust object or FFI owner ID | Source/derived kind, runtime, live state, publication state and reference to its key entry |

A successful repeated derivation creates another native owner whose key reference is the existing descriptor entry. All native allocation and admission events still occur. The deterministic KDF value can be memoized in the reduction because its repeated evaluation has the same fixed-oracle result.

### Exact lifecycle transitions

The source facts are direct:

- `SharedSecret::derive_key` borrows `&self`, takes `State::begin`, checks its `inner` field, validates the inputs, computes the key and creates a new `DerivedKey` with its own `Option<ZeroizingBytes<32>>` and a clone of the runtime `Arc` (`purpose.rs`, lines 125–155).
- `DerivedKey::export_for_protocol` checks the runtime and its own `bytes` field, then copies 32 bytes. Its export check does not take an in-flight operation lease (`purpose.rs`, lines 56–74).
- `DerivedKey::close` clears only that object's `bytes` field. Equal-info siblings retain their own fields.
- `SharedSecret::close` clears that source object's `inner` field. Already derived owners have their own key storage and runtime reference (`lib.rs`, lines 539–558).
- `Runtime::close` sets the shared runtime closed flag. Later open checks fail. A derivation that has passed its final admission check, or an export that has passed its open check, follows its actual completion path. Existing exported copies remain recipient-owned (`lib.rs`, lines 176–198 and 320–325).
- `DerivedKey` contains no `KeyLease`. Rust derivation uses the in-flight operation budget. The proof's lifetime bound on distinct infos is specified independently of the Rust live-KEM-owner limit.

For FFI callers, the registry adds an explicit live/pending handle budget and unique monotonically allocated IDs. `q_periapt_sdk_secret_derive` reserves a child under the **runtime parent** of the source, runs the Rust derivation, installs the result and publishes the new owner (`crates/q-periapt-ffi/src/sdk.rs`, lines 771–804). Closing the source handle therefore leaves existing derived siblings under that runtime. Runtime close removes/revokes its children. `publish` checks whether the parent is still live, and failed reservations dispose their unpublished objects (`sdk/registry.rs`, lines 120–182, 234–284 and 350–449).

These guards depend on available ownership and scheduling metadata. They are executed in the same order by the reduction.

### First computation and later retry

The proof table allocates an entry at the first actual private KDF computation of its complete descriptor. That entry exists even if later FFI handle publication fails. A subsequent native derivation may receive a new object or handle ID, and the cryptographic entry remains the same. This separates original private computation from observable publication while preserving both.

A fresh application target is marked before this earliest computation across **every owner in the protected family**. Equal-info aliases on another peer or runtime inherit the same key protection and application use. They retain their own source and runtime liveness checks.

## 4. Source correspondence induction

Use a relational invariant between the native owned objects and the proof controller:

1. Every live source owner refers to its original protected contribution family and actual runtime.
2. Every derived owner has the native runtime and local liveness/publication metadata, and refers to the entry for its complete effective info.
3. Every allocated descriptor's real value is the exact native HKDF output. Repeated values use the same entry; distinct owners remain independently closable.
4. The first-private-computation ledger and any fresh mark survive subsequent owner publication failure or closure.

The invariant holds when the source owners are created. For derivation, runtime admission and source availability are checked first, then the actual public input validation. A failing pre-KDF path preserves the absence of a new descriptor computation. A successful private computation determines its complete info from available arguments and runtime fields, obtains the entry's value and produces the native new owner. The deterministic HKDF formula preserves clause 3.

Export checks that owner's runtime and local field and copies its referenced value. Owner close updates that owner; source close updates the source; runtime close updates the shared runtime and the registry's actual children. Earlier copies already supplied to the controller keep their actual availability. Publication/rollback changes the native handle table while retaining the private computation ledger. These transitions establish the invariant inductively for the supported complete trace, including the specified interleavings at native admission/publication boundaries.

The comparison is therefore a whole Rust owned-API experiment: it preserves derived-key values, their repeated exports, all owner aliases, public failures and revocation behavior. Its crypto replacement changes only descriptor values.

## 5. Length-parameterized entry-table lemma

For the finite service

\[
R_{r,I}=F(F(r,S),I\Vert\mathtt{01}),
\]

retain the available-data, private-contribution and private-PRK interfaces of the established entry argument. Let class `i` have at most `N_i` complete infos, each of length at most `A_i`; put `L_i=A_i+1` and `lambda_i=ell(L_i)`. Choose all finite budgets before execution and require them to hold in each derived comparison.

The joint output-bit gap to the consistent independent table indexed by `(Gamma(r),I)` is at most

\[
\Delta_{\rm ent}=\min\left\{1,
\varepsilon_{\rm Hjoint}(C,0,q_S,32)
+\sum_{i=1}^C\varepsilon_{\rm Hrow}(N_i,q_i,L_i)\right\}.
\]

Valid conservative budgets are

\[
q_S=B+2D+\sum_i(2+\lambda_i)N_i,
\qquad
q_i=B+2D+\sum_{k>i}(2+\lambda_k)N_k.
\]

Here `D` bounds distinct 32-byte salt representations, `C` bounds their `Gamma` classes and `B` includes the entire other execution, preparation and terminal test.

**Proof.** The established column hybrid applies unchanged. Replace PRK-class rows in first-allocation order. The `i`th hidden row receives at most `N_i` messages of length at most `L_i`. Embed its challenge key at that class's first allocation, simulate earlier ideal rows and later real rows, and count the whole continuation. The map `I -> I || 01` is injective for variable-length infos, so the final interface is precisely the full-info random table. The row reductions receive their output values and can perform the entire declared continuation from those replies. An actual row costs at most two key pads plus `ell(L_i)` further compressions. This yields the budgets and the stated bound. ∎

For the native pending-root encoding, `A_i=97`, `L_i=98` and `lambda_i=3`, recovering the existing finite-entry interface and its five-call cost. The SDK's different info length is supplied explicitly to the same argument.

## 6. Native SDK table theorem

Let `N` bound the distinct effective SDK infos of the protected contribution family, and let `L` bound the lengths of `I || 01`. The owned API experiment from Sections 3–4 differs from its consistent independent-key table by output-bit gap at most

\[
\boxed{\Delta_{\rm sdk}=\min\{1,
\varepsilon_{\rm Hjoint}(1,0,B+2+(2+\ell(L))N,32)
+\varepsilon_{\rm Hrow}(N,B+2,L)\}.}
\]

**Proof.** The short-salt normalization gives one available 32-byte salt and one `Gamma` class. The source correspondence places every protected derivation under the exact complete info, with PRK use confined to that class's Expand row. Apply the length-parameterized lemma with `D=C=1`, preserving every owner and lifecycle operation. ∎

The full API admits `L=65899`, `ell(L)=1031`. A smaller declared workload uses its actual length bound. For the existing five-purpose fixture, `N=5`, `L=145`, and `ell(L)=4`, so

\[
q_S=B+32,\qquad q_1=B+2.
\]

The two peer owners have the same effective descriptor for the same purpose when their policy bindings agree. They therefore create five distinct table entries, with separate native owners and exact aliases at the peer.

The primitive bounds retain their complete shared-oracle conventions. `B` includes actual policy/trust-root preparation, all other KEM/record work, computations from returned keys and the final output test. When a preceding ContextBound comparison is used, its whole SHA3 budget also counts the complete resulting SDK continuation.

### Quantified key separation

The table comparison permits export of all derived entries. New distinct infos produce independent ideal keys, with the usual possibility of numerical coincidences. For keys exported from distinct allocated infos, with at most `N` total infos, the real probability of an equal pair of visible key values is bounded by

\[
\min\left\{1,\binom{N}{2}2^{-256}+\Delta_{\rm sdk}\right\}.
\]

In the ideal table this is the union bound for uniform independent 256-bit replies, valid for adaptive new infos. Applying the table's output-bit comparison gives the real bound. This is a quantitative separation result over effective descriptors.

## 7. One-use application consequence

A trusted application may mark a fresh complete info before its first private KDF computation. It retains that key for one specified application encryption/decryption experiment, while other derived entries may be exported. Every source/key owner alias of the selected descriptor routes to the same key-use instance, with its native liveness guards.

Use the one-key, one-encryption AEAD experiment already defined in the retained first-message section: equal-length challenge messages, one nonce/associated-data choice, and the declared classical decryption interface with the exact challenge represented by its authenticated marker. The honest application owns the selected key export used by this cipher. Its network observer sees the declared cipher outputs and available metadata.

Let `Z=1_A (2 1[g=b]-1)` for an available qualification predicate `A`, evaluated in each game's own trace and with zero when the designated application challenge is absent. For each fixed application bit, the terminal randomized test with success probability `(Z+1)/2` turns the KDF bit gap into signed-score cost `2 Delta_sdk`. Average the fixed-bit comparisons. A fresh ideal key can be presampled and withheld until its marked allocation. The AEAD reduction guesses `g` on qualified runs and an independent fair bit otherwise. Consequently,

\[
\boxed{|\mathbb E Z|\le\min\{1,2\Delta_{\rm sdk}+2\varepsilon_{\rm AEAD}\}.}
\]

If the protected common contribution is supplied by the previously established complete-tuple ContextBound replacement for the stopped source family, the additional signed cost is `2 Phi_256(d,Q_H)`. Its actual component, correctness and source/projection comparisons retain their established locations.

The existing SDK exposes the purpose key for application-controlled cipher/MAC use. This conditional consequence specifies that application use. The inspected durable epoch driver consumes the pending-root construction described next; its existing schedule theorem remains attached to that source interface.

## 8. Durable owner, retry and fork-path audit

The durable rekey implementation has exactly two production call sites of `response::derive_root`: responder computation at `response.rs:307`, and proposer acceptance at `completion.rs:851`. The formula itself is the 97-byte pending-root info at `response.rs:134–145`.

For one selected next-rekey operation in the already established authoritative-session profile:

- The original generation token progresses through `Key`, `Signing` and `Ready`, preserving its complete signed offer. Recomputed public material is checked against the retained body (`rekey.rs:321–452`).
- The response token retains its exact offer, conflicts on a different offer and transitions to its stored-root stage before release (`response.rs:183–367`).
- Proposer acceptance reconstructs the original key owner, checks the retained public key, uses that same offer-derived KEM context and verifies the response prefix before root derivation (`completion.rs:761–857`).
- The complete tuple fixes both ciphertext fields. The saved control/session/context prefix fixes the remaining response core. Together they fix the actual root info.
- The two live rekey-root assignments occur at final/receipt installation (`completion.rs:926,1080`); the active selected entropy-token stages have already been replaced. Authoritative recovery retains the committed transition or the old pending token and root.

Induction over this driver preserves one `(old root, complete pending-root info)` pair for the selected protected tuple, on all supported continuations of its matching immutable binding. Aggregate writes for another session preserve the target's original payload and reservation; the existing aggregate-copy test explicitly checks exact retry after such a write and reopen (`messages/tests/reservation_disclosure/aggregate_copy.rs:68–158`).

The source owns an exclusive database lifetime connection and authenticates identity on reopen (`durable.rs:665–669,784–840`). Its local-only mode allows an older whole-database restoration at the storage level, while required-witness mode adds the stated authority checks. The authoritative-history hypothesis is consequently retained at its actual experiment boundary. Physical copies and SDK expert key-transfer operations are recorded as their own source operations; they do not by themselves turn the same pending next-rekey token into a supported new root-info request.

Thus the durable next-rekey driver gives the established single-descriptor source instance. The SDK purpose API gives the directly existing multiple-info workload used in this note, through its actual public call surface and its precise length bridge.

## 9. Counterexamples and repairs

### Raw export of the protected parent contribution

If a caller obtains `S` through `SharedSecret::export_for_protocol`, it can compute the public fixed-salt HKDF locally for a chosen complete `I`. Comparing this value to a derived export succeeds always in the real KDF and with probability `2^-256` in an independent-key table. The output-test gap is `1-2^-256`.

The key-table profile therefore assigns the protected source its declared derivation interface. This restriction covers every source owner carrying that protected family. Other independently known sources retain their ordinary computation and query costs.

### One random key per returned owner

Two native `derive_key` calls with the same complete inputs return separate owners with equal key bytes. Independent random outputs indexed by owner ID would disagree with probability `1-2^-256`.

The repair uses one descriptor key value and separate owner records. The same rule covers matching peer owners and runtime aliases with equal effective info.

### One liveness flag per key descriptor

Derive two same-info owners, close the first, and export the second. Native code still returns the second owner's key while its runtime is open. A model that closes the whole descriptor on the first owner close gives an observably different status.

The repair keeps local owner liveness separate from the cryptographic descriptor. Source close, runtime close and recipient-owned exported copies each retain their actual scope.

### Protecting only one selected owner

Derive a marked purpose key through one source owner, then request its same effective descriptor through another owner and export that alias. Native determinism makes the exported bytes the marked key. A one-key message game that protects only the first owner has then disclosed its challenge key.

The application consequence protects the complete selected descriptor across the source family and routes all of its aliases to the one key-use instance.

### Ambiguous label/context concatenation

The pairs `(label=ab, context=c)` and `(label=a, context=bc)` have equal unframed concatenations. Their SDK length-prefixed infos differ. A cache built from the unframed concatenation would collapse two genuine entries.

The repair indexes the exact SDK info bytes. The same rule preserves the actual policy-state and root-digest fields.

### Selecting after private computation or export

A descriptor already privately evaluated has an existing table allocation, even if publication failed. A descriptor already exported also has its known value in the available view. Its subsequent owner creation provides an alias to that entry.

The fresh application target is chosen at the first private computation across the family. The owner ledger keeps this event through retries and failed publication.

## 10. Evidence and result status

The companion `source_map.json` binds eighteen inspected files to the source pin, records exact ranges and hashes, and distinguishes semantic source claims from finite checks. The executed `check_native_root.py` completes 93 source-range, source-binding, encoding and controller checks, recorded in `validation_report.json`. It recomputes the native public HMAC framing vector, salt normalization, length limits, full-info aliases and the owner/lifecycle counterexamples. It is a standalone algebra and controller check; the mathematical security claim is established by the primitive reductions and the source induction above. The accompanying `native_test_receipt.json` and `native_test_excerpt.log` retain an already completed CI execution of five native Rust purpose tests at development checkpoint `1c68aa6`. This research pass reads that retained execution and performs its separate source/algebra checks.

Completed here: actual SDK call-surface selection; complete byte encoding and length bridge; online owner/descriptor correspondence; joint table bound; quantified separation; and the conditional one-use AEAD consequence. The durable root source invariant and its original theorem remain in their established scopes.

Primary definition for HMAC padding: [RFC 2104, Section 2](https://www.rfc-editor.org/rfc/rfc2104). Native protocol encoding documentation: `docs/SDK_KEY_DERIVATION.md` at the same source pin. Dependency identities are retained in `Cargo.lock` (`hkdf` and `hmac` version 0.13.0).
