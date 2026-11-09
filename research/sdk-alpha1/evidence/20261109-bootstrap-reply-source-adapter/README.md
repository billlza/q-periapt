# Original bootstrap reply-source adapter: retained evidence

Assessed commit: `68549dbc3ae4491d8b5edaa708548dc60743eab7`.

The accompanying
[source adapter proof](../../../../docs/continuity/BOOTSTRAP_REPLY_SOURCE_ADAPTER_V1.md)
instantiates the original reply-key generation and response encapsulation
with the native replay tapes, durable source histories, complete ContextBound
tuple and expanded-key restore checks. It fixes the component challenge at
the original computation and handles later family selection through adjacent
ACK hybrids and fixed-pair candidate events.

The declared profile supplies `S0` when created and the traditional KEM
scalars when sampled, permits the initiator signing identity to be disclosed,
and retains the expected responder's protected signing owner. Registration
follows the original Reply checks/signing and precedes first ACK computation.
For fixed registration/pair bounds `R,G,A`, the proof supplies the uniform
bound

```text
epsilon_schedule <= min(1,
    2 R alpha + sum_r eta_cap,r
  + 2 R G A (nu_enc + rho + a + delta + Phi_256(d,Q_CB)
             + Delta_entry + D_tail + chi_h(Q_h))).
```

`nu_enc <= v/2^256 + delta_K-PKE(v+1)` counts all original fresh sampling
slots that could supply a non-target ciphertext, including unused reservations
and restore checks. `rho` is the existing concrete private-commitment/table
cost. The actual two-endpoint raw-acquisition term `eta_cap,r` is zero on the
declared acquisition-free branch; the proof defines the exact captured-byte
key-hierarchy interface needed to extend that branch. It keeps U3 readability
classification separate from the cryptographic record comparison.

No native implementation, wire format, release contract or CI gate is changed
by this evidence packet.

## Reproduce

From a checkout with the pinned source bytes:

```sh
python3 research/sdk-alpha1/evidence/20261109-bootstrap-reply-source-adapter/check_source_adapter.py
```

Use `--source-root PATH` for a separate exact snapshot and `--output PATH` to
retain a fresh result. The original execution used the assessed source snapshot
through `--source-root`. The retained `RESULT.json` identifies the exact checker
and source-pin digests; `SOURCE_PINS.json` records 32 implementation/proof
inputs with Git-blob, SHA-256 and byte-length identities.

## Executed controls

| Control | Retained result |
| --- | --- |
| Source correspondence | Fourteen checks cover first retention before computation, saved-body equality on replay, PQ/traditional tape order, sealed headers, fresh import check coins and complete combiner-field order. |
| Token layout | 141-byte authenticated binding; 165-byte header; 277/245-byte generation/encapsulation tokens; 64+32 and 32+32 entropy slices. Kind, policy, operation and input mutations give distinct bindings. |
| Durable origins | All three first-write outcomes preserve the correct executed origin. A failed uncommitted reservation remains its own unused draw; a committed unknown result resumes the original token. |
| ContextBound encoding | Ten fields, 2,639 encoded bytes, selected PQ-secret offset 76. Every single-field mutation changes the complete encoding; effective-tuple aliases across different origin labels reuse one entry. |
| Adjacent ACK localization | 8,192 finite endpoint executions across two registration ranks verify cancellation of absent-rank terms, exact pair-event decomposition, no promotion after parent opening, and the pointwise capture residual. |
| Two-endpoint capture accounting | The first-rank capture probabilities are 3/8 and 3/16; the second-rank values are 1/8 and 1/16. The fixture deliberately makes capture depend on the used ACK, detecting a one-endpoint accounting error. |
| Encapsulation collision budget | In the four-value, two-other-draw fixture, a selectable collision has probability 7/16. The original-slot bound 2/4 holds; counting only the one selected executed call would give the false bound 1/4. |
| KEM cache/restore route | One original challenge is reused on retry. Matching protocol decapsulation receives its cached key; ordinary ciphertexts go to the ordinary oracle. Earlier and later non-target ciphertext collisions stop before an excluded CCA query or consistency check. |
| Opaque-record closure | Generation and encapsulation sources reach expanded-owner, source-secret, root and activation records. Public Reply/MAC fields remain public. Capturing an unopened root checkpoint triggers the local acquisition monitor before it is readable. |

These are finite accounting, routing, encoding and source checks. They do not
execute the native ML-KEM implementation, and they do not replace the analytical
source, hidden-input, primitive or collision arguments. The small KEM fixture
is explicitly an oracle-routing model.

## Files

- `check_source_adapter.py`: standard-library executable controls.
- `SOURCE_PINS.json`: exact assessed source and proof dependencies.
- `RESULT.json`: actual successful execution result.

FIPS 203 Algorithms 14, 15, 17 and 18 provide the K-PKE encryption/decryption
and ML-KEM encapsulation relationship used by the fresh-input collision
argument; the [primary specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
was checked directly. The proof retains the K-PKE correctness event as an
explicit parameter and assigns it no numerical failure rate.
