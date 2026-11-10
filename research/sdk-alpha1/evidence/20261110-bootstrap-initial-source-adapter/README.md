# Original initial-source schedule adapter

Source: `471900bfe8070d1021a1feb67481437d599d80ba`; tree
`3ee8cf20e75008949f02c0dfe013b962dd3a7a0a`. Assessment: 10 November 2026.

The [proof](../../../../docs/continuity/BOOTSTRAP_INITIAL_SOURCE_ADAPTER_V1.md)
connects an original responder PQ inventory generation and an original
Initial encapsulation to the joint SDK-short/bootstrap-long Extract service.
It then reaches the U1 ACK-only endpoint through a second, online partition
of the long-PRK table.

## Established construction

The actual source computes `MAC0` from `S0` before the Initial is signed.
Future Replies select their `S1` and reply-core salt later. The construction
therefore retains one joint short/long interface for the original source
pair and preserves the exact shared raw compression input. After that
whole-service comparison, complete long descriptors are numbered by first
request, including failed attempts and exact aliases. A selected unused
table cell can then supply the tail's independent opaque parent.

This yields the explicit uniform schedule bound

```text
min(1,
  2 R alpha + sum_r eta_cap,r
  + 2 R G A [nu_enc + rho + a + delta + Phi_256(d,Q_CB)
             + Delta_entry + L (D_tail + chi_h(Q_h))]).
```

The second localization occurs after the component and joint-entry
comparisons, so `L` multiplies the tail terms. The protected initiator
purpose-5 ledger identifies the actual Initial source even when the responder
signer is available. The admitted context and selected prekey stay fixed;
all traditional material and actual reply contributions are available in
this profile. The original U1 eligibility, pre-return recipe stop and
two-endpoint raw-acquisition residual are retained.

## Source and finite controls

`SOURCE_PINS.json` records 35 exact files with length, Git blob and SHA-256
identities. These include the current inventory/plan/SDK sources, the prior
joint-entry and terminal proofs, and the completed reply-source adapter.
The 29 source checks cover the durable-before-private-effect order, separate
component owners, regeneration/public checks, initial signing order,
short/long schedule order and complete-wire descriptors.

`RESULT.json` retains these deterministic controls:

| Control | Result |
| --- | --- |
| Original draw/retention/execution/consumption histories | 54 traces; all executed retries keep their retained original source. |
| Composite prekey owner disclosure | Four cases distinguish the selected PQ token from the traditional token. |
| Complete descriptor cache | Ranks `1,1,2,3,1`; salt-only and inner-state-only alternatives give wrong class counts. |
| Failed request and live deletion | Failed first use retains rank 1; subsequent use has rank 2; a fresh post-deletion allocation gets rank 3. Recycling creates a duplicate identity. |
| Unused table-cell deferral | 512 executions in each construction give the same 320 joint views; 320 executions retain natural table-value coincidences. |
| Posthoc target selection countermodel | Selecting an observed favorable toy parent has probability `3/4`; assigning a fresh bit afterwards has probability `1/2`. |
| Adjacent ACK/source/rank accounting | 16,384 coin tapes, 49,152 endpoint executions, both registration ranks and exact two-level identities. |
| Nonzero adjacent-gap control | Rank-1 toy gap `5/256`; capture-zeroing changes it by `13/1024`, within its exact two-endpoint capture term. |
| Late protected opening | Explicit trace retains a latched true event at the global stop. |
| Endpoint-dependent capture | Explicit trace has no left-endpoint capture and a right-endpoint capture with candidate bit 1. |
| Original fresh-slot collision budget | 64 executions give `7/16`; the two-original-slot bound `1/2` covers it, whereas one executed ciphertext gives the invalid `1/4` bound. |

The toy public-confirmation bit intentionally creates a nonzero score gap;
it exercises the accounting equations rather than modelling native secrecy.
All reduced-domain outcomes, including numerical equality, are enumerated.
The cryptographic schedule claim is the analytical theorem, using its pinned
component, primitive-entry, record and tail inputs.

## Independent mathematical review

The [independent review](INITIAL_SOURCE_INDEPENDENT_REVIEW.md) accepts the
completed construction at its declared initial-surviving operation surface.
It checks the two localization stages, source and parent opening certificates,
two-endpoint acquisition term, actual inventory restoration, arbitrary Reply
processing and the source-correctness premise. Its
[structured receipt](INITIAL_SOURCE_INDEPENDENT_REVIEW.json) binds the final
32,339-byte proof with SHA-256
`b887e786d06b5226b9886d643c8b0e919cd49387cd5023e22b5878b0d93130ee`.

The [independent reproduction](INITIAL_SOURCE_REPRODUCTION.json) is
byte-identical to [the submitted result](RESULT.json). These three review
files are retained byte-for-byte from the independent execution. Paths inside
the receipts identify that execution's working copies; this directory and
the relative proof link above give their canonical repository locations.

## Reproduction

From an exact source tree, run:

```sh
python3 research/sdk-alpha1/evidence/20261110-bootstrap-initial-source-adapter/check_initial_source.py \
  --source-root . --output /tmp/q-periapt-initial-source-result.json
```

The result is deterministic. Its byte identity is
`b53cdf1a373c1ac60aeb26600914f7d682d3a6d8d74544a5e2995e787a419181`.
An unmodified checkout of the pinned source or the archived exact source
snapshot supplies the inputs; no local Rust or native provider execution is
represented by this Python receipt.

The fresh-ciphertext argument uses FIPS 203 Algorithms 14, 15, 17 and 18,
as in the reply-source proof:
<https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf>.
