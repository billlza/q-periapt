# Authenticated KEM provenance and the remaining message-secrecy gap

Six related obligations now pass together and replay in a fresh Tamarin 1.12.0
process without automatic proof search. They establish intermediate facts about
the existing ideal-primitive model. They do not establish message secrecy or the
complete 0.2.0 recovery claim.

| Obligation | Combined checked steps | Meaning |
| --- | ---: | --- |
| `signing_secret_derivation_origin` | 356 | Derivation of an observed signing key requires its modeled identity-disclosure event. |
| `generation_secret_derivation_origin` | 187 | Derivation of a generated KEM key requires generation-entropy leakage or phase-1/2/3 capture. |
| `signing_secret_origin` | 3 | The public `K` knowledge formulation follows in this checked helper context. |
| `generation_secret_origin` | 7 | The original public `K` property follows in this checked helper context. |
| `encapsulation_uses_authenticated_generation` | 163 | Without target-session initiator identity disclosure, the accepted offer uses an earlier honest generated KEM public key. |
| `encapsulation_derivation_requires_session_leak` | 204 | Derivation of the reserved encapsulation contribution requires target-session identity, entropy or snapshot leakage. |

These are necessary-event properties, not bounds on when a leak occurred or on
how many future messages remain exposed. Leakage in other sessions remains
allowed; replication is not bounded. The `KU` properties are auxiliary facts
about the pinned prover's derivation rules. All original public `K` queries,
including the positive recovery query, retain their complete declarations.
The original generated-key property had already been checked independently in
182 steps; the seven-step result here uses the newly checked helper context.
These step counts describe proof scripts, not a security strength or performance
comparison.

The accepted extension adds three removable observation actions: two signing-key
labels at Setup and one encapsulation label at reservation. No state fact, input,
output, equation, restriction or freshness condition changes. Erasing these
labels restores the original semantics. The pinned parser confirms all five
original declarations and the complete combined input/certificate declarations.
Bare input is compared with the bare original, and closed theory export with
the original checked export; their informational builtin/function declarations
differ. The first check rejected that presentation difference and is retained.
These labels are proof observations, not SDK logging or runtime leak detection.

The first signing-key proof also succeeds independently in 350 steps. A normal
identity-disclosure execution is witnessed in six steps. A countermodel removes
only the `IdentityLeak` observation from the rule that outputs the signing key;
the provenance statement is then falsified in five steps. This deliberately
changed model is a checker control, not a product vulnerability. The simplified
JSON graph omits that actionless rule, so the corrected reader checks both the
proof's `Reveal_Identity` case and the exact observed/known key. The earlier
reader failure and its status-regex limitation are preserved.

An independent replay verifies all six obligations in
`proof/composed-16-proof.spthy`, SHA-256
`789cbbdcc2ee6c172c190d5d4330f0fa781ba3772a272cfc9b911837e1690770`.
A second replay removes the first reusable proof. The prover exits zero and
still marks the other five obligations verified, but the required dependency
group is rejected. No unproved reusable lemma is accepted as a security premise.

The next steps in the composition remain open. K-form encapsulation search
(600 seconds), broad root/traffic-constructor helpers (600), a message-level
derivation helper (300, 8 GiB heap), and a root-observer helper (300) all time out.
The failed helpers are never imported into an accepted group. Expanding the two
`no_precomp` premises also times out during 180-second precomputation; removing
those annotations is not adopted. Timeouts are not counterexamples. Owned
process groups are confirmed absent, including cases requiring SIGKILL after
the five-second SIGINT grace period.

`CAPTURE.zip` contains **165 public members**, SHA-256
`6ee9a168d9b80b7c2105a7ca9537e823d2f513975b8790bb8613176e6676eedb`.
The manifest and readback bind recipes, proof inputs, certificates, complete
terminal statuses, independent replay, rejection controls and failed attempts.
The canonical model and product code are unchanged. No private SDK or device
cohort was reopened.

Reproduction uses the pinned Tamarin/Maude identities retained under
`toolchain/`. Extract the certificate and replay without `--prove`:

```sh
tamarin-prover --with-maude=/absolute/path/to/maude \
  composed-16-proof.spthy --derivcheck-timeout=60 --quit-on-warning \
  +RTS -N2 -M4G -s -RTS
```

Require all six terminal results above; exit zero alone is insufficient. Other
queries in this certificate remain incomplete. The prior honest and disclosure
witnesses retain their [separate checked evidence](../20261015-recovery-symbolic-disclosure/README.md).
See the Tamarin documentation on
[precomputation and derivation helpers](https://tamarin-prover.com/manual/master/book/009_precomputation.html)
and [reusable lemmas](https://tamarin-prover.com/manual/master/book/007_property-specification.html#lemma-annotations).

Perfect KEM/signatures/hash, protected storage, independent identities and one
exchange per pair remain the assumptions. Concrete HKDF/hybrid security,
exposed ML-DSA signing coins, shared-device state, multi-epoch recovery and Rust
refinement remain uncovered. The unchanged positive message-secrecy statement
and full release goal remain open.
