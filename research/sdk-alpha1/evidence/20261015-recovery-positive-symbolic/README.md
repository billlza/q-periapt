# Positive recovery in the single-exchange symbolic model

The original `clean_reservation_recovers_symbolic_message_secrecy` formula now
verifies in **9 steps**, together with all **19 required auxiliary properties**.
A fresh Tamarin 1.12.0 / Maude 3.5.1 process replays the complete group without
automatic proof search. The original five complete property declarations are
unchanged. This closes the positive query for the protected-state symbolic
projection; it does not establish the full 0.2.0 construction or release readiness.

The sufficient conditions are exactly those in the original query:

- Both target-session KEM reservations occur after Cut.
- The target session has no identity or entropy disclosure anywhere in the trace.
- No acquired target-session revision was saved after Cut.

The old root is public from Setup, and Cut exposes both wrapping keys. Other
sessions may still suffer identity, entropy and snapshot disclosure. The number
of independent instances is unbounded; each pair performs one exchange. The
theorem is conditional on an application-message event. It promises neither
network progress nor a runtime test for whether an attacker has been removed.

The successful proof follows explicit knowledge dependencies:

| Intermediate statement | Checked steps | Contribution |
| --- | ---: | --- |
| `response_confirmation_has_origin_or_prior_root` | 147 | A known confirmation tag has an earlier honest root origin or requires earlier root derivation. |
| `accepted_root_has_origin_or_prior_derivation` | 8 | An accepted root has that origin or was already derivable, without assuming identity secrecy. |
| `root_constructor_requires_prior_coins_or_snapshot` | 150 | Root derivation requires earlier contribution derivation or a prior snapshot of the embedded session. |
| `computed_root_derivation_requires_session_leak` | 20 | The checked encapsulation property then requires target-session disclosure. |
| `traffic_key_derivation_requires_prior_root` | 142 | Traffic-key derivation requires earlier root derivation. |
| `message_derivation_requires_prior_traffic_key` | 352 | Deriving a fresh payload requires earlier traffic-key derivation. |
| `message_derivation_requires_session_leak` | 18 | The authenticated message-root relation joins those dependencies. |

The prior signing/generation/authentication/encapsulation properties and the
13/42-step retained-record timing helpers complete the group. The public `K`
encapsulation formulation verifies in six steps. Root/session uniqueness is
checked; a separate two-step reservation-uniqueness result is independently
replayed. Constructor uniqueness is an ideal-symbolic fact, not a computational
collision-resistance result. All names/counts are in
`positive_recovery_certificate.verified_group` in `CAPTURE.json`.

Some new auxiliary proofs use `hide_lemma` to omit irrelevant reusable premises.
No formula, protocol rule, equation or trace restriction changes, and all 20
properties remain required. See Tamarin's
[lemma annotations](https://tamarin-prover.com/manual/master/book/007_property-specification.html#lemma-annotations).
The six existing observation actions erase to the unchanged canonical model;
no further observation, state or network output is added here.

The accepted certificate is `proof/final-positive-53-proof.spthy`, SHA-256
`91dd31801ee8c208d295a5a02efc1721c794fc8dd32bb1430d303fcb18199707`.
Replay takes 335.9 seconds with two threads and a 12 GiB heap on the recorded
host. The identical input at 8 GiB exhausts its heap and exits 251 after 606
seconds; that failure is retained. These are prover resource observations,
not SDK performance or a controlled benchmark.

```sh
tamarin-prover --with-maude=/absolute/path/to/maude \
  final-positive-53-proof.spthy --derivcheck-timeout=60 --quit-on-warning \
  +RTS -N2 -M12G -s -RTS
```

Require all 20 terminal results. The three original execution/disclosure
witnesses remain incomplete in this certificate and retain their
[separate checked certificates](../20261015-recovery-symbolic-disclosure/README.md).
The unchanged honest witness establishes reachability of the positive conditions.
No existential witness is a reusable premise of the positive proof.

A new boundary witness shows exactly one target-responder identity disclosure
permitting acceptance of an already-known root, without honest response-root
computation, entropy disclosure or snapshots. Search reports 19 steps;
independent replay reports 39. Readback checks the exact known/accepted root,
session and sole disclosure event. An earlier trace with two disclosures of the
same key is retained. This asserts no SDK attack or application decryption; it
explains why the positive identity condition cannot simply be omitted.

Admission controls reject deleting the main theorem, forbidding other-session
identity leakage in its premise, and adding a restriction forbidding all
snapshots. Pinned-parser checks also reject equation/output/restriction mutations.
Conditional search displays the main theorem as verified while dependencies are
incomplete; the group correctly rejects that exit-zero result. A separate
missing-confirmation-proof control rejects an incomplete group despite a verified
dependent accepted-root statement. Earlier failed searches and preparation errors
remain recorded. All owned proof process groups are terminal.

`CAPTURE.zip` has **279 public members**, SHA-256
`e207e57e480608b408823bff1c3ce28a805214df24e651a599b02150684dcea9`.
Manifest/readback bind all inputs, certificates, results, controls, witnesses and
tool identities. A CI explanation is also corrected: main CI has no cancellation
concurrency group; CodeQL has a separate group. No workflow or running job changes.

Perfect KEM/signatures/hash and ideal protected storage remain assumptions.
Concrete hybrid/HKDF security, exposed ML-DSA signing coins, shared identities and
journals, multi-epoch recovery, explicit-storage equivalence, Rust refinement,
message chains/ACKs, fsync and rollback remain uncovered. This certificate is not
yet wired into an automated release CI gate. Product code and the canonical model
are unchanged; no private SDK/device cohort is reopened. The full goal stays active.
