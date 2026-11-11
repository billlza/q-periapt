# Passive state-snapshot experiment

This experiment augments the unchanged pinned SPQR implementation with an
independent message-key derivation program. It exercises a concrete consequence
of state disclosure. It does not establish a recovery theorem or select the
Continuity product construction.

## Attacker inputs and comparison boundary

Each of the seven existing schedules captures A and B separately immediately
before sends 0, 1, 7, 63, 255 and 1,023: **84 cases**. A case obtains that one
endpoint's serialized state once, plus all public transmitted SPQR packets from
the beginning to the end of the run. It observes packets even when the network
schedule drops them before endpoint receipt. The analysis is retrospective: a
later public ciphertext may reveal an earlier message key. The report records the
first send at which sufficient public ciphertext chunks have been emitted.

The attacker implementation receives no later private state, message-key output,
fresh entropy or RNG state. A separate comparison harness retains actual sender
keys and checks every derived key for exact equality. No key or private snapshot
is serialized. As in the original reference corpus, the deterministic entropy
and initial secret are **public test fixtures**. The experiment constrains the
derivation program's inputs; it is not an unpredictability game over secret test
seeds.

The implementation reconstructs both directional chains from the captured state:

1. Existing chain secrets derive future indices through an independently written
   HKDF-SHA-256 chain step. Retained skipped keys remain available; consumed keys
   and erased chain secrets are not recreated.
2. A captured pending decapsulation key can also expose the next epoch. The
   program reconstructs its 960-byte first ciphertext part and 160-byte second
   part plus MAC from public polynomial chunks, using the unchanged upstream
   erasure decoder. It invokes the pinned incremental ML-KEM decapsulation,
   applies the SCKA output KDF, and mixes that secret with the stolen chain root.
3. The attacker then derives keys for that newly exposed epoch in both
   directions. It receives no fresh secret for the next exchange. An uncomputed
   key is reported only as `not_derived`, never as secure or recovered.

The KDF domains and state fields correspond to the pinned upstream
[chain implementation](https://github.com/signalapp/SparsePostQuantumRatchet/blob/f2589fef855c10f39d72634dab3d14654dd410bf/src/chain.rs)
and [incremental KEM adapter](https://github.com/signalapp/SparsePostQuantumRatchet/blob/f2589fef855c10f39d72634dab3d14654dd410bf/src/incremental_mlkem768.rs).
The snapshot classifier follows its actual pending-key fields, not an assumption
that the current emitted epoch bounds all exposed secrets. The
[ML-KEM Braid recovery analysis](https://signal.org/docs/specifications/mlkembraid/#the-vulnerable-message-set)
remains a separate source of construction-level reasoning.

## Observed results

For A's snapshot immediately after the first send, the remaining corpus has
2,047 sends. Exact derived-key counts are:

| Schedule | Derived keys | Of these, derived through the stolen pending KEM key | Not derived by this program |
| --- | ---: | ---: | ---: |
| Alternating | 172 | 87 | 1,875 |
| Loss | 198 | 93 | 1,849 |
| Reorder | 219 | 111 | 1,828 |
| Duplicate | 172 | 87 | 1,875 |
| 9:1 | 748 | 399 | 1,299 |
| Offline then exchange | 424 | 87 | 1,623 |
| One-way | 2,047 | 0 | 0 |

All twelve one-way cases derive every key emitted after their cut. In the
alternating case above, counting only the currently emitted epoch would omit
**87 actually derivable keys**. The results therefore rule out those two proposed
shortcuts for a recovery indicator: message-count-only progression, and exposure
limited to the current chain epoch.

`COMPROMISE_CORPUS.json` locks each full public experiment report and its case
summaries. The Python verifier independently checks capture points against the
original event order, complete ciphertext chunk availability, pending-key epoch
classification, every future send's accounting and the negative-control record.
The original seven wire-trace hashes remain unchanged. Two full executions must
produce the same experiment reports.

An altered stolen chain key is run through the same derivation path in every
case; it must disagree with an actual sender key. Rust tests separately compare
the independent KDF against upstream chains for both directions and a fresh
epoch, and cover erased/consumed/skipped-key distinctions and malformed wire.
Python negative controls reject omitted cases, altered predicted sets, invented
ciphertext completion, false interpretation labels and unexpected private fields.
These controls validate the experiment; they do not transform a missing attack
into a security proof.

## Remaining analysis

This lane does not model active injection after authenticator compromise,
repeated or continuous compromise, cloned RNGs, persistent snapshot rollback,
external authentication, the full Triple Ratchet, or application AEAD. It does not
measure energy or prescribe a product healing deadline. Those obligations and
matched whole-KEM/chunk-size comparisons remain part of the full 0.2.0 work.
The product API must describe confirmed protocol progress without claiming to
know whether a previously compromised endpoint is now secure.
