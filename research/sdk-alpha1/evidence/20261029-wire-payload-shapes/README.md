# Wire payload shapes and retained origin proof

Two structural properties are independently verified under the complete retained
protocol model: an emitted offer contains a KEM public-key constructor, and an
emitted response contains the expected hash and KEM-ciphertext constructors. They
take three and four proof steps respectively. Each proof hides all thirteen
previous reusable lemmas; neither new property is reusable during this first
check. The response statement leaves its peer argument unconstrained.

These properties do **not** close the generation-secret origin theorem. A full
replay using the same proposition and the complete retained proof tree leaves
all 42 Snapshot plaintext branches open. Its 389 steps, compared with the retained
382, do not establish further source or Stored-branch closure. The earlier fresh
search has 46 partial steps and is retained separately; its size is not comparable
to the complete tree.

The operational prefix has SHA-256
`3cb837646fa2097468d1fad0a10433f50d5c31b6be5553f20085170c3eef0266`.
All original 29 formulas, modes and attributes remain equal. The new properties
are appended after the original queries, then promoted only after independent
verification. The second continues to hide the first. A diagnostic copy of the
exact original origin proposition follows them, with its complete proof copied
apart from the lemma name. This respects the documented
[order of reusable lemmas](https://tamarin-prover.com/manual/master/book/007_property-specification.html#reuse).
No protocol rule, equation, restriction, leak action or trace event was added.

| Check | Time | Tool exit | Driver exit | Result |
| --- | ---: | ---: | ---: | --- |
| Independent packet shapes | 304.596 s | 0 | 0 | Both verified |
| Fresh origin search with proven shapes | 310.262 s | 0 | 1 | Incomplete, 46 steps |
| Complete retained origin replay | 325.165 s | 0 | 1 | Incomplete, 389 steps and 42 open leaves |

Every run uses pinned Tamarin 1.12.0 and Maude 3.5.1, one prover thread, a 12 GiB
GHC heap limit, a 900-second wall-clock limit, a 60-second derivation check and
strict warnings. Search depth remains 16; the final run replays the supplied
proof without an oracle or automatic search. None timed out. An incomplete
required proposition produces driver exit 1 even when Tamarin itself exits 0.

Sixteen auxiliary all-trace properties and the 414-step initial-traffic witness
verify in the final replay. Seventeen of eighteen knowledge-source branches and
three Stored producers remain closed, as before. Generation-origin, multi-epoch
secrecy, the longer recovery witnesses and correspondence to the implementation
remain open. The historical non-reusable `initial_epoch_counter_is_zero`
conjecture remains incomplete and is never treated as an assumption.

The negative result directs the next investigation toward retained root and
payload components in phase producers. Existing phase markers do not expose
their full payload. If an additional observation event is needed to state a useful
invariant, its erasure must reproduce the original operational rules exactly;
it must introduce no trace restriction or weaker attacker. That is a proposed
next experiment, not a verified property in this capture.

`CAPTURE.zip` retains the three complete inputs and outputs, terminal records,
streams, bounded driver, preparation scripts, tool identity, original 382-step
parent and initial preparation refusal. `CAPTURE.json` records all 32 file
members and the branch comparison; `READBACK.json` records a byte-for-byte
readback. The 211032-byte archive has SHA-256
`7e6b8fac1d56b34f0b5660e844d504338dd6e2e712442d471e03d494a7be009b`.
The capture was produced from source commit
`093555683948976f095c20e30e73e5d4ae87af12`. It is auxiliary formal evidence,
not release qualification.
