# Wire payload shapes and retained origin proof

Two structural properties are independently verified under the complete retained
protocol model: an emitted offer contains a KEM public-key constructor, and an
emitted response contains the expected hash and KEM-ciphertext constructors. They
take three and four proof steps respectively. Each proof hides all thirteen
previous reusable lemmas; neither new property is reusable during this first
check. The response statement leaves its peer argument unconstrained.

The generation-secret origin theorem remains incomplete. **The original
comparison in this record was incorrect:** the copied tree has seven invalid
proof steps after the new invariants change its contexts. Counting only its 42
explicit `by sorry` tokens omitted those invalid steps and their retained
descendants. Its 389 recorded steps are not a valid frontier comparison with the
382-step baseline and do not establish that the invariants are ineffective.
[CORRECTION.json](CORRECTION.json) identifies the exact raw model and invalid
locations. The archive, original manifest and terminal outputs are retained.
The earlier 46-step fresh search remains a separate partial experiment.

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
| Copied origin replay | 325.165 s | 0 | 1 | Incomplete, 389 recorded steps and 7 invalid proof steps |

Every run uses pinned Tamarin 1.12.0 and Maude 3.5.1, one prover thread, a 12 GiB
GHC heap limit, a 900-second wall-clock limit, a 60-second derivation check and
strict warnings. Search depth remains 16; the final run replays the supplied
proof without an oracle or automatic search. None timed out. An incomplete
required proposition produces driver exit 1 even when Tamarin itself exits 0.

Sixteen auxiliary all-trace properties and the 414-step initial-traffic witness
verify in the final replay. The original 382-step baseline has seventeen closed
knowledge-source branches and three closed Stored producers; the combined copy
needs its seven invalid contexts repaired before comparing closure. Generation-origin, multi-epoch
secrecy, the longer recovery witnesses and correspondence to the implementation
remain open. The historical non-reusable `initial_epoch_counter_is_zero`
conjecture remains incomplete and is never treated as an assumption.

The immediate next step is to repair or recapture the changed proof contexts.
Further root or payload invariants must be motivated by those actual goals.
Any added observation event must erase back to the original operational rules,
introduce no trace restriction or weaker attacker, and have independently checked
properties before reuse.

`CAPTURE.zip` retains the three complete inputs and outputs, terminal records,
streams, bounded driver, preparation scripts, tool identity, original 382-step
parent and initial preparation refusal. `CAPTURE.json` records all 32 file
members and the branch comparison; `READBACK.json` records a byte-for-byte
readback. The 211032-byte archive has SHA-256
`7e6b8fac1d56b34f0b5660e844d504338dd6e2e712442d471e03d494a7be009b`.
The capture was produced from source commit
`093555683948976f095c20e30e73e5d4ae87af12`. It is auxiliary formal evidence,
not release qualification.
