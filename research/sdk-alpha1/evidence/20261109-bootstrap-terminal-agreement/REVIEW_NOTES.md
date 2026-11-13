# Terminal-conversion review notes

## Claim and game correction

The first draft selected eligible classes at the verdict. That wording left
the replacement set dependent on future interaction and did not define a causal
simulation. The delivered theorem uses online registration before the first
private ACK-key computation or use at either endpoint, a monotone finite family and a common stop before releasing
a protected key recipe or replacing protected trusted state. It makes no
retrospective selection of surviving sessions. Exact byte-identical retries
share a registration; different complete signed-wire aliases remain distinct
classes with their actual common source dependencies.

The terminal event refers to the expected honest responder's historical durable
activation. It does not require that responder to be newly online when an old
proof is replayed. The caller's own current-authority checks remain part of the
return path. A successful local activation before an invalid ACK is not silently
rolled back or relabelled as connection success.

The explicit advantage bound is capped at one. Its joint schedule and multi-key
MAC gaps use the same fixed family/query budgets, online registration and stop
interface. There is no per-session guessing factor hidden behind a marginal
key-uniformity assertion. An instantiation with later protected disclosure has
its own stopping/partition dependency.

## Source and numerical review

The native responder writes `Complete` before activation. `State::new` splits
the 160-byte initial expansion into the rekey root and 128 traffic bytes.
`Traffic::from_material` places the initiator-direction acknowledgement key in
the initiator's `send_ack` and the responder's `receive_ack`. Both clients check
epoch zero, exact session ID and the shared MAC verifier before terminal return.

Eight existing Rust public-vector expectations are reproduced byte-for-byte.
The finite matrix checks 4 transcript classes × 2 directions × 2 epoch choices
× 3 floors × 4 key sources = 192 combinations. The two admitted combinations
have the original class/key, direction 1, epoch 0 and a floor no greater than
the sent count. Fourteen separate event controls cover online registration,
no late protection, fixed family bounds, shared-source exposure, guarded record
readability and permitted sibling/identity disclosures.

The execution reports public synthetic data only. It does not produce or retain
native private key material. Native signature/KEM evidence remains the original
retained R1–R4 record set in the construction matrix.

The final clarification makes `Bad` a latched pre-stop event; a later disclosure
stop preserves a previously observed bad acceptance. `Pr[Coll]` refers to the
original real experiment. Registered uniform keys are sampled without any
pairwise-distinct conditioning, and all other known-key computations remain in
the auxiliary view. Numerical key coincidences and their correlations belong
to the multi-key PRF gap.
