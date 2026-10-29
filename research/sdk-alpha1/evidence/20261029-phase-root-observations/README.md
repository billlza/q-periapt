# Phase-root observations and proof compatibility

Two structural facts are independently verified: each observed phase root is
the session's initial root or a hash value, and a generation secret is distinct
from every initial root. The completed proofs take 75 and one steps. These are
auxiliary structural facts, not message-secrecy or release claims.

The model adds seventeen observations of existing root fields to twelve rules,
plus one observation of the existing fresh initial root. They are action facts
used for proof inspection. Erasing the exact additions reproduces the original
operational prefix byte for byte, with SHA-256
`3cb837646fa2097468d1fad0a10433f50d5c31b6be5553f20085170c3eef0266`.
Premises, conclusion facts, equations, restrictions and leak behavior are
unchanged. The initial root remains the original fresh value; it is not replaced
with a fixed constant.

Both new properties are non-reusable and hide all thirteen existing reusable
lemmas during independent verification. The successful guide uses thirty
recorded callbacks: thirteen select a phase premise and seventeen select an
available induction condition. Prioritizing the condition avoids repeatedly
unfolding a predecessor when its root property is already available. The original
proofs still replay. The successful run took 319.437 seconds within the existing
900-second limit, one prover thread, 12 GiB GHC heap, 60-second derivation check,
depth bound sixteen and 32-callback budget.

The unsuccessful attempts remain in the capture. The initial automatic search
produced a 108-step partial root proof. The first guide incorrectly rejected an
empty method list and was stopped; an empty list is a legitimate oracle input.
The second guide preferred another phase expansion even when the induction
condition was present and reached its 32-callback limit. Neither interruption is
a theorem result or a timeout. The corrected guide changes method priority,
not the proposition or resource limits. The method interface is described in the
[Tamarin manual](https://tamarin-prover.com/manual/master/book/011_advanced-features.html#using-an-oracle).

Using the new root facts and the independently proved wire-shape facts in the
complete generation-origin proposition exposed seven incompatible old proof
steps. The response shape instantiates the previously generic `core` and changes
related variable names; an old `solve` string no longer selects the current
`Response5` premise. An attempt to close these contexts directly by contradiction
also failed. These copies have seven invalid steps each. Their 389 or 353 recorded
steps and 42 or 34 explicit `by sorry` tokens **cannot be compared as valid proof
frontiers**. The earlier wire-shape record now has an explicit correction; its
original raw archive and manifest remain intact.

This archive covers the six completed experiments through the contradiction
probe. The next operation is exact context capture and repair, with every
temporarily collapsed sibling retained and restored before whole-tree replay.
The original 382-step partial baseline remains available. Generation-origin,
multi-epoch secrecy, longer recovery witnesses and correspondence to the
implementation remain incomplete.

`CAPTURE.zip` contains 192 files and has SHA-256
`22afd7a48167e03ab738e687b37282cfe2955d88c73d14a25f50500fee183155`.
`CAPTURE.json` binds every model, driver, callback, terminal record and stream;
`READBACK.json` records byte comparison and separate verification statuses. The
analysis distinguishes invalid proof copies from valid partial frontiers and
retains all preparation and guide failures.

The subsequent repair is retained separately in `REPAIR_CAPTURE.zip`. Eighteen
no-search callbacks captured the current goals, including all seven changed
contexts. Each had exactly one current `Response5` premise. Replacing the stale
matching expression with that actual premise and restoring the six complete
unselected Stored subtrees yields a full 353-step replay with **zero invalid
proof steps**. The six restored subtrees are byte-identical in its final output.

The repaired proof is still partial: one response-source leaf and forty Snapshot
leaves remain. Sixteen of eighteen source branches are closed. This is not a
claim that moving from the older 42 tokens to 41 leaves improves the security
result; some older proof tails were exposed while repairing incompatible
methods. The current tree is now a valid basis for further work. All eighteen
auxiliary all-trace properties and the 414-step initial-traffic witness replay,
while the generation-origin and multi-epoch secrecy claims remain incomplete.

The capture and full repair took 316.734 and 329.072 seconds, with unchanged
resource limits. The full repair used no search or oracle. Its model SHA-256 is
`b8c7948025c223d87ef2dd5200f9eaa587fde56f4e46603f222a5fe971c3dde0`.
The 175855-byte repair archive has 64 files and SHA-256
`38a2722af54ede21162938a7809ae3d3218de9958f68fa71beea0e260da8d147`.
`REPAIR_CAPTURE.json` binds the exact goals, replacements and restored siblings;
`REPAIR_READBACK.json` records full byte comparison.
