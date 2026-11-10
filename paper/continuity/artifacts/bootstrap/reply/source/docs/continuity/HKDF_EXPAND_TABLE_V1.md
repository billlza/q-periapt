# A prefix-consistent table for an ideal HKDF-Expand row

This is an exact intermediate-game identity after the relevant HMAC row has
already been replaced by a private random function. It is not a statement that
real HMAC outputs are independent, a new KDF assumption, or a completed
multi-root reduction. The purpose is to remove an unnecessary private dependency
between HKDF output blocks when formulating the remaining composition argument.
Source mapping is pinned to `cc38ea0718400bc78b79a03e0ccc3c3a8fa725f6`; the
[source readback](../../research/sdk-alpha1/evidence/20261105-hkdf-expand-table/README.md)
records its limits. No new primitive execution or proof-tool run is claimed.

## Interface and statement

Fix a positive output width `h` bytes and a private uniformly random function
`U : byte_strings -> {0,1}^(8h)`. Its only interface to the surrounding machine
is classical `Expand(I,L)`, where `I` is the complete info byte string and
`0 <= L <= 255h`. The surrounding initial state is independent of `U`.
It may perform arbitrary quantum processing and query other independent public
oracles; it has no separate raw-`U`, private-table or internal-input interface.
Queries can be adaptive and info can depend on previously returned outputs.

For this specified interface, use the
[RFC 5869 section 2.3 recurrence](https://www.rfc-editor.org/rfc/rfc5869.html#section-2.3):

```text
T[I,0] = empty
T[I,1] = U(I || byte(1))
T[I,j] = U(T[I,j-1] || I || byte(j))       for 2 <= j <= 255
Expand(I,L) = prefix_L(T[I,1] || ... || T[I,ceil(L/h)])
```

`L=0` returns the empty string and makes no row query. This is a valid request,
not a substitute for an error. Requests outside the stated domain keep their
specified rejection behavior; they do not obtain a successful default value.

The observable interface has **exactly the same distribution** as one private
table of independent uniform `h`-byte blocks `V[I,j]`, indexed by full `I` and
block index `j`. `Expand(I,L)` returns the corresponding concatenated prefix.
Repeated queries use the same table. In particular, `L` is not an independent
randomization index: a 32-byte result must be the prefix of the 64-byte result
for the same `I` and same underlying row.

## Collision-free input indexing

The crucial property is about encoded **inputs**, not distinct random outputs.
For every possible collection of previous block values, inputs belonging to
different `(I,j)` pairs are distinct:

1. Different indices have different final counter octets. The counter ranges
   only from 1 through 255, so it does not wrap.
2. If both indices are 1, equality of `I || byte(1)` forces equal info strings.
3. If both indices are the same `j >= 2`, both inputs have exactly `h` bytes
   before their info field. Equality first forces equal info lengths and then
   equality of the info bytes at that fixed offset. It therefore forces equal
   `I`. Possible equality between previous output blocks does not identify
   different info strings.

For the same `(I,j)`, repeated computation produces the same input: induction
starts at block 1 and uses the deterministic cached previous block. Thus the
actual row-input equality relation is precisely the intended `(I,j)` equality
relation. No output-collision event, prefix-free info convention or restriction
on adaptively selected info is needed for this fact.

Lazily evaluate `U`. When an info string first needs block `j`, its input has
not appeared under any other pair. Conditioned on the existing classical row
queries and their outputs, this fresh table entry is uniform and independent.
Couple that entry to a newly sampled `V[I,j]`; retain the same value on every
repeat. A partial final block still samples and retains the entire `h`-byte
block, so later longer requests remain consistent. This constructs identical
answers for every adaptive interface query. Coupling the remaining quantum
operations and independent public-oracle answers identically gives identical
observable terminal states, without a computational or statistical error term.

If `M_I` is the maximum number of blocks requested for an info value, the
normalized implementation samples exactly `sum_I M_I` blocks. This may avoid
repeating ideal-table reads, but it does not retroactively reduce the query
budget of a preceding HMAC/QROM reduction. That reduction must retain a valid
bound for the actual or correctly simulated calls and the entire prefix.

## Three invalid extensions

- **Fresh output per request length.** With independent 32-byte and 64-byte
  answers for the same info, their first 32 bytes agree with probability
  `2^-256`; actual HKDF prefixes agree with probability one. The interface
  distinguishes these games with advantage `1 - 2^-256`.
- **A separate raw row oracle.** If the machine can also ask `U(I || byte(1))`,
  that answer equals the first block. Replacing Expand by an unrelated vector
  table while leaving that raw oracle untouched again changes an exact equality
  to a `2^(-8h)` event. The exclusive-interface premise cannot be omitted.
- **Independent tables for equal PRKs.** Two semantic HKDF objects with the same
  actual PRK and info have the same output. They must share one row and vector
  cache. A cache keyed only by an object, epoch or purpose name is insufficient.
  Unknown equality between different derived keys needs its actual global
  alias treatment; this lemma supplies no collision probability for those keys.

These are distinguishing experiments for incorrect intermediate games, not
attacks on the source implementation.

## Source correspondence and remaining use

The pinned RustCrypto `hkdf 0.13.0` implementation clones the keyed HMAC state for
each output chunk, feeds the full previous output if present, then the info
components in order, and finally a checked one-byte counter. It retains the
full HMAC output as `prev` even when copying only a partial final chunk. Its
length check precedes the loop. `expand(info, out)` supplies one info component;
the candidate call sites use this method, so no component-boundary identity is
invented. The audited dependency bytes match the existing vendored root-QROM
encoding capture.

| Candidate use | Output bytes | Blocks under SHA-256 |
| --- | ---: | ---: |
| `response::derive_root` | 32 | 1 |
| Responder confirmation key | 32 | 1 |
| Final or receipt confirmation key | 32 | 1 |
| `State::add_epoch` traffic material | 128 | 4 |
| `messages::step` next seed and message key | 64 | 2 |
| `State::new` initial rekey root and traffic material | 160 | 5 |

Each initial/rekey/chain invocation first performs its actual Extract; this
identity applies only after the relevant PRK's row has been validly idealized.
The three confirmation labels share the same zero-salt Extract result. A zero
session ID can also make the traffic Extract equal that result; the full info
strings, rather than fictitious distinct PRKs, separate their vector entries.
Initialization remains distinct from the claimed fresh-recovery epoch.

Within this idealized Expand-only wrapper, subsequent blocks no longer need a
private parent-row table keyed by the previous secret block: independent vector
entries give the same interface. This removes that particular representation
dependency when a block is later used as a child key. It does **not** establish
the child's required joint initialization, hide other appearances of the child,
bound actual key aliases, or justify treating correlated descendants as
independently fresh without the remaining simulation. Nor does it turn the
literal call-site inventory into a whole-program non-disclosure proof.

The [single-root HMAC reduction](SHARED_ROOT_HMAC_V1.md) and
[root extraction result](ROOT_EXTRACTION_QROM_V1.md) retain their own premises
and costs. The full accepted-prefix, multi-root, leakage, AEAD and ACK arguments
remain open. This normalization changes no product algorithm or MAIN condition.
