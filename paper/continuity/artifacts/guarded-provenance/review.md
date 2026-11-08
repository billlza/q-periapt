# Independent review: guarded provenance normalization

Date: 2026-11-07. Reviewed manuscript fragment: `../guarded_provenance_theorem.tex`.

Reviewed and rechecked checker SHA-256: `f1d099836194f17a165527d5a2296c06a7d2bd44bf187c1ab9c7456e4beeb92c`.

## Conclusion

**The stated normalization theorem and its proof are correct for the declared finite, immutable, acyclic record graph and fixed public unary key-derivation relation.** I found no mismatch between iterative decryption and normalized guarded paths within that interface. The proof establishes equality at each fixed prefix, so adaptively selecting a prefix or its acquisitions does not require a separate probabilistic argument.

The independent checks below used explicit expected outputs. Agreement between the two implementations was not itself the test oracle. All 17 checks passed. The executable record is `review_results.json`; the reproducible driver is `review_exposure.py`.

One checker execution issue was reproduced and fixed: Python optimization removed its `assert`-based evidence checks while the earlier program still reported success. The revised entry point rejects optimized execution. I independently re-ran all 17 expected-result checks against the revised hash above and verified that an optimized invocation exited with code 1 without creating a result file. The guard-verification record is `review_optimized_guard.json`.

## Mathematical review

The key-closure step is valid because key derivation depends only on disclosed keys and the fixed relation, independently of record plaintexts. Cycles in this relation are benign: they propagate an existing seed of knowledge but do not create one. The two graph algorithms implement this least fixed point using different mechanisms.

For the forward inclusion, every first derivation of a source either comes from direct disclosure or ends in decrypting a record. Following the first availability of each non-acquired parent backwards yields an acquired start and a containment path whose keys belong to the key closure. Acyclic containment ensures this path terminates. For the reverse inclusion, the acquired start and all satisfied guards permit sequential decryption along the path.

Reusing a key on two levels correctly produces one set member rather than two independent obligations: key knowledge is reusable. Alternative acquired records form a disjunction; the keys along each individual path remain a conjunction. Local deletion does not retract an already acquired ciphertext, including its embedded child ciphertexts.

The theorem's source sort denotes knowledge of the protected source value. A public origin identifier is not itself a disclosure of that value. The accompanying non-additivity proposition makes the same distinction and uses an explicit least-closure semantics rather than absolute claims about guessing probability.

## Independent cases and expectations

| Case | Explicit expected result | Observed |
|---|---|---|
| Acquired image; unseeded two-key derivation cycle | No keys and no exposed source | Pass |
| Same cycle seeded at its first key | Both guards become known; origin `o` exposed | Pass |
| Same cycle seeded at its second key | Both guards become known; origin `o` exposed | Pass |
| Direct disclosure of `o`, with no keys | `o` exposed; no key derived backwards | Pass |
| Unseeded key self-loop | No source exposed; closure terminates | Pass |
| Seeded key self-loop | `o` exposed; closure terminates | Pass |
| Derivation edges listed in reverse chain order | Fixed point reaches all three keys and `o` | Pass |
| Shared-leaf diamond, complete left path | `o` exposed | Pass |
| Shared-leaf diamond, complete right path | `o` exposed | Pass |
| Both diamond branches open, leaf key missing | No source exposed | Pass |
| Outer and leaf key known, both branch keys missing | No source exposed | Pass |
| Leaf acquired directly, only leaf key known | `o` exposed without outer guards | Pass |
| Two routes to one origin; only cross-route partial keys | No source exposed | Pass |
| One complete route plus one incomplete route | `o` exposed | Pass |
| Standalone token deleted; immutable enclosing image acquired later | Source exposed only after matching journal-key disclosure | Pass |
| Image acquired, both local image and token then deleted | Late journal-key disclosure still exposes its source | Pass |
| Record contains itself | Constructor rejects containment cycle | Pass |

The deletion tests distinguish removal of a direct acquisition surface from erasure of already retained bytes inside another immutable ciphertext. Neither test treats a local deletion as deletion from adversarial knowledge.

## Resolved execution issue

The issue below was reproduced on the earlier checker SHA-256
`4f6a2ccb07e7b9783393c636f5e54431572a1e8a95cda58bb812723e5a61cf71`.

Command used:

```text
python3 -O work/exposure/check_exposure.py --output work/exposure/review_optimized_run.json
```

The process exited successfully and reported `status: passed`, 5,360 assignments, 360 legal permutations, and five interpretation witnesses. In optimized Python, the `assert a == b`, monotonicity assertions, and `assert correct != mutant` comparisons are removed. Explicit exception-based invalid-input checks still run. That output did not accurately indicate that all advertised comparisons were evaluated in that execution mode. It is retained as `review_optimized_run_before_guard.json` solely as the pre-fix reproduction.

The revised entry point now checks `__debug__` and exits before evaluating the artifact when assertions are disabled. The implementation uses this fail-closed pattern:

```python
if not __debug__:
    raise SystemExit("Run this verification artifact without -O or PYTHONOPTIMIZE.")
```

The independent post-fix invocation used a new temporary output path. It produced exit code 1, no output file, and the diagnostic `validation requires assertions: run without -O or PYTHONOPTIMIZE`. All 17 normal-mode review cases passed again against the revised checker. The independent review driver uses explicit expected-result comparisons, so its own decisive oracle checks remain active under optimization.

## Scope and manuscript alignment

These are clarifications of the selected model, not new research gates:

- **Copy and rewrapping:** the graph declares that several records carry one origin. The theorem normalizes exposure under that relation; it does not establish that native copy code preserves the intended labels.
- **Creation times:** all fixture records initially exist as direct acquisition surfaces. The history API models acquisition, disclosure and local deletion, not record birth or native crash scheduling.
- **Replay context:** the checker has no operation-context field. Exact retry versus reuse under a new context is a separate rule and cannot be inferred from the enumeration count.
- **Key identities:** the same-key fixture uses one canonical symbol. The manuscript correctly declares equal actual keys to be one key identity; the checker does not discover that equivalence from native bytes.
- **Source universe:** the manuscript now explicitly defines `O = union_r orig(r)` and `S_t subseteq O`, matching the checker's declared sources and rejection of unknown direct-source identities.
- **Evidence naming:** the five interpretation witnesses deliberately distinguish specified wrong semantic readings. They are not native implementation mutations. The 5,360 assignment count includes direct-source subsets as well as acquisition and key subsets.

The manuscript already places native-to-interface simulation and message indistinguishability in their separate proof obligations. This is the correct placement: the normalization theorem is an exact result about the chosen derivation semantics.
