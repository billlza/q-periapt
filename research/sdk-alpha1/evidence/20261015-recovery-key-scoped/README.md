# Recovery scoped to reused identity keys

The single-exchange symbolic recovery formula now verifies when signing keys
can be reused across sessions and roles. All 20 universal properties replay in
one fresh process without proof search. Two separate witnesses distinguish
target-key compromise from disclosure of an unrelated key. This is not a
computational or product-release security proof.

## Accepted model and conditions

[`key-scoped.spthy`](../../../continuity-recovery-symbolic/key-scoped.spthy)
has SHA-256 `4f425a97517302603b18e4cb007677614c13b0e341b7619c485a6345af04fd04`.
`Identity_Key` allocates a signing key once; Setup may select any available keys
for its two roles. This permits arbitrary one-sided overlap, role changes and
unbounded concurrent session instances. The ten exchange/storage transitions,
ideal equations and Equality restriction retain their earlier behavior; additional
actions record the proof relationships without emitting private keys on the wire.

The target recovery query requires:

- Both target KEM reservations after Cut.
- No `IdentityKeyLeak` naming either actual target signing key anywhere in the
  trace, including later events and uses in other sessions or roles.
- No target-session entropy disclosure.
- No acquired target record whose Saved event follows Cut.

`IdentityKeyLeak` conservatively marks direct key release **and signer-file
capture before unsealing**. Its occurrence alone does not prove the captured file
is already readable. These are sufficient entire-trace conditions, not necessary
conditions or a forward-secrecy theorem permitting later identity exposure.
No restriction prohibits the leak rules; disclosure of other keys remains allowed.

The model still samples an old root and reveals it publicly at Setup, allocates
wrapping keys per session, and performs one exchange per session. It does not
establish arbitrary inherited-root correlations, shared journals or wrapping
owners, multi-epoch recovery, concrete KEM/HKDF security, exposed ML-DSA signing-coin
security, or SDK refinement. The separately retained explicit-storage theory has
no equivalence proof with this protected-state abstraction.

## Independent results

`experiments/final-37-proof.spthy` has SHA-256
`39f17d2cc5eed8697d0022a35fff2e8d32fea3f9787aad84afc850f496d2a7f7`.
Tamarin 1.12.0 / Maude 3.5.1 replays all 20 required properties with no `--prove`,
one thread and a 12 GiB heap limit. The terminal result takes 305.46 seconds on
this local run; that duration is not a controlled performance comparison.

The eight-step main theorem is
`key_scoped_reservations_recover_symbolic_message_secrecy`. Its full declaration
matches the initial candidate unchanged. `experiments/CERTIFIED_40.json` records
the 19 checked dependencies, complete declaration comparison and operational-model
comparison. The four other existential queries in this certificate are incomplete
and are not reused as premises. The current CI gate still checks the earlier
independent-identity model; this new certificate has not yet been added to it.

| Separate witness | Search / replay | Established behavior |
| --- | ---: | --- |
| Cross-role sibling disclosure | 32 / 55 steps | Three distinct identities, with the target responder's key reused as the sibling initiator. Exactly that sibling identity is disclosed; the attacker learns the target's exact application payload despite fresh target reservations and no snapshot/entropy leak. |
| Recovery premises with unrelated disclosure | 43 / 72 steps | The same one-sided overlap actively signs a sibling offer. A third identity's private key is known, while both target peers confirm and the target sends under the recovery premises. |

The normal witness establishes satisfiable premises and execution, not secrecy by
itself. Its certificate is `experiments/honest-sharing-replay-28-proof.spthy`; the
attack certificate is `experiments/cross-role-replay-09-proof.spthy`. Both replay
independently with no preceding reusable helper. `experiments/WITNESSES_38.json`
checks identity/key aliases, exact knowledge terms, target events and causal
edges. Neither trace claims an executed SDK attack.

## Rejected attempts and admission controls

The archive retains one parallel GHC 9.6.7 runtime abort during contribution
analysis (`eval_thunk_selector: strange selectee`, exit -6). A single bounded
control changes only two threads to one and fresh output paths; it succeeds on
the identical input. The final complete replay also uses one thread. The cause
of the runtime abort is not established, and no model or query was relaxed.

Several old causal proof scripts fail on changed stored-record node references.
Their exit-zero, incomplete group is rejected; fresh proofs replace those scripts.
Conditional search verifies the short main proof while dependencies are deferred,
but that result is rejected until the complete 20-property replay succeeds.

Four parser-valid mutations are rejected: deleting the main theorem, forbidding
unrelated identity-key disclosure, appending a leak-prohibiting restriction after
the lemmas, and removing a key-exposure observation while retaining key output.
The comparison inspects complete declarations and rejects operational declarations
after the first lemma, avoiding a prefix-only check that could miss late restrictions.

Two graph-verifier issues are retained and corrected in fresh scripts. A sibling
offer legitimately adds its own reservation, so event checks bind to the target
query's timepoints. The normal graph expands to 139,281,741 bytes; verification
uses one bounded 160 MiB snapshot for both parsing and hashing. Product SDK input
limits are unchanged. The graph size reflects symbolic-term expansion, not SDK
messages or runtime storage.

## Archive and reproduction

`CAPTURE.zip` contains 266 public members and 307,465,631 expanded bytes. All
members were reopened and hashed. The 5,664,151-byte archive has SHA-256
`97e974de0ce875f61f8d5d54708c393f342f73872e0f27a0e82957640f8affde`.
`CAPTURE.json` lists member digests and admitted results; `READBACK.json` records
the readback. No private SDK or device cohort was reopened or selected.

Extract the named certificate and use the pinned tools with a UTF-8 locale:

```sh
# Linux: LC_ALL=C.UTF-8. On macOS the recorded runs use en_US.UTF-8.
LC_ALL=C.UTF-8 tamarin-prover --with-maude=/absolute/path/to/maude \
  final-37-proof.spthy --derivcheck-timeout=60 --quit-on-warning \
  +RTS -N1 -M12G -s -RTS
```

Require all 20 universal terminal verdicts, not just exit zero or the main theorem.
The two witness certificates use `-M6G` and require their named existential query.
Tool assets and identities are retained in `tools/TOOLS_08.json`; the initial
runtime installation was local to the research workspace.
