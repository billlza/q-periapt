# Session-root authentication obligations

Two additional correspondence properties now verify together with all six
previous crypto obligations. A fresh process checks the complete eight-property
certificate without automatic proof search. This connects authenticated response
processing to the root used for a message; it does not prove that root or message
secret.

| New property | Checked steps | Meaning |
| --- | ---: | --- |
| `accepted_root_has_authenticated_origin` | 313 | If the target session's responder identity is not disclosed, an accepted root equals one computed earlier by that session's responder. |
| `message_root_has_authenticated_origin` | 6 | Under the same identity condition, the root used by an application message has that earlier computation origin. |

The identity condition excludes its disclosure anywhere in the trace, not merely
before acceptance. These statements do not require entropy or storage secrecy;
an authentic root can still be exposed. Other-session leakage and unbounded
independent instances remain allowed. The observer actions do not detect
compromise at runtime. The six preceding obligations retain their checked step
counts: 356, 187, 3, 7, 163 and 204, as detailed in the
[crypto-provenance checkpoint](../20261015-recovery-crypto-provenance/README.md).

The new extension adds `ResponseRoot`, `AcceptedRoot` and `TrafficInput` to the
existing three observations. Erasing all six restores the original operational
rules, equations and Equality restriction. The original five complete property
declarations are unchanged. Pinned-parser comparisons cover the actual composed
input and final certificate, including expanded function signatures. Informational
builtin/function summaries are separately checked against those signatures.
Three source mutations—equation, output and restriction—are parsed and rejected
by the same comparison. An earlier control only mutated normalized strings;
the stronger source-based control replaces that evidence claim.

An honest execution witness demonstrates that these conditions are reachable:
the responder computes a root, the initiator accepts the same root, and an
initiator message uses it, without identity, entropy or snapshot leakage.
Its standalone query precedes every reusable lemma. Initial search reports
15 steps; independent replay reports 29, with all complete declarations
unchanged. The checked trace binds the same session and root at all three events.
This witness asserts neither Cut nor completion of both peers' receipts. The
earlier full-exchange witness remains separate evidence.

Conditional search initially defers existing proof bodies while preserving every
formula and operational rule. Its successful new results are deliberately not
admitted as a complete group. The original six checked proof bodies are then
restored. Replaying this whole input at 4 GiB fails with heap exhaustion and
exit 251 after 302 seconds. Replaying the identical input at 8 GiB succeeds in
171.7 seconds and verifies all eight obligations. This changes a resource bound,
not a model assumption; the two runs are not a controlled performance benchmark.

A control removes only the accepted-root proof. The process exits zero and
verifies the other seven properties, including message-root correspondence;
the required group correctly rejects the missing dependency. The final
certificate is `proof/composed-13-proof.spthy`, SHA-256
`3f6ba5ef70570f91b4304ddace82746bd31ca5ac7e9bdfda89c043df5b8ac8ef`.
Replay it with the pinned tools and require all eight terminal results:

```sh
tamarin-prover --with-maude=/absolute/path/to/maude \
  composed-13-proof.spthy --derivcheck-timeout=60 --quit-on-warning \
  +RTS -N2 -M8G -s -RTS
```

Root secrecy remains incomplete. Conditional root search still times out at
300 seconds after deferring prior proof bodies, so replay overhead alone does
not explain the earlier timeout. A bounded oracle records 17 actual, validated
goal permutations before its 180-second timeout. Its final goals concern another
session's generic Stored contents; this identifies a search frontier, not an
attack or sole cause. Composing the prior record-content source lemma times out
at 300 seconds, with precomputation still the last reported phase. A separate
untracked-identity countermodel also times out at 180 seconds and supplies no
accepted falsification. Failed helpers are not imported as proved premises.
All owned process groups are confirmed absent.

`CAPTURE.zip` has **148 public members**, SHA-256
`f61b032f2d7c6c626d57bd208901d1f02d61335c716f120f2c38d6d457975955`.
The manifest/readback bind proof inputs, complete results, dependency controls,
semantic checks, honest trace, failed attempts and recipes. The proof-obligation
and oracle distinctions follow the Tamarin documentation on
[lemma reuse](https://tamarin-prover.com/manual/master/book/007_property-specification.html#lemma-annotations)
and [oracles](https://tamarin-prover.com/manual/master/book/011_advanced-features.html#using-an-oracle).

The canonical model and product code remain unchanged; no private SDK or device
cohort is reopened. Perfect primitives, protected storage, independent identities
and one exchange per pair remain the modeled limits. The positive message-secrecy
query, concrete construction argument, shared-device/multi-epoch analysis and
full release goal remain open.
