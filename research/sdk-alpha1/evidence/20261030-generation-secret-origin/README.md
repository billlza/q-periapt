# Multi-epoch generation-secret origin

The 591-step proof of
`epoch_generation_secret_derivation_origin_with_phase_roots` independently
replays with all 19 reusable premises verified. This is an auxiliary symbolic
origin theorem, not the main multi-epoch message-secrecy result or release
admission. The main theorem and the two-round execution witnesses remain
`analysis incomplete`.

## Exact claim and lineage

For any session and epoch, if an adversary derives a generated KEM secret,
the trace contains either the corresponding generation-entropy disclosure or
a captured phase 1, 2 or 3 record for that session and epoch. The formula does
not order those disclosure events before the knowledge event. It is identical
to the original generation-origin proposition; the earlier named proof remains
visible in its original position with its partial proof.

The operational rules, equations, restriction, attacker capabilities and all
35 preceding query contracts, attributes and relative ordering are unchanged
from `20261030-snapshot-origin-derivation`. The new reusable
`reserved_parent_has_hash_constructor` lemma has an independently checked
11-step proof. It states that a `RootBefore` transcript parent has the form
`h(material)`. No protocol observation, axiom, restriction or round bound was
added. The 34 non-target original proof bodies are retained unchanged.

The new invariant removes impossible fresh-secret/parent equalities. Source
analysis also resolves deduction-chain constraints displayed in the proof
state even when those constraints are absent from the ranked method list.
These are kernel-checked proof steps, not an assumption that omitted search
branches are impossible. Diagnostic closure was followed by restoration of
all dependency proofs and a fresh no-search replay.

The final inventory has 36 queries: 21 verified all-trace properties, including
all 19 reusable premises, and the existing 414-step initial-traffic witness.
The other 14 queries remain incomplete. Neither that witness nor the origin
theorem establishes multi-epoch recovery secrecy, computational security or
implementation correspondence.

## Fixed tools and bounded replay

The retained replay used Tamarin 1.12.0 and Maude 3.5.1 on Apple Silicon macOS,
with a 900-second process deadline, a 12 GiB RTS heap bound, one capability
(`-N1`), a 60-second derivation-check bound and `--quit-on-warning`.
The heap bound is not a bound on total process RSS. The input and output are
byte-identical, with SHA-256
`b2c6e233a3b2bb4ca75f8f438f84caca497523a32e6c86f05e467b5710425953`.
Replay completed in 350.588 seconds with no warning or invalid proof step.

The same complete input first exhausted the fixed heap after 678.895 seconds
with `-c100` (exit 251). A controlled second run changed only that argument to
`-c30`, the documented default compaction threshold for the binary's GHC 9.6.7
runtime. It completed without increasing any time, heap or worker limit.
The successful run's maximum live residency was 7,296,584,000 bytes. These two
runs establish the outcome for this input and tool build, not a general speed
or memory guarantee. See the
[GHC 9.6.7 runtime documentation](https://downloads.haskell.org/ghc/9.6.7/docs/users_guide/runtime_control.html#rts-flag--c).

The committed runner uses that explicit threshold and checks the complete
inventory. With the pinned tools available on `PATH`, run from the repository:

```sh
sh artifact/python-run.sh artifact/continuity_multi_epoch_search.py \
  --output /absolute/path/to/a/new/replay-directory
```

The output directory must not already exist. The research workflow retains
its exact toolchain and source inputs. A successful origin replay continues
to report `main_multi_epoch_secrecy_verified: false` and
`release_claim_eligible: false`.

## Retained evidence

`CAPTURE.json` pins every member of `CAPTURE.zip`; `READBACK.json` records
byte-for-byte archive verification. The capsule contains the complete current
certificate, verbatim successful replay streams and records, the original
35-query certificate, and the complete same-input copying-GC failure streams
and records. Earlier timeout, heap, canonicalization and stale-step failures
are identified by exact input and stream hashes in the retained-failure ledger;
their raw records remain in the local research checkpoint. No failed run is
counted as a proof.

The archive SHA-256 is
`9df4eefd5d08098018cba24565b89671c7292bd250dcf8e4c82fc3600e25dd92`
(112,939 bytes). Its source baseline is
`4ae5f77ad6e81dce956be24511d7f5e429924bde`; the proof-only continuation does not
change SDK behavior or claim final platform qualification.
