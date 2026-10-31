# Multi-epoch symbolic message secrecy

The original `multi_epoch_fresh_reservations_recover_symbolic_message_secrecy`
theorem is verified in 508 steps, with all 24 reusable premises checked in the
same independent, no-search replay. This closes the main symbolic theorem and
its dependencies. It does not establish the separate computational, implementation,
installed-platform, external-review or release-admission obligations.

## Exact scope

For a modeled session, both target-epoch generation and encapsulation reservations
occur after `Cut`. Neither participating identity key nor the target epoch's
reserved entropy is disclosed, and the adversary does not acquire a session record
saved after `Cut`. The theorem then excludes adversarial derivation of the target
application plaintext. `Cut` itself discloses both session wrapping keys. Initial
roots are public, and protocol rounds are unbounded. The theorem is not a claim
against continuing host compromise, forged storage or acquisition of later records.

The operational rules, equations, restrictions and all formulas and modes of the
original 35 queries remain unchanged. The later 38-query MAIN517 baseline is also
retained with its eight open branches. Two new reusable invariants show that two
same-session/role/epoch/phase events cannot be strictly ordered (177 steps), then
derive their equality (4 steps). This supplies the phase alignment used by MAIN
and factors the original first-responder Ready proof from 285 to 6 steps.
Additional helpers, hidden-premise attributes and historical ordering changes
are explicitly recorded in `lineage/CONTRACT.json`; the query contracts are not
claimed to have identical attributes or ordering to the original snapshot.

All 40 queries remain in the certificate. Twenty-six all-trace properties and
the 414-step initial-traffic witness are verified. Eleven multi-round existential
witnesses remain incomplete. The old initial-zero-counter query and the earlier
partial generation-origin proof are also retained, unused and incomplete; the
same generation-origin formula is verified in its phase-root helper. Main secrecy
and multi-round non-vacuity evidence are accounted for separately.

## Replay and retained failures

The local joint replay used Tamarin 1.12.0 and Maude 3.5.1 on Apple Silicon macOS
and completed in 779.048 seconds. Limits remain 900 seconds per process, 12 GiB
RTS heap, `-N1`, `-c30`, a 60-second derivation check and `--quit-on-warning`.
The heap bound does not limit total process RSS. The accepted certificate SHA-256
is `dde5d06a071b1560da0d4c28c3f1fd81a3c39708f9fd8564ee391ddc362bcf7f`.

The committed research entry point selects MAIN. It checks exact archive and
member hashes, unchanged model/query contracts, a complete terminal inventory
and every reusable premise; it rejects warning and invalid-proof diagnostics.
With the pinned tools on `PATH`, run from the repository:

```sh
sh artifact/python-run.sh artifact/continuity_multi_epoch_search.py \
  --output /absolute/path/to/a/new/replay-directory
```

The output directory must be new. `main_multi_epoch_secrecy_verified` reports the
validated MAIN result; `release_claim_eligible` stays false. A prior auxiliary
proof, zero process exit or omission of dependency proofs cannot satisfy MAIN.

`CAPTURE.zip` holds the complete certificate, exact successful input and streams,
original lineage, both timed-out full phase replays, rejected projected steps and
the accepted reopened partial. `PROVENANCE.zip` retains the wider diagnostic and
method-selection history, including the final interactive navigation failure and
its explicitly unaccepted candidate. The full joint replay subsequently checks
that candidate; navigation and zero remaining holes are not proof acceptance.
No failure is counted as success, and earlier capsules remain intact.

`CAPTURE.json` pins all 39 members of the compact capsule and `READBACK.json`
records byte-for-byte verification. Its SHA-256 is
`082aa9ab02e8eae4eb52296e329eeb22bb8ae2cf4a25114df5dc7177019528db`
(407,969 bytes). The provenance archive is 5,119,549 bytes, 733 members, SHA-256
`75719742d875f5d3de402a2ee8e3547b5294bc82265327d89712b2ea9997d259`.
The source baseline is `4ae5f77ad6e81dce956be24511d7f5e429924bde`; this proof-only
continuation does not change SDK behavior or establish final platform qualification.
