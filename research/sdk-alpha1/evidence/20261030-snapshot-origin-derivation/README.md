The complete 35-query model independently replays with 19 verified all-trace
auxiliary results and the 414-step initial-traffic witness. The generation-secret
origin proof has 431 steps and 24 remaining snapshot leaves. Full origin secrecy,
multi-epoch message secrecy and implementation correspondence remain incomplete.

The operational rules, equations, restrictions and original 34 query contracts
are unchanged from the [previous response-source checkpoint](../20261029-response-origin-derivation/README.md).
The one additional query, `signed_final_payload_has_public_constructors`, has its
own four-step proof and participates in the complete independent replay. No axiom
or extra attacker restriction was introduced.

This capsule starts from the subsequently checked 403-step, 24-leaf partial.
Existing deduction edges were captured from their exact proof states before they
were selected. Constructor projections expose more specific children; explicit
kernel-listed contradictions close public-field and cyclic branches. The response
ciphertext case follows `Response4` back to its original encapsulation reservation
and uses the existing separation of encapsulation randomness from generation
secrets. Five previously open leaf subtrees are now fully closed. Expanding other
subtrees leaves 24 finer-grained open obligations. Equal leaf counts do not mean
equal proofs, and these counts are not a security score.

All 35 queries and their attributes are retained. The three complete no-search
replays have 418, 431 and 431 origin steps; their open frontiers contain 27, 28 and
24 leaves respectively. Each prover returned zero with no invalid proof steps;
each qualification driver returned one because the selected origin theorem was
still incomplete. The final independent replay took about 341 seconds under the
existing 900-second limit, 12 GiB heap, one worker and 60-second derivation check.
The search-depth and guided-callback limits remain 16 and 32.

`CAPTURE.zip` retains 146 files: the final complete proof, the earlier 34-query
contract, the checked 403-step baseline, exact local inputs and outputs, method
observations and bounded execution records. `CAPTURE.json` lists every member's
size and SHA-256; `READBACK.json` records byte-for-byte archive verification. The
final model is `proof/current.spthy`. Historical drivers retain their original
local paths; the repository entry point below loads and verifies the portable
complete model without executing archived programs.

With the pinned Tamarin 1.12.0 and Maude 3.5.1 available, the research entry point is:

```sh
sh artifact/python-run.sh artifact/continuity_multi_epoch_search.py --output /absolute/fresh/output
```

It independently replays the baseline, performs a bounded origin search and
replays its result. An incomplete selected theorem remains a failure. Standard
streams are now retained within their existing bounds even on timeout; the
failure status and incomplete-output marker are retained with their hashes.

- Final proof SHA-256: `d21fa9256a72a5b7ad7ddc159762a10d14451bb0492b727f7d0a50428351bc72`.
- Capture SHA-256: `22d8253e76516d2862e89a156660260925c833609d8fe1f60728d3cc7ab9224e`.
- Capture size: 800,666 bytes; uncompressed size: 15,676,231 bytes.

The earlier 40-leaf checkpoint and all of its failures retain their original
scope. This partial proof confers no protocol freeze, ABI admission, device or
power-loss qualification, or release approval.
