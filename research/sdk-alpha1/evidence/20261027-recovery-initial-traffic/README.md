# Initial traffic in the multi-epoch recovery model

Source: `09b296dba27f4d05d3972ad14d3715ecd3c45e53`.
Pinned Tamarin 1.12.0 and Maude 3.5.1 on Apple Silicon macOS.
The captured natural-number/private-position model now permits application
messages in the initial epoch. Ten auxiliary properties and one initial-traffic
witness pass a joint, fresh-process certificate replay without automatic search.
Multi-epoch message secrecy and full SDK correspondence remain unproved.

## Correcting the execution boundary

The previous model's Setup rule created send states and permits, but omitted
`ApplicationEpoch(s, 1)`. Since Application_Message requires that persistent fact,
the model excluded initial-epoch traffic. Its `initial_epoch_counter_is_zero`
helper was valid in that narrower model and cannot be reused after enabling
initial traffic. The SDK's initial application path is visible in the independent
consumer's [traffic checks](../../../continuity-openssl-peer/traffic_checks.py).

The only operational change adds the existing `ApplicationEpoch` fact to Setup's
outputs. Removing exactly that output restores the preceding operational prefix
byte for byte. All 20 rules, the disclosure capabilities, equations and restriction
remain; all 25 preceding complete query formulas are retained. This is a change
to the allowed executions, not an observer-only extension or a proved equivalence
to the SDK or earlier Peano model. Positive naturals encode zero as `%1` here.

The additional existential query exhibits distinct device signing keys, distinct
storage keys, no rekey reservation, and an initial send advancing the encoded
counter from 1 to 2. Search and a separate no-search replay each verify it in
414 steps. Setup still exposes the initial root as in the preceding recovery
model. This witness establishes an allowed execution and the obsolete helper's
scope boundary; it is not an SDK attack or an initial-secrecy result.

The old zero-counter query remains visible and unproved, with no `reuse`
annotation. Its direct search ended incomplete at 77 steps. The verified
existential contradicts that invariant in the expanded model, but the direct
query's recorded tool status is not relabeled as `falsified`.

## Checked dependency closure

| Property | Steps | Proof premises |
| --- | ---: | --- |
| `phase_position_event_is_unique` | 29 | None |
| `first_responder_ready_event_is_unique` | 285 | Phase-position property |
| `ready_root_is_initial_or_hashed` | 11 | None |
| `produced_state_role_and_epoch_have_public_constructors` | 191 | The preceding three properties |
| `produced_counter_has_public_constructor` | 35 | None |
| `application_counter_has_public_constructor` | 17 | Produced-counter property |
| `produced_send_root_is_initial_or_hashed` | 55 | Ready-root property |
| `ready_epoch_and_parent_have_public_constructors` | 12 | The preceding seven properties |
| `generation_and_signing_secrets_are_distinct` | 1 | None |
| `generation_and_encapsulation_secrets_are_distinct` | 1 | None |
| `initial_epoch_traffic_advances_counter_is_executable` | 414 | None |

The joint replay uses `hide_lemma` to preserve each certificate's explicit premise
set. These annotations control proof dependencies, not protocol executions.
The acceptance check nevertheless requires every one of the ten helper results
and the witness to verify, together with the complete 26-query inventory.
The fresh joint replay took 243.17 seconds with the unchanged 900-second,
12-GiB and single-capability limits. It used neither `--prove` nor an oracle.

These results establish the stated structural properties. They do not establish
counter uniqueness, nonce safety, computational security, multi-epoch recovery
secrecy or implementation refinement. Generation-secret derivation provenance,
the multi-epoch secrecy query, local-root inheritance in this expanded model,
and the two-round execution/disclosure queries remain open. Earlier checkpoints
retain their original model-specific scope.

## Retained failures and proof repairs

The first old-certificate replay left four helpers incomplete. Later helpers
could display conditional success, but the required dependency group was rejected
despite prover exit zero. The first initial-traffic witness search also remained
incomplete; a breadth-first search found the recorded witness under the same
depth and resource limits.

The role/epoch helper was regenerated. The counter helper was proved independently
and then replayed as the sole premise of the application-counter proof. A batched
shape search was interrupted without a terminal receipt or complete proof; its
exit is unknown, and a later process inventory confirmed it had stopped.

The separate send-root search reached the 900-second limit. Its controller sent
SIGINT, then encountered EPERM when attempting process-group cleanup after the
five-second wait. The process was subsequently confirmed absent. No complete
proof was obtained, and the error and runtime statistics are retained. No
permissions or resource limits were changed. The successful repair instead asks
Tamarin to check contradiction at the seven newly exposed initial-epoch/Setup
branches in the existing proof script. A fresh replay verifies all those steps,
the 55-step send-root result and its 11-step Ready-root premise.

## Capture and reproduction

`CAPTURE.zip` contains 141 members and expands to 5,434,884 bytes. Its SHA-256 is
`851144c79fd0d16fcbe14e364413a381461c68bb3e8b1dcd8cb578783c2314b2`.
Every member was read back and rehashed; `CAPTURE.json` records the closed member
inventory, complete query results and dependency graph. Raw failed attempts are
retained alongside the successful certificates.

The final replay input and runner are in
`experiments/p0-initial-traffic-composition-replay-01/`. The capture includes the
pinned tool identities, arguments, resource bounds and repository-dependent
runner. Reproduction requires the recorded repository source and pinned tools;
restore their filesystem locations or explicitly map them while retaining the
binary hash checks. Use a fresh output label, replay mode and the selected lemma
list in `selected.json`. Accept the complete required verdict set, not process
exit zero or a search for placeholder words in a certificate.

The SDK runtime and original device/account/storage state were not changed.
This is local research evidence; hosted replay, full platform qualification and
0.2.0 release approval are separate open gates.
