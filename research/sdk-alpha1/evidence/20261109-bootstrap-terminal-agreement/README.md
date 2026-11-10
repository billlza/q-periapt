# Bootstrap terminal agreement — executed assessment packet

Source: `billlza/q-periapt`, commit
`6a0ac0bbd7a5be77443e10b22c20a31f4b3be271`, tree
`de5c5db02bba581850e30c323d6c882e6bad25c2`.

The [assessment](../../../../docs/continuity/BOOTSTRAP_TERMINAL_AGREEMENT_V1.md)
provides an exact full-wire Final invariant and a reduction from the bootstrap's
joint epoch-zero ACK schedule to historical responder activation. The terminal
experiment uses an online, monotone protected family with explicit recipe/state
stopping. This fixes the registration interface before the result is selected.

## Executed result

`CONTROL_RESULTS.json` records an actual run of
`check_terminal_confirmation.py`:

| Check | Result |
| --- | --- |
| Implementation/specification source identities | 16 Git-blob and SHA-256 matches |
| Existing native public synthetic vectors independently recomputed | 8 passed |
| Full-wire, ACK scope, replay and disclosure controls | 18 passed |
| Online protection and guarded-disclosure event controls | 14 passed |
| Transcript/direction/epoch/floor/key-source scope matrix | 192 cases, exact expected classification |

The matrix accepts two entries: the correct transcript and key, direction 1,
epoch 0, with consumed floor zero or one under a sent ceiling of one. All 190
other entries are refused. The checker uses Python's `hashlib` and `hmac`, and
calculates HKDF Extract/Expand directly. It reproduces the native test constants
before exercising the protocol equations.

Signature fields in this small experiment are opaque exact bytes. The
same-body valid-signature premise has its real native execution in R1/R2 of
the [construction matrix](../../../../docs/continuity/BOOTSTRAP_COMPROMISE_REVIEW_V1.md).
This packet does not execute a new native KEM/signature run. Its finite controls
check the reduction's encoding and event interface; the assessment supplies the
analytical proof.

## Reproduction

From a repository checkout whose 16 recorded implementation/specification files
retain their assessed bytes:

```sh
python research/sdk-alpha1/evidence/20261109-bootstrap-terminal-agreement/check_terminal_confirmation.py --source-root . --output /tmp/bootstrap-terminal-controls.json
```

The command checks the complete recorded input set before evaluating the
controls. An input hash mismatch or failed control exits with an error. The
assessed commit above always identifies the original input version. Two older
review documents are retained as historical input identities in the manifest;
their updated successor text is outside the unchanged-equation input set.

## Interpretation

The controls include deliberate counterexamples for omitted requirements:

* Skipping the complete Final-prefix comparison accepts the same-body wire
  alias in the post-authentication schedule model.
* Accepting only the public session ID lets the carrier report the alias as
  established even though the original responder rejected its Final.
* Disclosure of the bootstrap root reconstructs a valid epoch-zero proof;
  the online protected experiment stops before releasing that recipe.

The current source retains the Final and ACK checks. Exact READY replay succeeds
for the original transcript and corroborates the theorem's historical-activation
event. Local initiator activation can remain durable after a forged READY fails;
recovery keeps the original operation and session.

The theorem's joint schedule gap includes the complete protected family and all
retained auxiliary outputs. A later protected disclosure is a stop in this
specific conversion experiment. General adaptive recovery after such disclosure
requires the separately stated provenance stopping/partition composition.

The change is documentation and a reproducible research control. Protocol bytes,
runtime behavior and existing release/CI admission rules retain their current
definitions.
