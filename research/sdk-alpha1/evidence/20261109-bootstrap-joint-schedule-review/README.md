# Bootstrap joint-schedule assessment calculations

Prepared against source `a4c089570c787522210d16226219c0cc8aa9b05e` on
2026-11-09 for the
[bootstrap joint-schedule and retained-state assessment](../../../../docs/continuity/BOOTSTRAP_JOINT_SCHEDULE_REVIEW_V1.md).

`SOURCE_PINS.json` identifies 36 inspected implementation, contract and proof
files by exact Git blob, SHA-256 and byte length. The check first compares all
of those bytes with the supplied source root. `RESULT.json` is the result of
the check against the exact prepared-source snapshot. To reproduce from a
later checkout, supply a separate checkout/export of that pinned source. The
assessment also updates its older review entry point, so those document bytes
are deliberately compared with the stated original basis, not a later edit.

```sh
python research/sdk-alpha1/evidence/20261109-bootstrap-joint-schedule-review/check_review.py \
  --source-root /path/to/source-at-a4c08957 \
  --output /tmp/bootstrap-joint-schedule-result.json
```

The deterministic calculation completed with:

| Check | Result |
| --- | --- |
| Exact source/proof blobs | 36 matched |
| Existing public synthetic vectors, independently recomputed with Python `hashlib`/`hmac` | 10 matched the expected hex values in the pinned Rust test sources |
| Bootstrap info / root info / activation info lengths | 62, 70, 70 / 93 / 111 bytes; SDK initial-confirmation info is 178 bytes |
| Initial activation HMAC message lengths | 112, 144, 144, 144, 144 bytes |
| Manual SHA-256 compression evaluation of the 64-byte HMAC Extract equation | 3 public fixtures matched standard-library HMAC |
| Named phase/disclosure closures | 32 expected projections matched, including separate PQ/classical prekey leaves, consumed/abandoned/retired records and retained reusable tokens |
| Independent guard formula versus iterative record/replay closure | All 256 subsets of the declared eight-atom fixture matched |
| Selected prekey component coverage | All 16 token/key subsets matched the requirement to cover both authenticated selections |
| History controls | Late matching-key disclosure, retained acquisition after local deletion, public extraction of pending target ciphertext, and an intact pending target passed |
| Alias controls | SDK salt zero-extension, the shared 32/64-byte first private point, and a forced pad-state alias were preserved; salt-string-only indexing produced the expected different partition |
| Protected/unprotected activation interface | Nine controls retained first-allocation marks, alias sharing, real activation and ACK derivation for disclosed unprotected roots, and the cumulative recipe stop before a protected root return; late promotion and independent activation at a disclosed root were detected |

The disclosure fixture supplies the exact later public transcript as an
available input. A phase containing an original replay recipe can consequently
be followed through its eventual descendants. This does not move unpublished
wire bytes back to the capture time. The `messages_epoch0` fixture represents
initial activation; later acquisitions must follow their actual retained
epochs and current root. The fixed-point model evaluates only the named
decryption, replay and schedule rules. Its selected PQ and classical prekey
facts denote restored components matching their respective authenticated public
selections; a token for just one leaf does not supply both facts.

These are encoding calculations and finite model checks. The code does not
execute the Rust implementation, ML-KEM, ML-DSA, a platform adapter, CI or an
external review. The assessment's cryptographic results come from its stated
proofs and premises. Earlier native execution receipts keep the original source
identities cited by the existing bootstrap construction review.
