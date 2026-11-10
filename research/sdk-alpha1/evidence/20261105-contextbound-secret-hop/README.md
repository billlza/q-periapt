# Actual ContextBound input and a conditional secret hop

The [proof note](../../../../docs/continuity/CONTEXTBOUND_SECRET_HOP_V1.md)
derives an ideal-SHA3 private-function replacement only after the selected
component secret has independently been replaced by uniform 32 bytes. The
fixed-target KEM reduction, complete accepted prefix and multi-epoch composition
remain open. Product code is unchanged.

At source `f6de14a347bbd9865077ce4a09d24164b41fe51e`, an isolated Rust probe
calls the actual `q-periapt-core::combine_policy_bound` encoder. Its capture
backend reserves one staging buffer, emits the chosen public fixture input,
computes real RustCrypto SHA3-256 and wipes its staging bytes on drop. It is
test instrumentation, not a product backend for secret inputs. The component
public-key/ciphertext bytes are serialization fixtures, not validated or newly
generated ML-KEM values. No ML-KEM operation or real key/token was used.

Three cases keep the SDK rekey field widths: a base tuple, a first-PQ-secret-byte
change, and a first-application-context-byte change. The emitted input is 2,639
bytes in each case. An independent Python parser checks all ten outer fields,
the three nested policy-context fields, the exact concatenation and SHA3-256.
The PQ secret occupies `[76,108)`. The two changes affect only byte 76 and byte
2607 respectively. All three real Rust/Python hashes agree:

| Public fixture | SHA3-256 |
| --- | --- |
| Base | `95a9d0d7fd12cb60438dc24abcf6dc7d4a5d58100fe23c8d17a65c7de4f99acb` |
| Changed PQ byte | `0ce177c087755d4916767e975aaf6375d9ff4abf6b8e5359484e771a14593147` |
| Changed context byte | `233c38cf8c00e632b101444ce1334f45cc87f705fd256e3e9ccebd0f6e92f722` |

The context-only change concretely distinguishes complete combiner inputs even
with the same PQ ciphertext. A simulator may cache the component test secret
for its challenge ciphertext; it cannot use that ciphertext alone as the cache
key for the combined secret. Exact original retries retain the complete tuple.

The launcher finished with exit code zero in 3.308 seconds, from
2026-11-05 05:11:32.941099 UTC to 05:11:36.250465 UTC. Its parent and component
limits are 900 seconds, with 16-MiB bounded streams. Offline lock resolution,
Release compilation/execution and rustfmt checks passed. The selected source
files, task-private Rust 1.98.1 compiler and probe lock were unchanged. No global
toolchain or dependency installation occurred. The probe has its own build
directory and does not mutate the running Kotlin qualification source.

`CAPTURE.zip` includes the probe and lock, complete command streams/receipts,
all selected source inputs, the three public input files, independent readback
procedure/results and linked proof documents. `FILES.json` and `SHA256.json`
retain member hashes and complete archive readback. The encoding checks are
separate from the mathematical injectivity/freshness argument and do not claim
concrete hash security, a complete simulator, whole-suite execution, platform
qualification or release readiness.

Replay uses the pinned repository checkout and the probe's locked dependencies;
the capsule is not a bundled compiler or complete dependency distribution.
