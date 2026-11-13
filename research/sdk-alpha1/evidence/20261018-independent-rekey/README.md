# Independent four-flight rekey computation checkpoint

The independent Python/OpenSSL peer now computes the canonical v6 offer, response,
final and receipt; performs its own ContextBound KEM, rekey-root HKDF and all three
confirmation MACs; and derives epoch traffic/ACK keys. There is no Rust root-export
hook. `peer/rekey.py` contains computation and transcript validation, separate from
the durable owner still to be implemented. The Rust test driver exposes existing
journal operations and public progress only.

The final local run completes eight alternating exchanges through actual Rust
journals: four independently proposed and four native-proposed epochs. It passes
132 native commands and 108 Python refusals. Each epoch exchanges fresh messages
and consumption ACKs in both directions, including maximum plaintext/AD sizes.
All prior application work is explicitly settled before the test signs the next
retirement assertion. Native history moves beyond four epochs under this workload;
this does not implement independent history retention or unresolved-outcome policy.

The controls include valid identity signatures over invalid confirmation MACs,
incorrect predecessors, different session bindings, invalid ML-DSA and P-256
signatures, wrong KEM ownership and old roots, future-epoch traffic, cross-epoch
ACKs, wrong application AD and expired traffic. Exact Rust response/final/receipt
replay and eight same-process journal reopens preserve the original bytes.
After a native final commit, progress is explicitly `(prior, target, prior)`;
only receipt acceptance yields `(target, target, target)`. New-epoch packets before
admission are refused without preventing their later valid delivery.

The original 41-command/51-refusal volatile lane and six-kill/27-operation
epoch-zero persistence lane remain passing. The native driver passes strict build,
Clippy and formatting; workflow lint and Python AST checks pass. No Rust source was
added: the tracked inventory remains 722. Public readback rechecks all 26 runtime
source hashes, actual ARM64 executable, 32 signatures/prefixes/transcript hashes,
closing counts, directional progress, message/ACK encodings, actual application
bytes and all native command hashes. Runtime tests independently verify secret
KEM/MAC/AEAD agreement; the public reader does not export or rederive those secrets.

**Independent rekey state is still volatile.** Its durable `Session` remains
epoch-zero-only, and snapshot encoding explicitly refuses a nonzero epoch rather
than silently saving it as zero. Durable rekey reservations, exact signed outboxes,
directional cutover commits, aggregate unconfirmed send budgets, retained-epoch
resolution and process-loss recovery are the next required integration. This
checkpoint does not qualify independent durable rekey, fresh entropy after a
retained-state disclosure, post-compromise security, hardware power loss,
cross-host carriers, an installed independent package or release readiness.
