# Installed browser pending recovery through renewed traffic

The current-source npm archive completed two fresh Chrome Worker flows through
the installed web entry and real IndexedDB storage. Both retain one original
session, an unacknowledged application message and a partially completed rekey
before an ordinary remote-roster R1-to-R2 write loses its result. The roster keeps
the existing peer as an authorized member; this is a nonterminal update, not a
request to resume a deliberately closed session.

| Original R2 outcome | Worker calls | Actual Worker terminations | Held Query cancellation | Independent completion |
| --- | --- | --- | --- | --- |
| Not dispatched to witness | 41 | 2 | 1 | Exact original target approved and completed |
| Applied; reply lost | 40 | 2 | 1 | None; fresh authenticated Query suffices |

P0 expires by real wall clock before recovery; credentials remain valid. Public
recovery requests create no operational runtime and send no network request.
Complete original proposal and metadata survive a cancelled held Query and Worker
termination before confirmation. A second termination occurs after local
confirmation but before the host receives success. The root lease is observed
before each termination and its release is observed before reopening. Exact
confirmation retries remain Query-only; absence alone is refused. Modified
metadata is rejected before network access, and an unapplied target cannot be
confirmed before the independent controller completes it.

The controller's separate inspector verifies signed public R1/R2 material using
independently retained account and device inputs. It compares every source and
target record, allowing exactly one remote-roster change while retaining the
original live session, unknown message and pending rekey. Its approval is distinct
from the historical device signature. The ordinary HTTP endpoint never invokes
privileged completion. Five substituted public inputs are refused by the same
inspector without opening a private runtime or publishing an approval.

After recovery, independent account and policy roots approve P1 against the
original enrollment request. Witness preparation, commitment and retirement
complete on the same journal. The native counterpart separately renews its own
authority. Old direct session reopening is refused; the explicit continuation
path retains the original pending rekey and message. Both flows finish epoch 1,
replay the identical first control frame and original application ciphertext,
confirm the existing receiver effect, and complete the original reverse-direction
message. A duplicate reverse frame invokes no second application callback. A new
message has a distinct ID and ciphertext, reaches confirmed consumption and leaves
exactly two native effects: the original message and the new message. Confirmation
of the old pending-write target conflicts after the policy operation advances the
head.

Source is `a4c023bc52f00d0c2f630a6e18bc65ce55c7be25`. The same actual archive was built and
installed outside the checkout; installed Node and strict TypeScript checks
passed before browser execution. Fresh native fixtures use the current canonical
dependency versions and strict warning-as-error compilation. Initial lockfile
generation selected seven newer transitive dependencies and was rejected before
compilation; using the existing lockfile with Cargo metadata retained the canonical
versions. Both rejected preparation lockfiles are preserved. No SDK implementation,
protocol, storage grammar or security policy changed in this checkpoint.

| Artifact | SHA-256 |
| --- | --- |
| Installed npm archive | `ca30d0c531978e0f8bf5f2437f1918d6647af27a393e605dfcff22aca85e09da` |
| Public capture | `b43c84652f0ddce36a48a4d26b43fb164d62a60e787ce70cfe1fb3d0c961a295` |

`CAPTURE.zip` contains 4919 public members, including executed
fixtures, public inputs, command receipts and all 81 Worker
results. Independent readback checks every member hash and the complete behavior
census. Public-reader controls reject every individual call substitution, a
claimed second approval on the applied route, missing termination, changed replay
ciphertext and extra business effects. Private identities, keys, browser profiles,
runtime stores and compiler outputs are excluded. The browser session and fixture
server are closed; these runtime cohorts are sealed and must not be reopened.

The older [pending recovery checkpoint](../20261014-browser-pending-write-recovery/README.md)
intentionally finishes by closing sessions and accounting for loss. This checkpoint
adds a separate nonterminal path to actual continued traffic. It uses the same Rust
engine on both sides and a loopback carrier. It does not establish independent
implementation interoperability, mobile-browser qualification, deployed HTTPS,
physical power-loss durability or post-compromise secrecy. Protocol recovery
analysis, remaining lifecycle/platform composition, Linux/independent endpoints,
performance/energy/tail and peak-memory costs, maintenance/freeze, external review
and exact-source hosted checks remain 0.2.0 release gates. The single accepted
Android phone remains sufficient for its recorded scope; no Intel Mac requirement
is introduced.
