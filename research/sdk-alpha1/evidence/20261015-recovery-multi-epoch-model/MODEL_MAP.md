# Multi-epoch projection: correspondence obligations

Source baseline: `436cdd49aab36003137b3df6ae8e93f1ec88eafd`.
This is a symbolic projection under investigation, not a verified SDK refinement.

| Concrete behavior | Symbolic representation | Remaining abstraction |
| --- | --- | --- |
| `rekey.rs:88-142`: locally confirmed epoch, stable session/context, target, proposer and completed parent in the offer prefix | One `Setup`; `Ready` retains epoch/root/parent; `scope/6` binds session, context, current/target epochs, actor and parent | One implicit fixed profile; unbounded successors overapproximate finite checked counters; journal operation scope and authorization omitted |
| `response.rs:114-148`: response binds the offer; HKDF uses the previous root as salt and the hybrid shared secret as IKM | `Response_Compute_5` includes inherited `old`, new coins and response-core hash in `root`; next round receives this same root | Free hash and ideal KEM stand in for HKDF, hybrid KEM and computational assumptions |
| `completion.rs:279`: completed transcript digest includes all four flights | Both completion rules construct the next parent from offer, response, final and receipt | Symbolic tuples replace canonical concatenated bytes and domain-separated concrete hash |
| `completion.rs:646-700`: new traffic and one active send epoch; old send closes at signed count | `SendState`, counter successor, and `SendPermit` fence the two closing-signature reservations | No concrete send/receive chains, nonce construction, ACKs, receive closing limits or retention capacity |
| `completion.rs:926-936`: proposer installs the new root and send epoch before receipt acceptance | `Final_Commit_8` updates `SendState` but does not emit `Ready` or `Confirmed` | No persistence failure, rollback or release authorization |
| `completion.rs:1080-1090`: responder completes locally before peer receipt acceptance | `Receipt_Commit_0` emits next `Ready` immediately, with this responder as next proposer | Atomic admitted phase transitions; no crash/restart refinement |
| `completion.rs:1097+`: proposer completes only upon accepting the exact authenticated receipt | `Receipt_Accept_0` verifies scope, transcript and confirmation before next `Ready` | Concrete duplicate handling and stable operation identity remain outside this projection |

The initial root is sampled only once per stable session and explicitly public.
Every later root and parent depends on actual prior-round terms; there is no
round reset and no maximum modeled round count. The first two queries request
specific two-round witnesses within that unbounded transition system.

The normal witness requires actual knowledge of the first completed root and
both second-round reservations after Cut. It requests reachability, not secrecy.
The negative witness places a second-round generation reservation and its single
snapshot before Cut while the first-round receipt to the proposer is delayed.
It requests knowledge of an exact fresh second-round payload. Neither witness
has yet been admitted at the time this map is written.

The candidate universal query excludes later-acquired records of all post-Cut
writes in the target session, not only writes labelled with the target epoch:
later phases can retain an earlier recovery root. It excludes disclosure of the
actual target identity keys for the whole trace and entropy disclosure for the
selected recovery epoch; other epochs and sessions remain possible.

Cut reveals both session wrapping keys. The negative query captures only one
responder record, but this is not a claim that only one wrapping key was granted.
The witnesses require distinct identities, not distinct wrapping keys. The model
permits arbitrary identity and wrapping-key reuse across roles and sessions.
Per-record capture is not the actual whole-journal image boundary. Identity-file
capture is conservatively treated as identity exposure before decryption.

`no_precomp` variants only alter source-precomputation choices. Each successful
annotation generator compares the entire theory after annotation erasure, not
only selected lemmas. The official manual describes these as premise annotations:
https://tamarin-prover.com/manual/master/book/011_advanced-features.html#fact-annotations
Fewer precomputed sources can slow later solving or leave partial deconstructions;
annotation and parser success establish no security property.
