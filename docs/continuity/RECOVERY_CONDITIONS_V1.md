# Candidate recovery conditions and falsifying traces

Status: implementation obligations for the full 0.2.0 profile. This is neither a
frozen protocol nor a cryptographic proof. It records what a future recovery claim
must establish, and what the existing executed experiments already contradict.
The product ratchet construction, complete wire grammar and numeric progress floor
remain open in [PROTOCOL_V1.md](PROTOCOL_V1.md).

## Progress observable by the service

The service may report installed, sending, receiving and peer-confirmed epoch
identifiers, the exact pending control operation and whether its authenticated
progress budget permits another application send. It cannot observe an adversary's
knowledge. A valid confirmation demonstrates possession of a transcript-bound key;
it does not demonstrate that nobody else holds that key.

Two executed counterexamples make this distinction operational:

- The [passive state predictor](../../research/continuity-spqr-reference/COMPROMISE_EXPERIMENT.md)
  derives an additional epoch from a disclosed pending decapsulation key and later
  public ciphertext. The current emitted epoch does not bound exposure.
- The [whole-KEM active fork](../../research/continuity-whole-kem-reference/ACTIVE_COMPROMISE.md)
  obtains all 1,536 actual sender keys while honest endpoints confirm fresh epochs
  on two attacker-controlled exchanges. More frequent rekeying does not remove
  continuing impersonation by a disclosed session authenticator.

These observations do not establish that every unpredicted message is secure.
They falsify unconditional recovery labels and identify assumptions that must be
tested in the complete hybrid construction.

## Disclosure cases that must remain distinct

| Disclosed state / intervention | Consequence to preserve | Required recovery premise or action |
| --- | --- | --- |
| Current root and traffic-chain state; adversary subsequently only observes | Existing chains remain derivable | A later authenticated exchange must contribute unknown fresh secret material to the keys actually used for subsequent traffic |
| Pending KEM private key or its recoverable generation reservation | A later public ciphertext can expose the corresponding future epoch | Do not classify that pending exchange as fresh relative to this disclosure; follow all derivable descendants before identifying a later candidate recovery point |
| Session authenticators plus continued active packet replacement | The active-fork experiment maintains two accepted conversations | State the end of active intervention, or establish transcript binding to separately uncompromised authority; the old root MAC is insufficient |
| Device signing authority | Fresh signatures from that key no longer distinguish the honest device | Independently authenticated revocation and replacement generation; no silent session repair or reused journal owner |
| Account root / independently retained authority | Device replacement issued solely by the compromised root does not restore trust | Explicit authenticated root-replacement procedure and new independent trust configuration |
| RNG state or a compromised entropy source | Later API calls need not introduce unknown randomness | State when the entropy source becomes trustworthy; counters and wall-clock time cannot supply this evidence |
| Old sealed database restored | Old message keys, counters and pending operations may reappear | Required-witness reconciliation against independently retained state, or explicit new device/session provisioning; never implicit reset |
| Wrapping key plus retained pages/backups | Logically removed secrets can remain decryptable | Bound the compromise/observation model and implement any claimed cryptographic erasure separately |

The classical and post-quantum claims also differ. A quantum adversary may learn
the classical contribution; a PQ recovery argument must still identify an unknown
PQ contribution under the selected KEM assumption. A hybrid claim must state the
combiner assumptions and preserve the complete authenticated context. Finite
message-key comparisons do not replace that argument.

## Durable freshness is reservation freshness

The SDK's sealed operation owner intentionally regenerates the same private key,
encapsulation and signature from the exact reserved command after a crash. That
is required for nonce/key uniqueness and exact unknown-outcome reconciliation.
It also means that execution after a compromise cut does not by itself constitute
fresh entropy.

A disclosure trace must include the journal wrapping/recovery key and every
retained entropy reservation within its scope. If those bytes reveal a future
private key, the trace must treat that key as exposed even before the provider has
executed it. Reopening, a second provider call, a new ciphertext wrapper nonce or
a successful witness query does not make the same reservation fresh. New entropy
must be reserved only for a genuinely new, admissible transition, never as a retry
of an uncertain old operation.

The existing passive component experiments serialize KEM private keys directly;
they do not yet model the candidate's sealed operation reservations. That
implementation-correspondence experiment remains required.

## Control delivery and bounded continuation

Every compared construction has an executed one-way application-traffic trace
without fresh PQ progress. The product transport must therefore carry pending
control requests, responses and confirmations independently of application payloads.
Those control messages still require exact durable outboxes, authenticated context,
revocation checks, bounded retries and resource accounting.

A signed closed profile must set a hard application-send budget while fresh PQ
progress is pending. Counting local sends alone is not progress. At exhaustion,
new application work must fail with an explicit pending-rekey condition, while
read-only reconciliation and exact control retransmission remain available.
Loss of control delivery can prevent liveness; it must not cause a reset, skipped
confirmation or an unapproved weaker profile. An idle peer that receives control
traffic must be able to respond without an application creating dummy messages.

Choosing the budget requires a matched full-profile measurement that includes
control-only traffic, bandwidth, durable writes, latency and energy. The existing
32/64-message component intervals are experiment parameters, not product defaults.

## Required trace and implementation evidence

For each claimed recovery point, retain the exact protocol profile and source,
disclosure cut and fields, public delivery/active-intervention schedule, pending
reservation ancestry, fresh contribution/confirmation dependencies, actual
message-key agreement and all retained old-epoch keys. Report uncomputed keys as
uncomputed until the construction's argument justifies a stronger statement.

The complete implementation must exercise both roles, asymmetric traffic,
control-only replies, loss/reorder/duplicates, concurrent update requests, old-epoch
delivery, budget exhaustion, revoked peers, expired authority, process loss and
unknown commit results. The required witness and device-generation rules apply
to the same transaction as each ratchet transition. A component trace, a journal
unit test and a formal model each establish different parts of this obligation.

The [Double Ratchet recovery discussion](https://signal.org/docs/specifications/doubleratchet/#recovery-from-compromise)
and [ML-KEM Braid vulnerable-message analysis](https://signal.org/docs/specifications/mlkembraid/#the-vulnerable-message-set)
motivate the distinction between delivery-dependent progress and adversary-dependent
recovery. Their construction-specific results are not inherited by changing this
repository's authentication, KDF, wire or persistence composition.
