# Continuity upgrade and maintenance admission contract

Status: **candidate admission requirements and current compatibility evidence**.
This document makes the version boundary explicit; it does not freeze the
candidate, admit its ABI into the product, or declare a published 0.2.0 release.
The [product admission](PRODUCT_ADMISSION.md),
[storage recovery](STORAGE_RECOVERY_V1.md) and
[security maintenance policy](../../SECURITY.md) remain applicable.

## Program version, logical image and database format

These are separate compatibility decisions. A program replacement can preserve
the existing logical format. An authenticated logical-image transition can occur
inside the same physical database format. A database-engine upgrade alone does
not establish either protocol or logical-image compatibility.

The native candidate and independent Python wheel currently both carry version
`0.0.0`. That string cannot identify a compatible pair. Qualification must bind
source commit, package/archive digest, installed executable/module digest,
dependency resolution, platform and the actual reader/writer scenario. The
release manifest must eventually replace this preview ambiguity with a unique
product version and the frozen contract digest; renaming the package is not that
qualification.

| Persisted object | Current reader/writer boundary | Upgrade implication |
| --- | --- | --- |
| Device journal | `continuity_device_candidate_v21`; paired `QPVLT021`/`QPVIMG21` through `QPVLT024`/`QPVIMG24`, selected by publication and registry binding | Earlier journal tables are refused. Registry adoption is an explicit existing transaction; no general v1–v20 migration exists. |
| Installation | `continuity_installation_v1`, `QPCINS01`, original journal ID, owner, wrapping-key commitment, policy, path and witness binding | Open the original configuration; a missing or incompatible configuration is not first use. |
| Session cleanup archive/index | `QPCSCA01` / `QPCSIX01` | Preserve original cleanup bindings. An archive does not recreate an operational session or current authority. |
| Witness image | `continuity_anchor_candidate_v1`; recognized tags `QPANC001`–`QPANC004` and `QPANC006`–`QPANC022`; no `QPANC005` | Opening authenticates without rewriting the logical image. A later authorized transaction selects the representation required by its retained features. This is not a promise that every older reader accepts it. |
| Witness handoff plan | `QPAHPL01` and `QPAHPL02` retain their original signed bytes | A legacy 01 plan only establishes the first transition from its original namespace; it cannot stand in for a bound later handoff. |
| SDK signed-policy store | Separate [policy maintenance tool](../POLICY_MAINTENANCE.md) for the original five-field `QPeriapt-Host-Policy-v1` redb-format-2 store | Its explicit engine transition does not migrate a Continuity journal, installation, enrollment image or Witness database. Its existing platform and interruption limits still apply. |
| Unpublished publication control | `.private-attempt-v2-*`, `QPSTG002`, independent `QPSTGL02` lease; cleanup intent `QPSTGC02` and receipt `QPSTGD02` | Explicit maintenance accepts only the bound original scope and filesystem identities. Legacy prefix-only residues, experimental v1 records, incomplete controls, copied identities and controls moved to a different parent are refused. Operational storage formats are unchanged. |

The Witness compatibility above is implemented, not merely proposed. In
particular, authenticated 001 state supplies its original owner as the initial
current credential owner; an ordinary transaction can write 002. A joint
transition can atomically advance 001/002 to 003 while preserving its terminal
floor and acknowledgement. Grant-only Closed state uses 004; after all such slots
are acknowledged, the remaining floor/ACK state has the 003 representation.
Neither direction clears a floor. See
[Witness image compatibility](../../research/continuity-identity-candidate/ANCHOR_WITNESS.md)
and the actual
[recognized versions](../../research/continuity-identity-candidate/src/anchor/store/image_version.rs).

`AnchorStore::retain_original_identity` is a separate explicit admission for an
existing subject. It requires the original owner and full device public key,
retains the current head/authority and pending operations, and does not derive
current permission from an expired historical credential. Exact retries do not
write. The original signed credential/roster and independent pins must be
available; the updater must not invent a replacement identity. See the
[implementation contract](../../research/continuity-identity-candidate/src/anchor/store/lineage.rs).

## Replacing the program while retaining the state

A qualified replacement uses the following procedure:

1. Identify the installed version and the intended replacement from their
   authenticated distribution records and integrity manifests. Confirm that the
   replacement supports the actual original formats and pending operations.
2. Stop dispatch and release all application/SDK owners. A database lock conflict
   means another owner still exists; it is not permission to bypass the lock or
   copy the database to a second active location.
3. Retain the original installation/configuration, journal and write intent,
   protected keys, account/policy/roster records, Witness selection and independently
   trusted freshness inputs. Retain application effect IDs and deduplication
   records separately. Do not roll the Witness back with a client backup.
4. Replace the program and open those same original stores with the original
   identity and protection. Do not provision, relocate or regenerate state on an
   open failure. Reconcile an unknown outcome using the original pending target
   and operation identity, including its original authorization requirements.
5. Admit new traffic only after current account/device/policy/Witness authority
   passes the normal checks. Historical recovery or successful decoding alone is
   not traffic authorization. An expired runtime still needs its explicit renewal
   or restricted-recovery procedure.

An older program may be selected only for a separately qualified reader/writer
edge and the current authoritative state. **Program rollback is not backup
restoration.** If the newer writer has introduced an unsupported tag, table or
operation, the older reader must fail and leave the lineage available for the
compatible program. Removing the new record, editing the version tag, restoring
an older journal or generating a fresh operation is not a rollback procedure.

For a format-changing update, admission must identify the source and target
formats, preserved bindings, exclusive ownership, atomic publication and exact
recovery after an uncertain commit. Test the actual old writer and new reader
where that version edge is promised. Existing current-code legacy fixtures remain
valuable decoder/transition tests, but do not constitute a historical installed
writer experiment. An incompatible network/protocol or ABI meaning requires an
explicit version/identifier and migration rule; an unsupported peer must not be
silently downgraded to a weaker operation.

## Retention, capacity and failed initialization

Keep terminal fences, original receipts and one-time-key occupancy until the
existing authenticated retention/cleanup contract permits a change. Capacity
refusal must not evict them or resurrect an older publication. Cleanup archives
and lifecycle retirement provide their declared restricted scope; neither grants
fresh operational authority. Current resource observations and aggregate caps
remain documented in [budgets](BUDGETS_V1.json) and
[performance](../SDK_PERFORMANCE.md), with their measured workload limits.

Unpublished first-use staging files are not recovery inputs or authority to delete
anything. A failed first-use retry requires its retained original explicit intent;
it does not permit repeated unbounded provisioning. Formal destination names,
previously active state and unknown-commit records must remain intact. Publication
now retains a separate control lease before exposing the original payload, through
rename and both parent syncs. The explicit Rust API and `qperiapt publication-reclaim`
command implement the [v2 maintenance contract](../PRIVATE_PUBLICATION_MAINTENANCE.md).
They admit the whole remaining payload and all file leases before deleting it,
retain the original cleanup intent/result through interruption, and never follow
the formal destination. There is no automatic sweep. Matching a prefix or a prior
error is insufficient authority. Legacy/incomplete control disposition and the new
installed/platform qualification remain separate admission obligations.

The [isolated maintenance protocol experiment](../../research/sdk-alpha1/evidence/20261104-staging-maintenance-protocol/README.md)
reproduces why a pinned staging-directory descriptor alone is insufficient:
after publication it still refers to the formal directory. A separate continuous
control lease protects the tested file/directory cases, but that experiment's
extended aggregate failed when the existing operational opener refused a valid
empty unpublished payload. The failure remains retained. The subsequent v2
implementation uses a separate internal disposable-file admission with the original
record/lease, ownership, ACL, link and inode checks. The normal-store opener still
refuses empty files. This implementation does not retroactively qualify the failed
experiment or authorize cleanup of old residues.

The existing security policy supports the latest verified ABI 2 publication set
while its receipt selects it as current. This document does not invent an LTS
duration or extend preview support. Each future supported update must publish its
format/ABI compatibility, preserved or deprecated entry points, affected platform
qualification and required maintenance action. Deprecation cannot silently remove
the original-operation recovery needed by retained state; any removal needs an
explicit successor path and versioned contract.

## Current qualification and remaining admission

The [installed program-replacement checkpoint](../../research/sdk-alpha1/evidence/20261104-installed-program-upgrade/README.md)
uses independently packaged native builds from `6ce866b3` and `21e00e9c`, a freshly
installed independent Python wheel, original stores and actual process replacement.
It covers ordinary successor communication plus Witness interruption before
commit and loss of the reply after commit. The native fixture combines the peer
and test Witness in one process; independent operation of a remote Witness remains
a separate deployment boundary. Synthetic fixture clocks are explicit.

This pair shares the current storage formats. Its relevant source change adds
signature-purpose contract metadata, not a legacy storage migration. These
results establish this finite program-replacement edge, including original
pending handshake/message/rekey behavior. They do not qualify all historical
candidate images, arbitrary downgrades, a published 0.1.x-to-0.2.0 Continuity
migration, foreign installers, other platforms or physical power loss.

Before formal admission, bind this compatibility table to the final package and
contract versions, explicitly dispose of preview-state support, qualify each
promised actual migration edge and its installer failure behavior, and close the
installed/platform maintenance path and legacy-residue disposition. Preserve recognized Witness compatibility
and the existing policy-maintenance tool's narrow scope. Do not mark the ABI,
storage contract or release frozen on the strength of this checkpoint alone.
