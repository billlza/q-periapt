# Continuity 0.2.0 compatibility policy

Selected on 2026-11-09 against integration source
`e108ff9df704c8a551e9d3b62c0462c88384d18a`.

This policy adopts the existing reader/writer formats, original-state replacement
procedure, explicit maintenance operations and preview dispositions for
`q-periapt-continuity` `0.2.0`. The compatibility selection is complete. The final
selected distribution will bind its own source, artifact digests, applicable
qualification and specification-lock identity under the existing
[admission plan](RELEASE_0_2_ADMISSION_PLAN.md).
`BUDGETS_V1.json` retains `frozen_product_contract=false` until that coordinated
admission change.

The [source distribution](SOURCE_DISTRIBUTION_0_2.md) retains the existing Rust
library target and versioned Continuity `qpc-owner/1` interface alongside SDK C
ABI 2. Package versions, protocol domains, authenticated logical images and
physical database formats remain separate identities. This policy carries
forward the [upgrade and maintenance contract](UPGRADE_MAINTENANCE_V1.md).

## 1. Selected persisted formats

| Object | Selected reader/writer formats | Preserved behavior |
| --- | --- | --- |
| Device journal | Table `continuity_device_candidate_v21`, with the four envelope/image pairs below | Select the representation from the retained publication and registry-binding state. Earlier journal tables are refused; registry adoption remains its existing explicit transaction. |
| Installation | Table `continuity_installation_v1`, image `QPCINS01` | Preserve the original journal ID, owner, wrapping-key commitment, policy, paths and Witness binding. An absent or incompatible active configuration is not a first installation. |
| Session cleanup archive / index | `QPCSCA01` / `QPCSIX01` | Preserve the original cleanup scope and authentication. Restricted recovery keeps its original authority and loss-accounting conditions. |
| Witness image | Table `continuity_anchor_candidate_v1`; `QPANC001`–`QPANC004` and `QPANC006`–`QPANC022` | Authenticate the recognized image on open. An authorized transaction selects the representation required by its retained features. `QPANC005` remains outside the recognized set. |
| Witness handoff plan | `QPAHPL01`, `QPAHPL02` | Preserve the original signed bytes. An 01 plan denotes its original first namespace transition; later bound handoffs retain their own required evidence. |
| Unpublished publication maintenance | `.private-attempt-v2-*`, record `QPSTG002`, independent lease `QPSTGL02`, cleanup intent `QPSTGC02`, receipt `QPSTGD02` | Admit only the exact original parent, control, lease and payload identities under the existing v2 maintenance operation. |
| SDK signed-policy store | The original five-field `QPeriapt-Host-Policy-v1` redb-format-2 store, through the separate policy-maintenance tool | Retain the existing explicit engine-transition scope. That tool does not migrate Continuity journal, installation, enrollment or Witness images. |

The journal pairs are exact; publication and registry binding are independent
retained features:

| Publication record | Registry binding | Encrypted envelope | Logical image |
| --- | --- | --- | --- |
| Absent | Absent | `QPVLT021` | `QPVIMG21` |
| Present | Absent | `QPVLT022` | `QPVIMG22` |
| Absent | Present | `QPVLT023` | `QPVIMG23` |
| Present | Present | `QPVLT024` | `QPVIMG24` |

These mappings and their authenticated fields come from the
[storage contract](STORAGE_RECOVERY_V1.md#aggregate-image-and-local-write-intent).
The recognized Witness transitions preserve terminal floors, acknowledgements,
pending operations and original identity. Reading an older recognized image does
not grant an older program permission to read every later representation. The
[policy-store maintenance](../POLICY_MAINTENANCE.md) and
[publication-maintenance v2](../PRIVATE_PUBLICATION_MAINTENANCE.md) contracts retain
their separate scope, filesystem ownership and interruption rules.

## 2. Selected preview and refusal policy

| Input or requested action | 0.2.0 policy |
| --- | --- |
| Original state in a listed format | Use the existing authenticated reader and retain the original installation, protected keys, contexts, pending operations and independent trust inputs. New work still passes current authority checks. |
| Known same-format program replacement | Apply the original-state replacement procedure below. The two executed source/artifact edges in section 4 are the retained replacement evidence; the selected 0.2.0 distribution receives its own final binding. |
| A recognized older Witness representation | Preserve its implemented reader and explicit transaction behavior, including historical confirmation and current-authorization distinctions. No terminal floor or original operation is cleared to admit the image. |
| An unidentified preview distribution or an unlisted package/format migration | Do not select it as an authorized installer/replacement edge. Preserve the original state and its supported recovery path. A format tag alone is not distribution provenance. |
| An unsupported table, image, version or incompatible pending operation | Return the existing refusal and preserve the lineage for a compatible program. Do not edit tags, delete the new record, restore an older journal or reprovision to make the open succeed. |
| A legacy prefix-only residue, experimental v1 record, incomplete control, copied control identity or control under a different parent | Refuse automatic reclaim. Retain the original bytes; the v2 maintenance API does not acquire authority from a filename prefix or an earlier error. |
| Missing active installation files, a formal destination, or an unknown commit | Reconcile through the original identity, intent and result where the existing contract permits it. Do not interpret the condition as permission for fresh initialization or a new operation. |

These choices dispose of preview support by preserving the listed current
readers and the existing explicit operations. There is no selected general
v1–v20 journal conversion or 0.1.x-to-0.2.0 Continuity migration. An additional
future edge must identify its actual source and target before being offered;
it is not an outstanding obligation of this selected 0.2.0 policy. Preview
provenance is a distribution/installer decision, without adding a new runtime
format detector.

## 3. Original-state replacement and maintenance

1. Select the installed and replacement programs from their authenticated
   distribution records. Match the original formats and pending operations to
   the replacement's declared support.
2. Stop dispatch and release the existing owners. Preserve exclusive store
   ownership; a live lock remains a live owner, not permission to open a second
   copy.
3. Retain the original installation, journal, write intent, protected keys,
   authority records and Witness selection. Preserve independently committed
   application effects and deduplication records. Keep the independent Witness's
   current history separate from any client backup.
4. Open those original stores with their original bindings. Reconcile an
   uncertain outcome using the retained operation ID, target and authorization.
   Resume an admitted operation through its original recovery path.
5. Admit fresh traffic after the normal current account/device/policy/Witness
   checks. Expiry uses the existing renewal or restricted-recovery path.

The executed backward selections in section 4 use the same current authoritative
stores. They preserve the qualified reader/writer edge and do not restore a
backup. An incompatible older reader refuses the state.

For unpublished first-use state, use the existing continuously leased v2
maintenance operation and its complete payload preflight. Retain the original
cleanup intent and result across interruption. Formal destinations, active state,
unknown outcomes, one-time-key occupancy and terminal fences keep their existing
protection. Reclaim remains explicit; no automatic sweep or capacity-driven
history eviction is selected.

## 4. Executed same-format replacement edges

Both retained experiments use Apple M4 Max, macOS 26.7.2, actual installed native
crate/SDK consumers built outside their source checkouts, and a freshly installed
independent Python wheel. The native fixture combines the peer and test Witness
in one process with loopback communication and explicit synthetic clocks. These
source-bound process-replacement results retain that execution scope.

### Exact original programs

| Program | Native source commit | SDK producer commit |
| --- | --- | --- |
| A: original installed build | `6ce866b31088b3215bcc24bcfef84b4075ff5907` | `6084f3bfb09333f6b66291b38809ed512296a27b` |
| B: signature-purpose contract build | `21e00e9c3cfd193b9f51491888347f583620dfe0` | `6084f3bfb09333f6b66291b38809ed512296a27b` |
| C: publication-maintenance cohort | `4effa8b2b25e7403ab912b65894a7d1e73695542` | `f560d803c43a24fff222daa5e5e5bd623bfdf874` |

| Program | Original crate bytes / SHA-256 | Installed executable SHA-256 |
| --- | --- | --- |
| A | 1,958,765 / `e0d32e8e142a386147a88d9d4fd4eac42efb472a9c691c9405055ad69318f993` | `f7fe7507bdd539b4404709b45df207869b5d06ecfc1f62f979c866e01f8437a8` |
| B | 1,959,062 / `1326dbd2ba1c93f950a5f582e11af1514a017f0275d643812b7072da90ba54a9` | `c6af99c69f87f15f7c741ed97161b41c6b1673bae6ecc12f4ef4ea5a51e12b22` |
| C | 1,959,516 / `9bd308702bbb922122ae9f69c40d0cd691f67da9ef0d7d6c2b5381adf2cce163` | `eaf5e7cc305775b7d13292252dfba581bc797bca90be2a2b94d66ba2c2205254` |

The crate hashes and sizes are recorded in the original
[A/B inventory](../../research/sdk-alpha1/evidence/20261104-installed-program-upgrade/SHA256.json)
and [B/C inventory](../../research/sdk-alpha1/evidence/20261104-maintenance-program-upgrade/FILES.json).
Each crate has 767 members. A/B changes three signature-purpose contract files
and keeps all storage encoders/decoders byte-identical. B/C changes one native
document and four test files; its shared SDK carries the publication-maintenance
implementation. All 20 native fixture source/manifest inputs match for B/C.

| Shared installed input | Original SHA-256 |
| --- | --- |
| SDK producer `6084f3bf` report | `d9cd990bf3dc6a731ec09b659fdc38f3f3cbc17b2f035b09e5e61094cbc11885` |
| SDK producer `f560d803` report | `93fbef9dace1af6550a85095f6d2392285197a8fe589838f4d6f8447ba03c4f8` |
| Independent Python wheel in both edges | `596bba62781296558a64d768a12ed618043b8cf3e14070cdf81c2ed423d3a094` |

### Results carried forward

| Exact edge | Completed execution and readback | Original capture identity |
| --- | --- | --- |
| A ↔ B | Three replacement scenarios: ordinary lifecycle, Witness mutation interrupted before dispatch, and committed mutation with reply withheld. They execute 32 process cuts and 29 switches (15 forward, 14 backward). A separate one-program baseline adds 10 cuts. Readback checks all four scenarios, 1,347 native commands, 898 Witness attempts and 24 rejected altered-input controls. | `CAPTURE.zip`, SHA-256 `b05519651e9f54c18ae75aece12d21382e7983f0277176669b0cc979d9b633a8`; 5,061 members. |
| B ↔ C | The same three replacement scenarios execute 32 process cuts and 29 switches (15 forward, 14 backward), with 1,019 native commands and 679 Witness attempts. Independent readback checks original operations and rejects 18 altered-input controls. | `CAPTURE.zip`, 22,348,480 bytes, SHA-256 `63e68f58ed18a85813fe5af85eda9078c325f295c2c4644f05216a34f925b2f6`; 3,600 members. |

The [A/B execution and failure record](../../research/sdk-alpha1/evidence/20261104-installed-program-upgrade/README.md),
[summary](../../research/sdk-alpha1/evidence/20261104-installed-program-upgrade/SUMMARY.json)
and [checks](../../research/sdk-alpha1/evidence/20261104-installed-program-upgrade/CHECKS.json)
bind controllers `b22f627ace3df39a4317b5a50de192768f6ae5bf` and
`f17402654cab21589eb774747bae928b540dba28`. The
[B/C execution/readback record](../../research/sdk-alpha1/evidence/20261104-maintenance-program-upgrade/README.md)
and [result](../../research/sdk-alpha1/evidence/20261104-maintenance-program-upgrade/RESULT.json)
bind controller `0b75a2d16fcb8c5acf333cfa8cb88d837e5546de`.

Both edges preserve original bootstrap replies, session identity, pending target,
message ciphertext/plaintext, acknowledgement state and rekey results through the
actual PID chain, then communicate in both directions at epoch one. Each cut
retains the original journal and 58 key/identity/public-input file hashes. Witness
retry retains the mutation command and target while producing a fresh challenge
and signature for the transport attempt.

The original failures remain part of these records. A/B's first preparation
omitted the required private probe-cache directory and ran no lifecycle scenario;
the later fresh attempts supplied it. B/C's lifecycle commands and import probes
completed, followed by an outer wheel-inventory failure caused by including
separate controller files. The retained corrected readback checks the exact
113-wheel-file/101-controller-file union and reuses the original runtime traces;
it does not relabel the outer driver exit or invent a new execution.

## 5. Final artifact binding

The format, preview and maintenance policy above is selected. The historical
replacement edges are completed evidence with the original identities listed
here. Their records remain unchanged when this policy enters the specification
inventory.

The material still to be supplied for the final 0.2.0 distribution is its own
selected source and actual archive/binary digests, exact package/format pairing,
applicable installed/replacement qualification, and coordinated specification
lock. That is the existing final-artifact admission step; A, B and C are not
relabeled as newly built `0.2.0` artifacts. Reuse of unchanged-component evidence
retains its source correspondence and original scope under the
[release-manifest contract](RELEASE_MANIFEST_V1.md).

This document adds no runtime change, migration implementation, CI gate or native
execution. The normative contract remains unfrozen until the coordinated release
change selects and verifies the actual distribution.
