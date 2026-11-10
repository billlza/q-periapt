# Selected public-source baseline for comparison

> **Status:** selected revisions plus reproducible content hashes, dated 2026-07-11. Only the
> versioned IETF archive URLs and the pinned Signal Git commit are immutable source
> identifiers. Signal/Apple publisher pages are mutable; their declared hash profiles
> detect content drift but do not provide an archive. Full byte locking, the component integration profile,
> state corpus, and external interoperability remain open for `SPEC_LOCK.json`.

The reference lane must reproduce public components before Q-Periapt research deltas
are compared. The following revisions are the selected comparison baseline:

The pinned SPQR implementation now has an
[isolated execution driver](../../research/continuity-spqr-reference/README.md).
It retains the original 32-byte chunks, dependency versions and source commit,
compares actual send/receive message keys, and locks seven public traffic corpora.
This supplies a component execution baseline. Full PQXDH/Triple Ratchet/manager
composition, controlled latency/energy measurements and deployment interoperability remain open.
Its [passive state-snapshot experiment](../../research/continuity-spqr-reference/COMPROMISE_EXPERIMENT.md)
now derives actual exposed message keys from 84 captured endpoint states and the
public transcript. Pending decapsulation keys expose an additional epoch in the
duplex traces; all subsequent one-way keys remain derivable. Uncomputed keys are
not labeled secure, and active/repeated compromise analysis remains open.
The [64-byte experiment](../../research/continuity-spqr-reference/variants/README.md)
adds a separately identified source patch and matched traffic/snapshot corpus.
It advances epochs faster under duplex delivery at a higher per-message byte cost;
one-way traffic still does not advance. It is not a component-conformant result.
An [authenticated whole-KEM control](../../research/continuity-whole-kem-reference/README.md)
now executes full ML-KEM-768 exchanges at three fixed intervals under the same
traffic schedules and snapshot cuts. It binds all three confirmation flights,
preserves exact pending material and bounds skipped keys. Its different
authentication and retention rules are explicit; the finite comparison does not
select the product construction or establish a recovery theorem.

| Component | Selected public revision | Role | Boundary |
|---|---|---|---|
| [PQXDH](https://signal.org/docs/specifications/pqxdh/) | Revision 3, 2023-05-24; last updated 2024-01-23 | asynchronous initial key agreement | Classical mutual authentication in this revision; not active-PQ authentication |
| [Double/Triple Ratchet](https://signal.org/docs/specifications/doubleratchet/) | Revision 4, 2025-11-04 | symmetric/DH ratchet plus hybrid Triple Ratchet composition | Component specification, not proof that this repository interoperates |
| [ML-KEM Braid](https://signal.org/docs/specifications/mlkembraid/) | Revision 1, 2025-02-21; last updated 2025-09-26 | sparse continuous PQ key agreement | Its exact state machine, encoder and recovery rule must be preserved |
| [Sesame](https://signal.org/docs/specifications/sesame/) | Revision 2, 2017-04-14 | asynchronous multi-device session manager | Names X3DH + Double Ratchet; a PQXDH/Triple-Ratchet integration profile is separate work |
| [Signal SPQR engineering report](https://signal.org/blog/spqr/) | published 2025-10-02 | rollout, implementation-verification and migration evidence | Publisher page, not a protocol specification or proof that Q-Periapt matches its CI linkage |
| [Signal SPQR Rust](https://github.com/signalapp/SparsePostQuantumRatchet/tree/f2589fef855c10f39d72634dab3d14654dd410bf) | commit `f2589fef855c10f39d72634dab3d14654dd410bf`, retrieved 2026-07-11 | exact implementation comparison point | Pinned source, but no Q-Periapt interoperability or refinement claim |
| [Apple PQ3](https://security.apple.com/blog/imessage-pq3/) | public description published 2024-02-21 | deployed asynchronous bootstrap, per-device sessions and ongoing PQ rekey comparison | Mutable product description; not an interoperable public implementation |
| [X-Wing](https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-10.txt) | draft-connolly-cfrg-xwing-kem-10, 2026-03-02 | hybrid-KEM compatibility/control lane | Versioned archive of an individual Internet-Draft; not a standardized session protocol |
| [Hybrid KEMs](https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-12.txt) | draft-irtf-cfrg-hybrid-kems-12, 2026-07-06 | general hybrid-KEM comparison and binding analysis | Versioned archive; does not define identity, prekeys, ratchets, persistence or multi-device behavior |

Component conformance, the separately specified manager composition, and real Signal
interoperability are three different claims. No modification of a component KDF,
codec, state transition, limit or field ordering may retain the component-conformant
label.

The machine-readable companion records the URL class and versioned SHA-256 method for
each hashed page/archive, plus the exact SPQR Git commit. Signal injects randomized
Cloudflare email-obfuscation hex into two footer attributes, so raw response hashes are
not reproducible. Profile `signal_cfemail_normalized_sha256_v1` replaces only those two
ASCII hex payloads with fixed markers before hashing; it does not parse the DOM or
normalize whitespace, Unicode, ordering, or any protocol text. Apple PQ3 and versioned
IETF archives use raw bytes. Two consecutive retrievals must produce identical
post-profile bytes and the declared digest.

The verifier is network-explicit and fail closed. Run one component at a time:

```sh
sh artifact/python-run.sh artifact/reference_baseline.py \
  --baseline docs/continuity/reference-baseline.json \
  verify-url --component PQXDH
```

`verify-file` accepts previously captured response bytes for offline reproduction.
Neither mode turns a mutable page into an archive. The companion is not a protocol
profile and intentionally marks full byte lock, integration, and interoperability
pending.
