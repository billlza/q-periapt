# Multiple original-record commitments and acquisition semantics

The [manual note](../../../../docs/continuity/MULTI_RECORD_COMMITMENTS_V1.md)
adds a bounded hybrid composition for the explicitly defined private-record
interface. It counts fresh sealing invocations, preserves exact-copy caches,
permits distinct canonical intent headers and charges all SHA3 prefix and
continuation queries. The one-image/one-intent case reduces to the earlier
six-interface bound. A separate conditioning observation covers an independent
auxiliary public oracle without erasing that oracle's later query-accounting
obligations. None of this establishes the concrete SHA3/HMAC assumptions or
unrestricted native-record simulation.

The frozen model's Snapshot action outputs an encrypted record without waiting
for decryption. Cut separately reveals both selected-session wrapping keys. MAIN
excludes matching acquisitions of any selected-session state saved after Cut;
its condition is not restricted to the target epoch. This is an exact reading
of the retained original formula, not an added prohibition on ciphertext views.
Actual aggregate, pending-target, retained-copy and projection views still need
their correct content/provenance mapping.

The reader checks 50 files against source
`21176899dfa2cfa9e07a15be6e30de8123a8a1df`; all 41 files from the earlier
single-record audit remain byte-identical. It retains the four concrete pending
constructor sites and confirms nonce placement after plaintext encoding,
verbatim record-payload copying, original-target retention and exact pending-byte
comparison. Existing aggregate-copy and pending-target runtime captures keep
their earlier source and execution scopes; they were not rerun here.

The source also has private-state-dependent cleanup MACs. Session closure
excludes its own 64-byte report/key tail from the MAC transcript; aggregate
abandonment excludes its batch report/key tail. These facts avoid a particular
self-key transcript dependency but do not simulate an unknown private payload.
The report/zero-value check occurs before persistence, so a closure attempt
cannot automatically be treated as an irreversible loss of the target message.
The note retains this concrete existing simulation obligation instead of claiming
that the six SHA3 digest domains cover it.

The complete frozen model is retained with SHA-256
`dde5d06a071b1560da0d4c28c3f1fd81a3c39708f9fd8564ee391ddc362bcf7f`;
the extracted original MAIN formula remains
`0b92ee18d7731c7c83fa05329e486fd6813f8ea13d64ed92215346f10cdf8faa`.
All 40 queries remain. This is a source/formula readback and a manual conditional
argument, not a new Tamarin execution, runtime test or external review.

`CAPTURE.zip` contains source, the model and extracted rules/formula, the prior
audit, the reader and new note. All 59 members were reread:
239,757 bytes, SHA-256
`279c2b064c6b6f8cd97a2f931e571eb1a5c47450933ae855907cd7876e6ad4b8`.
`SOURCE_AUDIT.json` and `FILES.json` retain exact inputs and limitations. No
product code, protocol acceptance rule, MAIN premise or remote workflow changed.
