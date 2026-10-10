# Portable public bootstrap materials

`BootstrapBundle` supplies the byte-oriented input boundary needed by language
bindings and standalone consumers. It uses the existing credential, roster,
manifest, proof and context verifiers. It is not a new signature scheme, session
protocol, enrollment API, policy store or product release authorization.

## Trust and lifetime

The bundle contains only the public-material fields below. The caller supplies
an existing `Arc<VerifiedSessionPolicy>`, two independently retained `AccountPin`s,
the exact intended device IDs and generations, one explicit required prekey
quality, the independently retained directory expectation and trusted time.
The input cannot supply its own trust root, policy owner, checkpoint, intended
peer, required mode or clock.

`from_bytes` and `from_materials` validate the outer grammar and bounds only.
They return an **untrusted container**, never an authenticated context. `verify`
then checks the requested mode against the existing live policy/runtime, verifies
both signatures on each credential and roster, checks exact pinned checkpoints
and membership, and enforces the separately intended device IDs and generations.
It verifies the responder manifest and actual membership proofs through the
original `select_prekeys` path, then calls the original `BootstrapContext::new`.

A fully signed package for another device under the same trusted account still
fails the intended-device check. Swapping roles does not grant permission to select
new peers. An explicitly requested one-time mode cannot become reusable merely
because the signed policy permits both. Missing or extra optional proofs fail;
there is no exhaustion-driven fallback.

The policy object is retained rather than reconstructed from incoming signed
bytes. Closing that instance or its underlying runtime affects every context
which shares it. Verification does not reopen it or create an independent active
copy. Pins are borrowed only during verification; the returned context owns its
verified public snapshots and the original policy reference.

A valid context remains a snapshot. This method neither installs a new roster
head nor provisions a journal, consumes a prekey, creates a session, proves peer
key possession or grants application privilege. Journal admission, current roster
fences, configured witnesses and fresh bootstrap confirmation remain mandatory.
A matching directory digest is still a binding to an independent expectation,
not a transparency, lease, availability or consistency proof.

These are cryptographically public materials, but credentials, complete rosters
and the role-ordered pair can disclose sensitive metadata. The library does not
log or transmit the package automatically. The host chooses protected storage and
transport appropriate to that metadata. The existing network carrier sends the
original bootstrap/control/application frames; it does not silently add this
container to the wire.

## Canonical outer grammar

`QPBNDL01[8] || quality:u8 || nine fields`, where each field is
`length:u16 || exact bytes`, with big-endian lengths and no trailing data.

| Field | Existing encoding | Presence |
| --- | --- | --- |
| 1 | Initiator signed credential | mandatory |
| 2 | Initiator signed roster | mandatory |
| 3 | Responder signed credential | mandatory |
| 4 | Responder signed roster | mandatory |
| 5 | Responder signed manifest | mandatory |
| 6 | Signed classical baseline leaf proof | mandatory |
| 7 | Last-resort PQ baseline leaf proof | mandatory |
| 8 | One-time classical leaf proof | modes 1 and 4 only |
| 9 | One-time PQ leaf proof | modes 1 and 3 only |

Quality values retain `PrekeyQuality`: 1 one-time both, 2 reusable both,
3 signed classical plus one-time PQ, 4 one-time classical plus last-resort PQ.
Other values fail. Each field is at most 8,192 bytes; the complete container is at
most 65,536 bytes. All mandatory fields are nonempty. An absent optional field
is exactly zero length. The Rust builder rejects `Some(empty)` so absence has a
single representation. The existing proof decoder independently caps depth at ten
and validates exact leaf sizes and trailing bytes.

The container carries actual signed inputs and actual proofs, not a caller-selected
selection record or context digest. All four modes reconstruct exactly the same
context commitment as the existing verified-object constructor. The outer package
is not hashed into a new session identity. Different valid signature randomness
can encode the same authenticated contents; outer framing canonicality does not
mean one globally unique byte string per context.

## Executed consumption paths

The native connection tests now save a real inventory-backed bundle and reverify
that file in each endpoint process before establishment, rekey or application
traffic. Independently configured expectations remain separate from the file.
The existing complete reference trace and crash/cancellation/unknown-commit cases
exercise those imported contexts. Unit cases cover all four modes, every byte
truncation, trailing data, oversized fields/packages, optional-proof shape,
all signed/proof-field tampering, cross-manifest substitution, wrong checkpoints,
expiry, closed policy/runtime, and fully valid same-account role substitution.

A second path crosses a real language/serialization boundary:

1. `public_vectors` issues fresh public signatures and exports the local fixture
   issuer's trust expectations separately from the candidate package fields.
2. Python `scripts/exercise_bootstrap_bundle.py` independently constructs QPBNDL01
   from those public inputs, without importing the Rust encoder or asserting trust.
3. The compiled `examples/import_bootstrap_bundle.rs` consumer takes separate trust,
   input, required-mode and trusted-time arguments. It reconstructs a fresh fixture
   runtime from the locally trusted signed policy, imports the package through the
   public API and compares its context to the issuer's independent expected digest.
4. One valid input and 25 malformed, tampered or mismatched inputs run through that
   actual consumer. A negative counts only a typed exit-1 import failure; missing
   programs, crashes and timeouts are not accepted as rejection evidence. The
   executable is hashed before and after the run and must remain unchanged.

The fixture trust directory is explicit test genesis, not a production trust
store or permission to enroll whatever roots arrive from a peer. The independent
OpenSSL public-vector and witness checks remain separate from this construction
exercise. This is cross-language **input verification**, not an installed C/JVM/
Swift/Android/WASM SDK connection or independent protocol implementation claim.
The example and exercise are also wired into the existing public-vector CI lane.

Bundle import preserves QPTEPO04, QPCNET01, QPCCTL01, v6 rekey controls, SDK KATs
and published ABI contracts. The current durable lifecycle format is documented
in [session closure](SESSION_CLOSURE.md). The candidate stays outside the published
SDK dependency graph. Product admission, lifecycle completion, protocol/recovery
analysis, matched performance and current-device qualification remain required.
